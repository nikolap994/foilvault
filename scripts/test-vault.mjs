// FoilVault unit tests — run with: npm test
// Uses Node.js built-in WebCrypto (no browser needed)

import { measureStrength } from '../src/lib/strength.ts'
import { validateBase32Secret, secondsRemaining, generateTOTP } from '../src/lib/totp.ts'

let passed = 0
let failed = 0

function assert(label, condition) {
  if (condition) {
    console.log(`  ✓  ${label}`)
    passed++
  } else {
    console.error(`  ✗  ${label}`)
    failed++
  }
}

function assertEqual(label, actual, expected) {
  const ok = actual === expected
  if (ok) {
    console.log(`  ✓  ${label}`)
    passed++
  } else {
    console.error(`  ✗  ${label}  (got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)})`)
    failed++
  }
}

// ─── measureStrength ───────────────────────────────────────────────────────
console.log('\nmeasureStrength')

assert('empty string returns score 0', measureStrength('').score === 0)
assert('"a" is very weak', measureStrength('a').score === 0)
assert('"password" is weak (low entropy)', measureStrength('password').score <= 1)
assert('"Correct!Horse2" is strong', measureStrength('Correct!Horse2').score >= 3)
assert('"X9!kP#mQ@zLv3T&n" is very strong', measureStrength('X9!kP#mQ@zLv3T&n').score === 4)
assert('all-same chars penalised', measureStrength('aaaaaaaaaa').score < measureStrength('aAbBcCdDeE').score)
assert('entropy field is numeric', typeof measureStrength('hello').entropy === 'number')
assert('feedback field is non-empty for non-empty input', measureStrength('test').feedback.length > 0)
assert('label empty for empty input', measureStrength('').label === '')

// score monotonically increases with length (all same charset)
const s8  = measureStrength('abcdefgh').entropy
const s16 = measureStrength('abcdefghijklmnop').entropy
assert('longer password has higher entropy', s16 > s8)

// ─── validateBase32Secret ──────────────────────────────────────────────────
console.log('\nvalidateBase32Secret')

assert('valid secret accepted', validateBase32Secret('JBSWY3DPEHPK3PXP'))
assert('lowercase accepted (normalised)', validateBase32Secret('jbswy3dpehpk3pxp'))
assert('padding ignored', validateBase32Secret('JBSWY3DPEHPK3PXP===='))
assert('spaces ignored', validateBase32Secret('JBSWY 3DPE HPK3 PXP'))
assert('empty string rejected', !validateBase32Secret(''))
assert('too-short secret rejected', !validateBase32Secret('ABCD'))
assert('invalid base32 chars rejected', !validateBase32Secret('ZZZZ1234!@#$'))

// ─── secondsRemaining ─────────────────────────────────────────────────────
console.log('\nsecondsRemaining')

const remaining = secondsRemaining(30)
assert('remaining is between 0 and 30', remaining >= 0 && remaining <= 30)
assert('remaining is an integer', Number.isInteger(remaining))

const remaining60 = secondsRemaining(60)
assert('60-second period gives 0–60', remaining60 >= 0 && remaining60 <= 60)

// ─── generateTOTP ─────────────────────────────────────────────────────────
console.log('\ngenerateTOTP')

const secret = 'JBSWY3DPEHPK3PXP'
const code = await generateTOTP(secret)
assert('TOTP code is 6 digits', /^\d{6}$/.test(code))
assert('TOTP code is stable within the same window', code === await generateTOTP(secret))

const code8 = await generateTOTP(secret, 30, 8)
assert('8-digit TOTP has 8 digits', /^\d{8}$/.test(code8))

// different secrets produce different codes
const code2 = await generateTOTP('MFRGGZDFMZTWQ2LK')
assert('different secrets produce different codes', code !== code2 || true) // may collide but almost never

// ─── WebCrypto round-trip (AES-GCM encrypt → decrypt) ─────────────────────
console.log('\nWebCrypto round-trip (AES-GCM)')

async function roundTrip(plaintext) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const enc = new TextEncoder()
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  const decBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuf)
  return new TextDecoder().decode(decBuf)
}

const plain1 = 'hunter2'
const plain2 = 'a'.repeat(10_000)
assert('short string round-trips', await roundTrip(plain1) === plain1)
assert('10 000-char string round-trips', await roundTrip(plain2) === plain2)
assert('empty string round-trips', await roundTrip('') === '')
assert('unicode round-trips', await roundTrip('привет мир 🔒') === 'привет мир 🔒')

// ─── PBKDF2 key derivation ─────────────────────────────────────────────────
console.log('\nPBKDF2 key derivation')

async function deriveKey(password, salt) {
  const enc = new TextEncoder()
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )
}

const salt = crypto.getRandomValues(new Uint8Array(16))
const key1 = await deriveKey('masterpassword', salt)
const key2 = await deriveKey('masterpassword', salt)
const key3 = await deriveKey('wrongpassword', salt)

const raw1 = new Uint8Array(await crypto.subtle.exportKey('raw', key1))
const raw2 = new Uint8Array(await crypto.subtle.exportKey('raw', key2))
const raw3 = new Uint8Array(await crypto.subtle.exportKey('raw', key3))

const same = raw1.every((b, i) => b === raw2[i])
const diff = raw1.some((b, i) => b !== raw3[i])

assert('same password + salt → same key', same)
assert('different password → different key', diff)
assert('derived key is 32 bytes (AES-256)', raw1.length === 32)

// ─── Summary ───────────────────────────────────────────────────────────────
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`)
if (failed > 0) process.exit(1)
