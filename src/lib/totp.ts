// RFC 6238 TOTP — generates 6-digit time-based codes from a base32 secret
// No external dependencies — uses SubtleCrypto HMAC-SHA1

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(input: string): Uint8Array {
  const s = input.replace(/\s/g, '').replace(/=+$/, '').toUpperCase()
  const bits: number[] = []
  for (const ch of s) {
    const idx = BASE32_CHARS.indexOf(ch)
    if (idx < 0) continue
    for (let i = 4; i >= 0; i--) bits.push((idx >> i) & 1)
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8))
  for (let i = 0; i < bytes.length; i++) {
    let b = 0
    for (let j = 0; j < 8; j++) b = (b << 1) | (bits[i * 8 + j] ?? 0)
    bytes[i] = b
  }
  return bytes
}

function uint64ToBytes(n: number): Uint8Array {
  const buf = new Uint8Array(8)
  let v = Math.floor(n)
  for (let i = 7; i >= 0; i--) {
    buf[i] = v & 0xff
    v = Math.floor(v / 256)
  }
  return buf
}

export async function generateTOTP(secret: string, period = 30, digits = 6): Promise<string> {
  const keyBytes = base32Decode(secret)
  const counter = Math.floor(Date.now() / 1000 / period)
  const msg = uint64ToBytes(counter)

  const key = await crypto.subtle.importKey('raw', keyBytes.buffer as ArrayBuffer, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, msg.buffer as ArrayBuffer)
  const hmac = new Uint8Array(sig)

  const offset = hmac[hmac.length - 1] & 0x0f
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
     (hmac[offset + 3] & 0xff)

  return String(code % Math.pow(10, digits)).padStart(digits, '0')
}

export function secondsRemaining(period = 30): number {
  return period - (Math.floor(Date.now() / 1000) % period)
}

export function validateBase32Secret(s: string): boolean {
  return /^[A-Z2-7\s=]+$/i.test(s) && s.replace(/\s/g, '').replace(/=+$/, '').length >= 8
}
