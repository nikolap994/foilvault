import { logAuditEvent } from './audit'

export interface PasswordHistoryEntry {
  password: string
  changedAt: number
}

export interface Credential {
  id: string
  type: 'login' | 'note' | 'card' | 'identity'
  site: string
  username: string
  password: string
  totp?: string
  notes: string
  folder?: string
  expiresAt?: number
  createdAt: number
  updatedAt: number
  passwordHistory?: PasswordHistoryEntry[]
  pinned?: boolean
  // Card fields
  cardNumber?: string
  cardExpiry?: string
  cardCvv?: string
  cardHolder?: string
  // Identity fields
  idFirstName?: string
  idLastName?: string
  idEmail?: string
  idPhone?: string
  idAddress?: string
  idDob?: string
}

interface VaultData {
  credentials: Credential[]
  version: number
}

const SESSION_KEY = 'foilvault_session_key'
const SALT_KEY = 'foilvault_salt'

// ─── PBKDF2 key derivation ─────────────────────────────────────────────────
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 600_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )
}

async function exportKeyB64(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key)
  return btoa(String.fromCharCode(...new Uint8Array(raw)))
}

async function importKeyB64(b64: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

// ─── AES-GCM encrypt / decrypt ────────────────────────────────────────────
async function encryptString(key: CryptoKey, plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const enc = new TextEncoder()
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain))
  const combined = new Uint8Array(12 + cipherBuf.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(cipherBuf), 12)
  return btoa(String.fromCharCode(...combined))
}

async function decryptString(key: CryptoKey, b64: string): Promise<string> {
  const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  const iv = combined.slice(0, 12)
  const cipher = combined.slice(12)
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher)
  return new TextDecoder().decode(plain)
}

// ─── Salt management ──────────────────────────────────────────────────────
async function getOrCreateSalt(): Promise<Uint8Array> {
  const stored = await chrome.storage.local.get(SALT_KEY)
  if (stored[SALT_KEY]) {
    return Uint8Array.from(atob(stored[SALT_KEY] as string), c => c.charCodeAt(0))
  }
  const salt = crypto.getRandomValues(new Uint8Array(32))
  await chrome.storage.local.set({ [SALT_KEY]: btoa(String.fromCharCode(...salt)) })
  return salt
}

// ─── Session key (stored in memory per session) ───────────────────────────
async function getSessionKey(): Promise<CryptoKey | null> {
  const s = await chrome.storage.session.get(SESSION_KEY)
  if (!s[SESSION_KEY]) return null
  try {
    return await importKeyB64(s[SESSION_KEY] as string)
  } catch {
    return null
  }
}

async function setSessionKey(key: CryptoKey): Promise<void> {
  await chrome.storage.session.set({ [SESSION_KEY]: await exportKeyB64(key) })
}

export async function clearSessionKey(): Promise<void> {
  await chrome.storage.session.remove(SESSION_KEY)
}

// ─── Vault blob ────────────────────────────────────────────────────────────
async function readVaultBlob(): Promise<string | null> {
  const s = await chrome.storage.local.get('foilvault_blob')
  return (s['foilvault_blob'] as string | undefined) ?? null
}

async function writeVaultBlob(blob: string): Promise<void> {
  await chrome.storage.local.set({ foilvault_blob: blob })
}

// ─── Public API ────────────────────────────────────────────────────────────
export async function isVaultInitialized(): Promise<boolean> {
  return (await readVaultBlob()) !== null
}

export async function isVaultUnlocked(): Promise<boolean> {
  return (await getSessionKey()) !== null
}

export async function initVault(password: string): Promise<void> {
  const salt = await getOrCreateSalt()
  const key = await deriveKey(password, salt)
  const empty: VaultData = { credentials: [], version: 1 }
  const blob = await encryptString(key, JSON.stringify(empty))
  await writeVaultBlob(blob)
  await setSessionKey(key)
  await logAuditEvent('vault_create')
}

export async function unlockVault(password: string): Promise<boolean> {
  const blob = await readVaultBlob()
  if (!blob) return false
  const salt = await getOrCreateSalt()
  const key = await deriveKey(password, salt)
  try {
    await decryptString(key, blob)
    await setSessionKey(key)
    await logAuditEvent('vault_unlock')
    return true
  } catch {
    return false
  }
}

export async function lockVault(): Promise<void> {
  await logAuditEvent('vault_lock')
  await clearSessionKey()
}

async function readData(): Promise<VaultData> {
  const key = await getSessionKey()
  if (!key) throw new Error('vault_locked')
  const blob = await readVaultBlob()
  if (!blob) throw new Error('vault_not_initialized')
  const json = await decryptString(key, blob)
  return JSON.parse(json) as VaultData
}

async function writeData(data: VaultData): Promise<void> {
  const key = await getSessionKey()
  if (!key) throw new Error('vault_locked')
  const blob = await encryptString(key, JSON.stringify(data))
  await writeVaultBlob(blob)
}

export async function getCredentials(): Promise<Credential[]> {
  return (await readData()).credentials
}

export async function getFolders(): Promise<string[]> {
  const data = await readData()
  return [...new Set(data.credentials.map(c => c.folder).filter((f): f is string => !!f))].sort()
}

export async function addCredential(cred: Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>): Promise<Credential> {
  const data = await readData()
  const now = Date.now()
  const full: Credential = {
    ...cred,
    id: crypto.randomUUID(),
    createdAt: now,
    updatedAt: now,
  }
  data.credentials.push(full)
  await writeData(data)
  await logAuditEvent('credential_add', cred.site)
  return full
}

export async function updateCredential(id: string, patch: Partial<Omit<Credential, 'id' | 'createdAt'>>): Promise<void> {
  const data = await readData()
  const idx = data.credentials.findIndex(c => c.id === id)
  if (idx < 0) return
  const current = data.credentials[idx]
  if (patch.password && patch.password !== current.password) {
    const prev = current.passwordHistory ?? []
    patch = { ...patch, passwordHistory: [{ password: current.password, changedAt: current.updatedAt }, ...prev].slice(0, 10) }
  }
  data.credentials[idx] = { ...current, ...patch, updatedAt: Date.now() }
  await writeData(data)
}

export async function pinCredential(id: string, pinned: boolean): Promise<void> {
  const data = await readData()
  const idx = data.credentials.findIndex(c => c.id === id)
  if (idx < 0) return
  data.credentials[idx] = { ...data.credentials[idx], pinned }
  await writeData(data)
}

export async function deleteCredential(id: string): Promise<void> {
  const data = await readData()
  const cred = data.credentials.find(c => c.id === id)
  data.credentials = data.credentials.filter(c => c.id !== id)
  await writeData(data)
  await logAuditEvent('credential_delete', cred?.site)
}

export async function exportCredentials(format: 'json' | 'csv'): Promise<string> {
  await logAuditEvent('vault_export')
  const creds = await getCredentials()
  if (format === 'json') return JSON.stringify(creds, null, 2)

  const header = 'name,username,password,url,notes,folder,totp\n'
  const rows = creds.map(c => {
    const esc = (s: string) => `"${(s ?? '').replace(/"/g, '""')}"`
    return [esc(c.site), esc(c.username), esc(c.password), '', esc(c.notes), esc(c.folder ?? ''), esc(c.totp ?? '')].join(',')
  })
  return header + rows.join('\n')
}

// ─── Encrypted vault export / import ─────────────────────────────────────
export interface EncryptedExport {
  v: 1
  kdf: 'pbkdf2'
  hash: 'SHA-256'
  iterations: number
  salt: string   // base64
  iv: string     // base64
  data: string   // base64 AES-GCM ciphertext of JSON credential array
}

export async function exportEncrypted(password: string): Promise<string> {
  await logAuditEvent('vault_export')
  const creds = await getCredentials()
  const enc = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv   = crypto.getRandomValues(new Uint8Array(12))
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 600_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(creds)))
  const toB64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  const payload: EncryptedExport = {
    v: 1, kdf: 'pbkdf2', hash: 'SHA-256', iterations: 600_000,
    salt: toB64(salt.buffer as ArrayBuffer),
    iv:   toB64(iv.buffer as ArrayBuffer),
    data: toB64(cipher),
  }
  return JSON.stringify(payload, null, 2)
}

export async function importEncrypted(json: string, password: string): Promise<Credential[]> {
  const payload = JSON.parse(json) as EncryptedExport
  if (payload.v !== 1 || payload.kdf !== 'pbkdf2') throw new Error('unsupported_format')
  const fromB64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))
  const salt = fromB64(payload.salt)
  const iv   = fromB64(payload.iv)
  const enc  = new TextEncoder()
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: payload.iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, fromB64(payload.data).buffer as ArrayBuffer)
  return JSON.parse(new TextDecoder().decode(plain)) as Credential[]
}

export function generatePassword(opts: { length: number; symbols: boolean; numbers: boolean; upper: boolean }): string {
  const lower = 'abcdefghijklmnopqrstuvwxyz'
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const numbers = '0123456789'
  const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?'
  let pool = lower
  if (opts.upper) pool += upper
  if (opts.numbers) pool += numbers
  if (opts.symbols) pool += symbols

  const arr = new Uint32Array(opts.length)
  crypto.getRandomValues(arr)
  return Array.from(arr, n => pool[n % pool.length]).join('')
}
