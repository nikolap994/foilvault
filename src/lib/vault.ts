export interface Credential {
  id: string
  type: 'login' | 'note'
  site: string
  username: string
  password: string
  totp?: string          // base32 TOTP secret
  notes: string
  folder?: string
  expiresAt?: number     // Unix ms — password expiry date
  createdAt: number
  updatedAt: number
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
}

export async function unlockVault(password: string): Promise<boolean> {
  const blob = await readVaultBlob()
  if (!blob) return false
  const salt = await getOrCreateSalt()
  const key = await deriveKey(password, salt)
  try {
    await decryptString(key, blob)
    await setSessionKey(key)
    return true
  } catch {
    return false
  }
}

export async function lockVault(): Promise<void> {
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
  return full
}

export async function updateCredential(id: string, patch: Partial<Omit<Credential, 'id' | 'createdAt'>>): Promise<void> {
  const data = await readData()
  const idx = data.credentials.findIndex(c => c.id === id)
  if (idx < 0) return
  data.credentials[idx] = { ...data.credentials[idx], ...patch, updatedAt: Date.now() }
  await writeData(data)
}

export async function deleteCredential(id: string): Promise<void> {
  const data = await readData()
  data.credentials = data.credentials.filter(c => c.id !== id)
  await writeData(data)
}

export async function exportCredentials(format: 'json' | 'csv'): Promise<string> {
  const creds = await getCredentials()
  if (format === 'json') return JSON.stringify(creds, null, 2)

  const header = 'name,username,password,url,notes,folder,totp\n'
  const rows = creds.map(c => {
    const esc = (s: string) => `"${(s ?? '').replace(/"/g, '""')}"`
    return [esc(c.site), esc(c.username), esc(c.password), '', esc(c.notes), esc(c.folder ?? ''), esc(c.totp ?? '')].join(',')
  })
  return header + rows.join('\n')
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
