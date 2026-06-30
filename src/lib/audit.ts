export type AuditEvent =
  | 'vault_unlock'
  | 'vault_lock'
  | 'vault_create'
  | 'autofill'
  | 'credential_copy'
  | 'credential_view'
  | 'credential_add'
  | 'credential_delete'
  | 'hibp_check'
  | 'vault_export'
  | 'vault_import'

export interface AuditEntry {
  event: AuditEvent
  ts: number
  site?: string
}

const STORAGE_KEY = 'foilvault_audit_log'
const MAX_ENTRIES = 300

export async function logAuditEvent(event: AuditEvent, site?: string): Promise<void> {
  const stored = await chrome.storage.local.get(STORAGE_KEY)
  const log: AuditEntry[] = stored[STORAGE_KEY] ?? []
  log.push({ event, ts: Date.now(), ...(site ? { site } : {}) })
  if (log.length > MAX_ENTRIES) log.splice(0, log.length - MAX_ENTRIES)
  await chrome.storage.local.set({ [STORAGE_KEY]: log })
}

export async function getAuditLog(): Promise<AuditEntry[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY)
  const log: AuditEntry[] = stored[STORAGE_KEY] ?? []
  return [...log].reverse()
}

export async function clearAuditLog(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY)
}

export function formatAuditEvent(event: AuditEvent): string {
  const labels: Record<AuditEvent, string> = {
    vault_unlock:      'Vault unlocked',
    vault_lock:        'Vault locked',
    vault_create:      'Vault created',
    autofill:          'Autofill used',
    credential_copy:   'Password copied',
    credential_view:   'Credential viewed',
    credential_add:    'Credential added',
    credential_delete: 'Credential deleted',
    hibp_check:        'Breach check run',
    vault_export:      'Vault exported',
    vault_import:      'Vault imported',
  }
  return labels[event] ?? event
}
