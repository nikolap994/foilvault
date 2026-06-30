import { getAuditLog, clearAuditLog, formatAuditEvent, logAuditEvent } from '../lib/audit'
import { exportEncrypted, importEncrypted, addCredential, getCredentials } from '../lib/vault'
import { checkPasswordBreach } from '../lib/hibp'
import { measureStrength } from '../lib/strength'

interface VaultOptions {
  autolockMinutes: number
  clipboardClearSeconds: number
  hibpEnabled: boolean
  expiryWarningsEnabled: boolean
  autofillEnabled: boolean
  genLength: number
  genUpper: boolean
  genLower: boolean
  genDigits: boolean
  genSymbols: boolean
  genExcludeAmbiguous: boolean
}

const DEFAULTS: VaultOptions = {
  autolockMinutes: 5,
  clipboardClearSeconds: 30,
  hibpEnabled: true,
  expiryWarningsEnabled: true,
  autofillEnabled: true,
  genLength: 20,
  genUpper: true,
  genLower: true,
  genDigits: true,
  genSymbols: true,
  genExcludeAmbiguous: false,
}

async function loadOptions(): Promise<VaultOptions> {
  const stored = await chrome.storage.local.get('foilvault_options')
  return { ...DEFAULTS, ...(stored.foilvault_options ?? {}) }
}

async function saveOptions(opts: VaultOptions): Promise<void> {
  await chrome.storage.local.set({ foilvault_options: opts })
}

function collectForm(): VaultOptions {
  return {
    autolockMinutes: parseInt((document.getElementById('autolock-select') as HTMLSelectElement).value, 10),
    clipboardClearSeconds: parseInt((document.getElementById('clipboard-select') as HTMLSelectElement).value, 10),
    hibpEnabled: (document.getElementById('hibp-toggle') as HTMLInputElement).checked,
    expiryWarningsEnabled: (document.getElementById('expiry-toggle') as HTMLInputElement).checked,
    autofillEnabled: (document.getElementById('autofill-toggle') as HTMLInputElement).checked,
    genLength: parseInt((document.getElementById('gen-length') as HTMLInputElement).value, 10),
    genUpper: (document.getElementById('gen-upper') as HTMLInputElement).checked,
    genLower: (document.getElementById('gen-lower') as HTMLInputElement).checked,
    genDigits: (document.getElementById('gen-digits') as HTMLInputElement).checked,
    genSymbols: (document.getElementById('gen-symbols') as HTMLInputElement).checked,
    genExcludeAmbiguous: (document.getElementById('gen-ambiguous') as HTMLInputElement).checked,
  }
}

function applyToForm(opts: VaultOptions): void {
  ;(document.getElementById('autolock-select') as HTMLSelectElement).value = String(opts.autolockMinutes)
  ;(document.getElementById('clipboard-select') as HTMLSelectElement).value = String(opts.clipboardClearSeconds)
  ;(document.getElementById('hibp-toggle') as HTMLInputElement).checked = opts.hibpEnabled
  ;(document.getElementById('expiry-toggle') as HTMLInputElement).checked = opts.expiryWarningsEnabled
  ;(document.getElementById('autofill-toggle') as HTMLInputElement).checked = opts.autofillEnabled
  ;(document.getElementById('gen-length') as HTMLInputElement).value = String(opts.genLength)
  ;(document.getElementById('gen-length-val') as HTMLSpanElement).textContent = String(opts.genLength)
  ;(document.getElementById('gen-upper') as HTMLInputElement).checked = opts.genUpper
  ;(document.getElementById('gen-lower') as HTMLInputElement).checked = opts.genLower
  ;(document.getElementById('gen-digits') as HTMLInputElement).checked = opts.genDigits
  ;(document.getElementById('gen-symbols') as HTMLInputElement).checked = opts.genSymbols
  ;(document.getElementById('gen-ambiguous') as HTMLInputElement).checked = opts.genExcludeAmbiguous
}

function showStatus(msg: string, isError = false): void {
  const el = document.getElementById('save-status')!
  el.textContent = msg
  el.className = 'save-status' + (isError ? ' error' : '')
  setTimeout(() => { el.textContent = '' }, 2500)
}

document.addEventListener('DOMContentLoaded', async () => {
  const icon = document.getElementById('logo-icon') as HTMLImageElement
  icon.src = chrome.runtime.getURL('icons/foilvault-32.png')

  const opts = await loadOptions()
  applyToForm(opts)

  document.getElementById('gen-length')!.addEventListener('input', (e) => {
    const val = (e.target as HTMLInputElement).value
    document.getElementById('gen-length-val')!.textContent = val
  })

  document.getElementById('btn-save')!.addEventListener('click', async () => {
    try {
      await saveOptions(collectForm())
      showStatus('Settings saved')
    } catch {
      showStatus('Failed to save', true)
    }
  })

  const overlay = document.getElementById('confirm-dialog')!
  const btnClear = document.getElementById('btn-clear-vault')!
  const btnCancel = document.getElementById('confirm-cancel')!
  const btnConfirm = document.getElementById('confirm-ok')!

  btnClear.addEventListener('click', () => overlay.classList.remove('hidden'))
  btnCancel.addEventListener('click', () => overlay.classList.add('hidden'))
  btnConfirm.addEventListener('click', async () => {
    await chrome.storage.local.clear()
    overlay.classList.add('hidden')
    showStatus('Vault cleared')
  })

  // Encrypted export
  const exportPwInput = document.getElementById('export-password') as HTMLInputElement
  const exportStatus  = document.getElementById('export-status')!
  document.getElementById('btn-export-enc')!.addEventListener('click', async () => {
    const pw = exportPwInput.value.trim()
    if (!pw) {
      exportStatus.textContent = 'Enter a backup password first.'
      exportStatus.className = 'export-status err'
      return
    }
    try {
      const json = await exportEncrypted(pw)
      const blob = new Blob([json], { type: 'application/json' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      const date = new Date().toISOString().slice(0, 10)
      a.href = url
      a.download = `foilvault-${date}.foilvault`
      a.click()
      URL.revokeObjectURL(url)
      exportPwInput.value = ''
      exportStatus.textContent = 'Backup downloaded.'
      exportStatus.className = 'export-status ok'
      setTimeout(() => { exportStatus.textContent = '' }, 3000)
    } catch {
      exportStatus.textContent = 'Export failed — vault may be locked.'
      exportStatus.className = 'export-status err'
    }
  })

  // Security health
  document.getElementById('btn-health-check')!.addEventListener('click', async () => {
    const btn = document.getElementById('btn-health-check') as HTMLButtonElement
    const statusEl = document.getElementById('health-status')!
    const resultsEl = document.getElementById('health-results')!
    btn.disabled = true; statusEl.textContent = 'Scanning vault…'; statusEl.className = 'export-status'
    resultsEl.classList.add('hidden')
    try {
      const creds = await getCredentials()
      const logins = creds.filter(c => c.type !== 'note' && c.password)
      const now = Date.now()

      const weak = logins.filter(c => measureStrength(c.password).score < 2)

      const byPw = new Map<string, typeof logins>()
      for (const c of logins) { const g = byPw.get(c.password) ?? []; g.push(c); byPw.set(c.password, g) }
      const reusedGroups = [...byPw.values()].filter(g => g.length > 1)

      const expired = creds.filter(c => c.expiresAt && c.expiresAt <= now)

      const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000
      const old = logins.filter(c => (now - c.updatedAt) >= ninetyDaysMs && !c.expiresAt)

      const total = weak.length + reusedGroups.length + expired.length + old.length
      statusEl.textContent = total === 0 ? '✓ Vault looks healthy — no issues found.' : `⚠ ${total} issue${total !== 1 ? 's' : ''} found.`
      statusEl.className = `export-status ${total > 0 ? 'err' : 'ok'}`

      const setBadge = (id: string, n: number) => {
        const el = document.getElementById(id)!
        el.textContent = String(n); el.className = `health-badge ${n > 0 ? 'health-badge-warn' : 'health-badge-ok'}`
      }
      setBadge('health-weak-count', weak.length)
      setBadge('health-reused-count', reusedGroups.length)
      setBadge('health-expired-count', expired.length)
      setBadge('health-old-count', old.length)

      const row = (site: string, user: string, extra: string, extraColor?: string) =>
        `<div class="health-item"><span class="health-site">${site}</span><span class="health-user">${user}</span><span class="health-score"${extraColor ? ` style="color:${extraColor}"` : ''}>${extra}</span></div>`

      document.getElementById('health-weak-list')!.innerHTML = weak.length === 0
        ? '<p class="health-empty">All passwords are strong.</p>'
        : weak.map(c => row(c.site, c.username, measureStrength(c.password).label)).join('')

      document.getElementById('health-reused-list')!.innerHTML = reusedGroups.length === 0
        ? '<p class="health-empty">No passwords are reused.</p>'
        : reusedGroups.map(g =>
            `<div class="health-reuse-group">${g.map(c => row(c.site, c.username, '')).join('')}</div>`
          ).join('')

      document.getElementById('health-expired-list')!.innerHTML = expired.length === 0
        ? '<p class="health-empty">No expired passwords.</p>'
        : expired.map(c => row(c.site, c.username, new Date(c.expiresAt!).toLocaleDateString(), '#ef4444')).join('')

      document.getElementById('health-old-list')!.innerHTML = old.length === 0
        ? '<p class="health-empty">All passwords updated recently.</p>'
        : old.map(c => {
            const days = Math.floor((now - c.updatedAt) / (24 * 60 * 60 * 1000))
            return row(c.site, c.username, `${days}d ago`, '#f59e0b')
          }).join('')

      resultsEl.classList.remove('hidden')
    } catch {
      statusEl.textContent = 'Failed — vault may be locked.'; statusEl.className = 'export-status err'
    }
    btn.disabled = false
  })

  // Vault audit
  const btnAuditVault = document.getElementById('btn-audit-vault')!
  const auditVaultProgress = document.getElementById('audit-vault-progress')!
  const auditVaultResults = document.getElementById('audit-vault-results')!

  btnAuditVault.addEventListener('click', async () => {
    ;(btnAuditVault as HTMLButtonElement).disabled = true
    auditVaultResults.classList.add('hidden')
    auditVaultProgress.textContent = 'Loading credentials…'
    auditVaultProgress.className = 'export-status'
    try {
      const creds = await getCredentials()
      const targets = creds.filter(c => c.type !== 'note' && c.password)
      if (targets.length === 0) {
        auditVaultProgress.textContent = 'No passwords to check.'
        ;(btnAuditVault as HTMLButtonElement).disabled = false
        return
      }
      const results: Array<{ site: string; username: string; breached: boolean; count: number; err?: boolean }> = []
      for (let i = 0; i < targets.length; i++) {
        const c = targets[i]
        auditVaultProgress.textContent = `Checking ${i + 1} of ${targets.length}…`
        try {
          const r = await checkPasswordBreach(c.password)
          results.push({ site: c.site, username: c.username, ...r })
        } catch {
          results.push({ site: c.site, username: c.username, breached: false, count: 0, err: true })
        }
      }
      const breached = results.filter(r => r.breached)
      auditVaultProgress.textContent = breached.length === 0
        ? `✓ All ${targets.length} passwords are clean.`
        : `⚠ ${breached.length} of ${targets.length} passwords found in known breaches.`
      auditVaultProgress.className = `export-status ${breached.length > 0 ? 'err' : 'ok'}`
      auditVaultResults.innerHTML = results.map(r => {
        const statusStyle = r.err ? 'color:#64748b' : r.breached ? 'color:#ef4444' : 'color:#41d07f'
        const statusText = r.err ? 'check failed' : r.breached ? `⚠ ${r.count.toLocaleString()} breaches` : '✓ clean'
        return `<div class="audit-entry">
          <span class="audit-event">${r.site}</span>
          <span class="audit-site">${r.username}</span>
          <span class="audit-time" style="${statusStyle}">${statusText}</span>
        </div>`
      }).join('')
      auditVaultResults.classList.remove('hidden')
    } catch {
      auditVaultProgress.textContent = 'Failed — vault may be locked.'
      auditVaultProgress.className = 'export-status err'
    }
    ;(btnAuditVault as HTMLButtonElement).disabled = false
  })

  // Encrypted import
  const importEncPwInput = document.getElementById('import-enc-password') as HTMLInputElement
  const importEncFileInput = document.getElementById('import-enc-file') as HTMLInputElement
  const importEncFilename = document.getElementById('import-enc-filename')!
  const importEncStatus  = document.getElementById('import-enc-status')!

  document.getElementById('btn-import-enc-pick')!.addEventListener('click', () => importEncFileInput.click())
  importEncFileInput.addEventListener('change', () => {
    importEncFilename.textContent = importEncFileInput.files?.[0]?.name ?? ''
  })
  document.getElementById('btn-import-enc')!.addEventListener('click', async () => {
    const file = importEncFileInput.files?.[0]
    const pw = importEncPwInput.value.trim()
    if (!file) {
      importEncStatus.textContent = 'Choose a .foilvault file first.'
      importEncStatus.className = 'export-status err'
      return
    }
    if (!pw) {
      importEncStatus.textContent = 'Enter the backup password.'
      importEncStatus.className = 'export-status err'
      return
    }
    try {
      const text = await file.text()
      const creds = await importEncrypted(text, pw)
      if (!confirm(`Import ${creds.length} credential${creds.length !== 1 ? 's' : ''} into your vault?`)) return
      for (const c of creds) await addCredential(c)
      await logAuditEvent('vault_import')
      importEncPwInput.value = ''
      importEncFileInput.value = ''
      importEncFilename.textContent = ''
      importEncStatus.textContent = `✓ Imported ${creds.length} credentials.`
      importEncStatus.className = 'export-status ok'
      setTimeout(() => { importEncStatus.textContent = '' }, 4000)
    } catch {
      importEncStatus.textContent = 'Failed — wrong password or invalid file.'
      importEncStatus.className = 'export-status err'
    }
  })

  // Security log
  async function renderAuditLog(): Promise<void> {
    const container = document.getElementById('audit-log')!
    const entries = await getAuditLog()
    if (entries.length === 0) {
      container.innerHTML = '<p class="audit-empty">No events recorded yet.</p>'
      return
    }
    container.innerHTML = entries.slice(0, 100).map(e => {
      const time = new Date(e.ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      return `<div class="audit-entry">
        <span class="audit-event">${formatAuditEvent(e.event)}</span>
        ${e.site ? `<span class="audit-site">${e.site}</span>` : '<span></span>'}
        <span class="audit-time">${time}</span>
      </div>`
    }).join('')
  }

  await renderAuditLog()

  document.getElementById('btn-clear-log')!.addEventListener('click', async () => {
    await clearAuditLog()
    await renderAuditLog()
  })
})
