import './popup.css'
import {
  isVaultInitialized, isVaultUnlocked, initVault, unlockVault, lockVault,
  getCredentials, getFolders, addCredential, updateCredential, deleteCredential,
  exportCredentials, generatePassword, type Credential,
} from '../lib/vault'
import { importCredentials, detectFormat } from '../lib/import'
import { checkPasswordBreach } from '../lib/hibp'
import { measureStrength } from '../lib/strength'
import { generateTOTP, secondsRemaining, validateBase32Secret } from '../lib/totp'

// ─── Views ─────────────────────────────────────────────────────────────────
type View = 'loading' | 'firstrun' | 'locked' | 'unlocked' | 'add' | 'gen' | 'import'

const views: Record<View, string> = {
  loading: 'view-loading', firstrun: 'view-firstrun', locked: 'view-locked',
  unlocked: 'view-unlocked', add: 'view-add', gen: 'view-gen', import: 'view-import',
}

let prevView: View = 'unlocked'

function show(v: View): void {
  for (const [key, id] of Object.entries(views)) {
    document.getElementById(id)!.classList.toggle('hidden', key !== v)
  }
  const ha = document.getElementById('header-actions')!
  ha.style.display = (v === 'unlocked' || v === 'add' || v === 'import') ? 'flex' : 'none'
}

// ─── Elements ──────────────────────────────────────────────────────────────
const $  = (id: string) => document.getElementById(id)!
const $i = (id: string) => document.getElementById(id) as HTMLInputElement
const $b = (id: string) => document.getElementById(id) as HTMLButtonElement
const $s = (id: string) => document.getElementById(id) as HTMLSelectElement

// firstrun
const btnCreate = $b('btn-create'), newMp = $i('new-mp'), newMp2 = $i('new-mp2')
const firstrunStatus = $('firstrun-status')
// locked
const mpInput = $i('mp-input'), btnUnlock = $b('btn-unlock'), lockedStatus = $('locked-status')
// unlocked
const searchInput = $i('search-input'), credList = $('cred-list'), credEmpty = $('cred-empty')
const btnAdd = $b('btn-add'), btnLock = $b('btn-lock'), btnGen = $b('btn-gen')
const folderFilter = $s('folder-filter'), sortSelect = $s('sort-select')
const expiryBanner = $('expiry-banner'), expiryBannerText = $('expiry-banner-text')
// add/edit
const btnCancel = $b('btn-cancel'), btnSave = $b('btn-save'), btnDelete = $b('btn-delete')
const formTitle = $('form-title'), addStatus = $('add-status')
const fSite = $i('f-site'), fUser = $i('f-user'), fPass = $i('f-pass')
const fNotes = document.getElementById('f-notes') as HTMLTextAreaElement
const fFolder = $i('f-folder'), fTotp = $i('f-totp'), fExpiry = $i('f-expiry')
const btnShowPass = $b('btn-show-pass'), btnFillGen = $b('btn-fill-gen')
const btnBreachCheck = $b('btn-breach-check'), breachResult = $('breach-result')
const pwStrengthWrap = $('pw-strength-wrap'), pwStrengthBar = $('pw-strength-bar')
const pwStrengthLabel = $('pw-strength-label'), pwStrengthEntropy = $('pw-strength-entropy')
const totpPreview = $('totp-preview'), loginFields = $('login-fields')
const typeBtnLogin = $b('type-login'), typeBtnNote = $b('type-note')
const folderDatalist = $('folder-list') as HTMLDataListElement
// import
const btnImport = $b('btn-import'), btnImportBack = $b('btn-import-back')
const importFileInput = $i('import-file-input'), fileDropZone = $('file-drop-zone')
const importFileName = $('import-file-name'), importPreview = $('import-preview')
const importStatus = $('import-status'), btnImportConfirm = $b('btn-import-confirm')
// export
const btnExport = $b('btn-export')
// gen
const genOutput = $('gen-output'), genLen = $i('gen-len'), genUpper = $i('gen-upper')
const genNums = $i('gen-nums'), genSyms = $i('gen-syms'), btnRegen = $b('btn-regen')
const btnCopy = $b('btn-copy'), copyStatus = $('copy-status'), btnGenBack = $b('btn-gen-back')
const genStrengthBar = $('gen-strength-bar'), genStrengthLabel = $('gen-strength-label')

// ─── State ─────────────────────────────────────────────────────────────────
let allCreds: Credential[] = []
let editingId: string | null = null
let credType: 'login' | 'note' = 'login'
let totpInterval: ReturnType<typeof setInterval> | null = null

// ─── Init ──────────────────────────────────────────────────────────────────
async function init(): Promise<void> {
  show('loading')
  if (!(await isVaultInitialized())) { show('firstrun'); setupStrengthOnInput(newMp, 'new-mp-strength', 'new-mp-bar', 'new-mp-label'); return }
  if (await isVaultUnlocked()) { await loadList() } else { show('locked'); mpInput.focus() }
}

// ─── Strength meter ────────────────────────────────────────────────────────
function setupStrengthOnInput(input: HTMLInputElement, wrapId: string, barId: string, labelId: string): void {
  const wrap = $(wrapId), bar = $(barId), label = $(labelId)
  input.addEventListener('input', () => {
    const r = measureStrength(input.value)
    if (!input.value) { wrap.classList.add('hidden'); return }
    wrap.classList.remove('hidden')
    bar.style.background = r.color
    bar.style.width = `${(r.score / 4) * 100}%`
    label.textContent = r.label
    ;(label as HTMLElement).style.color = r.color
  })
}

// ─── First run ─────────────────────────────────────────────────────────────
btnCreate.addEventListener('click', async () => {
  const pw = newMp.value, pw2 = newMp2.value
  if (!pw || pw.length < 8) { firstrunStatus.textContent = 'Password must be at least 8 characters.'; return }
  if (pw !== pw2) { firstrunStatus.textContent = 'Passwords do not match.'; return }
  firstrunStatus.textContent = ''
  btnCreate.disabled = true; btnCreate.textContent = 'Creating…'
  try { await initVault(pw); await loadList() }
  catch { firstrunStatus.textContent = 'Failed to create vault.'; btnCreate.disabled = false; btnCreate.textContent = 'Create vault →' }
})
newMp2.addEventListener('keydown', e => { if (e.key === 'Enter') btnCreate.click() })

// ─── Unlock ────────────────────────────────────────────────────────────────
btnUnlock.addEventListener('click', async () => {
  const pw = mpInput.value; if (!pw) return
  btnUnlock.disabled = true; btnUnlock.textContent = 'Unlocking…'
  const ok = await unlockVault(pw)
  if (ok) { mpInput.value = ''; lockedStatus.textContent = ''; await loadList() }
  else { lockedStatus.textContent = 'Incorrect password.'; btnUnlock.disabled = false; btnUnlock.textContent = 'Unlock vault →'; mpInput.select() }
})
mpInput.addEventListener('keydown', e => { if (e.key === 'Enter') btnUnlock.click() })

// ─── Lock ──────────────────────────────────────────────────────────────────
btnLock.addEventListener('click', async () => { await lockVault(); show('locked'); mpInput.value = ''; mpInput.focus() })

// ─── List ──────────────────────────────────────────────────────────────────
async function loadList(): Promise<void> {
  allCreds = await getCredentials()
  await refreshFolderUI()
  renderList(allCreds)
  checkExpiry()
  show('unlocked')
}

async function refreshFolderUI(): Promise<void> {
  const folders = await getFolders()
  // Update datalist
  folderDatalist.innerHTML = ''
  folders.forEach(f => { const o = document.createElement('option'); o.value = f; folderDatalist.appendChild(o) })
  // Update filter select
  const cur = folderFilter.value
  folderFilter.innerHTML = '<option value="">All folders</option>'
  folders.forEach(f => { const o = document.createElement('option'); o.value = f; o.textContent = f; folderFilter.appendChild(o) })
  folderFilter.value = folders.includes(cur) ? cur : ''
  folderFilter.classList.toggle('hidden', folders.length === 0)
}

function checkExpiry(): void {
  const now = Date.now()
  const expiring = allCreds.filter(c => c.expiresAt && c.expiresAt <= now + 7 * 86400_000)
  if (expiring.length === 0) { expiryBanner.classList.add('hidden'); return }
  const expired = expiring.filter(c => c.expiresAt! <= now)
  const soon = expiring.filter(c => c.expiresAt! > now)
  const parts: string[] = []
  if (expired.length) parts.push(`${expired.length} password${expired.length > 1 ? 's' : ''} expired`)
  if (soon.length) parts.push(`${soon.length} expiring soon`)
  expiryBannerText.textContent = '⚠ ' + parts.join(' · ')
  expiryBanner.classList.remove('hidden')
}

function sortedCreds(creds: Credential[]): Credential[] {
  const order = sortSelect.value
  return [...creds].sort((a, b) => {
    if (order === 'added') return b.createdAt - a.createdAt
    if (order === 'updated') return b.updatedAt - a.updatedAt
    return a.site.localeCompare(b.site)
  })
}

function renderList(creds: Credential[]): void {
  credList.innerHTML = ''
  credEmpty.classList.toggle('hidden', creds.length > 0)
  const now = Date.now()
  for (const c of sortedCreds(creds)) {
    const li = document.createElement('li')
    li.className = 'cred-item'
    if (c.expiresAt && c.expiresAt <= now) li.classList.add('cred-expired')

    const favicon = document.createElement('div')
    favicon.className = 'cred-favicon'
    favicon.textContent = c.type === 'note' ? '📝' : c.site.charAt(0).toUpperCase()
    li.appendChild(favicon)

    const info = document.createElement('div')
    info.className = 'cred-info'
    const site = document.createElement('div'); site.className = 'cred-site'; site.textContent = c.site
    const sub = document.createElement('div'); sub.className = 'cred-user'
    if (c.type === 'note') { sub.textContent = 'Secure note' }
    else { sub.textContent = c.username + (c.folder ? ` · ${c.folder}` : '') }
    info.appendChild(site); info.appendChild(sub); li.appendChild(info)

    if (c.type !== 'note') {
      // Username copy
      if (c.username) {
        const copyUser = document.createElement('button')
        copyUser.className = 'cred-copy'; copyUser.title = 'Copy username'; copyUser.textContent = '👤'
        copyUser.addEventListener('click', async (e) => {
          e.stopPropagation()
          await navigator.clipboard.writeText(c.username)
          copyUser.textContent = '✓'; setTimeout(() => { copyUser.textContent = '👤' }, 1500)
        })
        li.appendChild(copyUser)
      }
      // Password copy
      const copyPw = document.createElement('button')
      copyPw.className = 'cred-copy'; copyPw.title = 'Copy password'; copyPw.textContent = '📋'
      copyPw.addEventListener('click', async (e) => {
        e.stopPropagation()
        await navigator.clipboard.writeText(c.password)
        copyPw.textContent = '✓'; setTimeout(() => { copyPw.textContent = '📋' }, 1500)
      })
      li.appendChild(copyPw)
      // TOTP copy
      if (c.totp && validateBase32Secret(c.totp)) {
        const copyTotp = document.createElement('button')
        copyTotp.className = 'cred-copy'; copyTotp.title = 'Copy 2FA code'; copyTotp.textContent = '🔑'
        copyTotp.addEventListener('click', async (e) => {
          e.stopPropagation()
          try {
            const code = await generateTOTP(c.totp!)
            await navigator.clipboard.writeText(code)
            copyTotp.textContent = '✓'; setTimeout(() => { copyTotp.textContent = '🔑' }, 2000)
          } catch { copyTotp.textContent = '✗'; setTimeout(() => { copyTotp.textContent = '🔑' }, 1500) }
        })
        li.appendChild(copyTotp)
      }
    }

    li.addEventListener('click', () => openEdit(c))
    credList.appendChild(li)
  }
}

function applyFilters(): void {
  const q = searchInput.value.toLowerCase()
  const folder = folderFilter.value
  renderList(allCreds.filter(c =>
    (c.site.toLowerCase().includes(q) || c.username.toLowerCase().includes(q) || c.notes.toLowerCase().includes(q)) &&
    (!folder || c.folder === folder)
  ))
}
searchInput.addEventListener('input', applyFilters)
folderFilter.addEventListener('change', applyFilters)
sortSelect.addEventListener('change', applyFilters)

// ─── Export ────────────────────────────────────────────────────────────────
btnExport.addEventListener('click', async () => {
  const fmt = confirm('Export as JSON? (Cancel = CSV)') ? 'json' : 'csv'
  const content = await exportCredentials(fmt)
  const mime = fmt === 'json' ? 'application/json' : 'text/csv'
  const dataUri = `data:${mime};charset=utf-8,${encodeURIComponent(content)}`
  const a = document.createElement('a'); a.href = dataUri
  a.download = `foilvault-export-${new Date().toISOString().slice(0, 10)}.${fmt}`
  a.click()
})

// ─── Type toggle ───────────────────────────────────────────────────────────
function setCredType(t: 'login' | 'note'): void {
  credType = t
  typeBtnLogin.classList.toggle('active', t === 'login')
  typeBtnNote.classList.toggle('active', t === 'note')
  loginFields.style.display = t === 'login' ? '' : 'none'
  fSite.placeholder = t === 'note' ? 'Title' : 'Site / App'
  if (t === 'note') { stopTotpPreview() }
}
typeBtnLogin.addEventListener('click', () => setCredType('login'))
typeBtnNote.addEventListener('click', () => setCredType('note'))

// ─── Add / Edit ────────────────────────────────────────────────────────────
btnAdd.addEventListener('click', () => openAdd())

function clearForm(): void {
  fSite.value = ''; fUser.value = ''; fPass.value = ''; fNotes.value = ''
  fFolder.value = ''; fTotp.value = ''; fExpiry.value = ''
  addStatus.textContent = ''; breachResult.classList.add('hidden')
  pwStrengthWrap.classList.add('hidden'); totpPreview.classList.add('hidden')
  stopTotpPreview()
}

function openAdd(): void {
  editingId = null; clearForm(); setCredType('login')
  formTitle.textContent = 'Add credential'
  btnDelete.classList.add('hidden'); btnBreachCheck.classList.add('hidden')
  prevView = 'unlocked'; show('add'); fSite.focus()
}

function openEdit(c: Credential): void {
  editingId = c.id; clearForm(); setCredType(c.type ?? 'login')
  formTitle.textContent = 'Edit credential'
  fSite.value = c.site; fUser.value = c.username; fPass.value = c.password
  fNotes.value = c.notes; fFolder.value = c.folder ?? ''; fTotp.value = c.totp ?? ''
  if (c.expiresAt) fExpiry.value = new Date(c.expiresAt).toISOString().slice(0, 10)
  if (c.password) fPass.dispatchEvent(new Event('input'))
  if (c.totp) startTotpPreview(c.totp)
  btnDelete.classList.remove('hidden'); btnBreachCheck.classList.remove('hidden')
  prevView = 'unlocked'; show('add'); fSite.focus()
}

btnCancel.addEventListener('click', () => { stopTotpPreview(); show('unlocked') })

// Password strength on input
fPass.addEventListener('input', () => {
  const r = measureStrength(fPass.value)
  if (!fPass.value) { pwStrengthWrap.classList.add('hidden'); return }
  pwStrengthWrap.classList.remove('hidden')
  pwStrengthBar.style.background = r.color
  pwStrengthBar.style.width = `${(r.score / 4) * 100}%`
  pwStrengthLabel.textContent = r.label;
  (pwStrengthLabel as HTMLElement).style.color = r.color
  pwStrengthEntropy.textContent = `${r.entropy} bits`
})

btnShowPass.addEventListener('click', () => {
  fPass.type = fPass.type === 'password' ? 'text' : 'password'
  btnShowPass.textContent = fPass.type === 'password' ? '👁' : '🙈'
})
btnFillGen.addEventListener('click', () => { fPass.value = genPw(); fPass.dispatchEvent(new Event('input')) })

// TOTP preview
function startTotpPreview(secret: string): void {
  stopTotpPreview()
  if (!validateBase32Secret(secret)) return
  async function update(): Promise<void> {
    try {
      const code = await generateTOTP(secret)
      const secs = secondsRemaining()
      totpPreview.textContent = `${code.slice(0, 3)} ${code.slice(3)} · ${secs}s`
      totpPreview.classList.remove('hidden')
    } catch { totpPreview.classList.add('hidden') }
  }
  update()
  totpInterval = setInterval(update, 1000)
}
function stopTotpPreview(): void {
  if (totpInterval) { clearInterval(totpInterval); totpInterval = null }
  totpPreview.classList.add('hidden')
}
fTotp.addEventListener('input', () => {
  const val = fTotp.value.trim()
  if (val && validateBase32Secret(val)) startTotpPreview(val)
  else stopTotpPreview()
})

btnSave.addEventListener('click', async () => {
  const site = fSite.value.trim()
  const notes = fNotes.value
  if (!site) { addStatus.textContent = credType === 'note' ? 'Title is required.' : 'Site is required.'; return }
  if (credType === 'login' && !fPass.value) { addStatus.textContent = 'Password is required.'; return }
  if (fTotp.value && !validateBase32Secret(fTotp.value)) { addStatus.textContent = 'Invalid TOTP secret — must be base32.'; return }
  btnSave.disabled = true
  const expiresAt = fExpiry.value ? new Date(fExpiry.value).getTime() : undefined
  try {
    const cred = {
      type: credType, site, username: fUser.value.trim(), password: fPass.value,
      notes, folder: fFolder.value.trim() || undefined, totp: fTotp.value.trim() || undefined, expiresAt,
    }
    if (editingId) await updateCredential(editingId, cred)
    else await addCredential(cred)
    stopTotpPreview(); await loadList()
  } catch { addStatus.textContent = 'Failed to save.'; btnSave.disabled = false }
})

btnDelete.addEventListener('click', async () => {
  if (!editingId || !confirm('Delete this credential?')) return
  try { stopTotpPreview(); await deleteCredential(editingId); await loadList() }
  catch { addStatus.textContent = 'Failed to delete.' }
})

// ─── Breach check ──────────────────────────────────────────────────────────
btnBreachCheck.addEventListener('click', async () => {
  const pw = fPass.value
  if (!pw) { breachResult.textContent = 'Enter a password first.'; breachResult.className = 'breach-result'; breachResult.classList.remove('hidden'); return }
  btnBreachCheck.textContent = 'Checking…'; btnBreachCheck.disabled = true
  breachResult.classList.remove('hidden'); breachResult.className = 'breach-result'; breachResult.textContent = ''
  try {
    const res = await checkPasswordBreach(pw)
    breachResult.className = `breach-result ${res.breached ? 'breach-danger' : 'breach-safe'}`
    breachResult.textContent = res.breached
      ? `⚠ Seen ${res.count.toLocaleString()} times in data breaches — change this password.`
      : '✓ Not found in known data breaches.'
  } catch { breachResult.textContent = 'Breach check failed (network error).' }
  btnBreachCheck.textContent = 'Check for breaches 🔍'; btnBreachCheck.disabled = false
})

// ─── Import ────────────────────────────────────────────────────────────────
let pendingImport: Array<{ type: 'login' | 'note'; site: string; username: string; password: string; notes: string }> = []

btnImport.addEventListener('click', () => {
  pendingImport = []; importPreview.classList.add('hidden'); importStatus.textContent = ''
  btnImportConfirm.classList.add('hidden'); importFileName.textContent = 'no file selected'
  prevView = 'unlocked'; show('import')
})
btnImportBack.addEventListener('click', () => show('unlocked'))
fileDropZone.addEventListener('click', () => importFileInput.click())
importFileInput.addEventListener('change', () => {
  const file = importFileInput.files?.[0]; if (!file) return
  importFileName.textContent = file.name
  const reader = new FileReader()
  reader.onload = (e) => {
    const text = e.target?.result as string
    const fmt = detectFormat(text)
    try {
      const raw = importCredentials(text, fmt)
      pendingImport = raw.map(r => ({ ...r, type: 'login' as const }))
      importPreview.innerHTML = `Detected: <strong>${fmt}</strong> · <strong>${pendingImport.length}</strong> credential${pendingImport.length !== 1 ? 's' : ''}`
      importPreview.classList.remove('hidden'); importStatus.textContent = ''
      btnImportConfirm.classList.toggle('hidden', pendingImport.length === 0)
    } catch { importStatus.textContent = 'Failed to parse CSV.' }
  }
  reader.readAsText(file); importFileInput.value = ''
})
btnImportConfirm.addEventListener('click', async () => {
  if (!pendingImport.length) return
  btnImportConfirm.disabled = true; btnImportConfirm.textContent = 'Importing…'
  try {
    for (const c of pendingImport) await addCredential(c)
    importStatus.className = 'status-msg status-ok'; importStatus.textContent = `✓ Imported ${pendingImport.length} credentials.`
    btnImportConfirm.classList.add('hidden'); pendingImport = []; await loadList()
    setTimeout(() => show('unlocked'), 1200)
  } catch { importStatus.className = 'status-msg'; importStatus.textContent = 'Import failed.'; btnImportConfirm.disabled = false; btnImportConfirm.textContent = 'Import → add credentials' }
})

// ─── Generator ────────────────────────────────────────────────────────────
function genPw(): string {
  return generatePassword({
    length: Math.max(8, Math.min(64, Number(genLen.value) || 20)),
    upper: (genUpper as HTMLInputElement).checked,
    numbers: (genNums as HTMLInputElement).checked,
    symbols: (genSyms as HTMLInputElement).checked,
  })
}

function refreshGen(): void {
  const pw = genPw(); genOutput.textContent = pw
  copyStatus.textContent = ''; copyStatus.className = 'status-msg'
  const r = measureStrength(pw)
  genStrengthBar.style.background = r.color; genStrengthBar.style.width = `${(r.score / 4) * 100}%`
  genStrengthLabel.textContent = r.label; (genStrengthLabel as HTMLElement).style.color = r.color
}

btnGen.addEventListener('click', () => { prevView = 'unlocked'; refreshGen(); show('gen') })
btnGenBack.addEventListener('click', () => show(prevView))
btnRegen.addEventListener('click', refreshGen)
btnCopy.addEventListener('click', async () => {
  await navigator.clipboard.writeText(genOutput.textContent ?? '')
  copyStatus.textContent = 'Copied!'; copyStatus.className = 'status-msg status-ok'
  setTimeout(() => { copyStatus.textContent = ''; copyStatus.className = 'status-msg' }, 2000)
})
;[genLen, genUpper, genNums, genSyms].forEach(el => el.addEventListener('change', refreshGen))

init()
