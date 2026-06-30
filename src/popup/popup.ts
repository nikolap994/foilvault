import './popup.css'
import {
  isVaultInitialized, isVaultUnlocked, initVault, unlockVault, lockVault,
  getCredentials, getFolders, addCredential, updateCredential, deleteCredential,
  pinCredential, exportCredentials, generatePassword, type Credential,
} from '../lib/vault'
import { importCredentials, detectFormat } from '../lib/import'
import { checkPasswordBreach } from '../lib/hibp'
import { measureStrength } from '../lib/strength'
import { generateTOTP, secondsRemaining, validateBase32Secret } from '../lib/totp'
import { logAuditEvent } from '../lib/audit'
import { generatePassphrase, passphraseEntropy, WORDLIST } from '../lib/passphrase'

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
const cardFields = $('card-fields'), identityFields = $('identity-fields')
const typeBtnLogin = $b('type-login'), typeBtnNote = $b('type-note')
const typeBtnCard = $b('type-card'), typeBtnId = $b('type-id')
const folderDatalist = $('folder-list') as HTMLDataListElement
// card inputs
const fCardHolder = $i('f-card-holder'), fCardNumber = $i('f-card-number')
const fCardExpiry = $i('f-card-expiry'), fCardCvv = $i('f-card-cvv')
// identity inputs
const fIdFirst = $i('f-id-first'), fIdLast = $i('f-id-last')
const fIdEmail = $i('f-id-email'), fIdPhone = $i('f-id-phone')
const fIdAddress = $i('f-id-address'), fIdDob = $i('f-id-dob')
// import
const btnImport = $b('btn-import'), btnImportBack = $b('btn-import-back')
const importFileInput = $i('import-file-input'), fileDropZone = $('file-drop-zone')
const importFileName = $('import-file-name'), importPreview = $('import-preview')
const importStatus = $('import-status'), btnImportConfirm = $b('btn-import-confirm')
// export
const btnExport = $b('btn-export')
// gen — random password
const genOutput = $('gen-output'), genLen = $i('gen-len'), genUpper = $i('gen-upper')
const genNums = $i('gen-nums'), genSyms = $i('gen-syms'), btnRegen = $b('btn-regen')
const btnCopy = $b('btn-copy'), copyStatus = $('copy-status'), btnGenBack = $b('btn-gen-back')
const genStrengthBar = $('gen-strength-bar'), genStrengthLabel = $('gen-strength-label')
const genStrengthWrap = $('gen-strength-wrap'), genEntropyLabel = $('gen-entropy-label')
const genPwOpts = $('gen-pw-opts'), genPpOpts = $('gen-pp-opts')
const genTabPw = $b('gen-tab-pw'), genTabPp = $b('gen-tab-pp')
// gen — passphrase
const ppWords = $i('pp-words'), ppSep = $s('pp-sep')
const ppCap = $i('pp-cap'), ppNum = $i('pp-num')
let genMode: 'pw' | 'pp' = 'pw'

// ─── State ─────────────────────────────────────────────────────────────────
let allCreds: Credential[] = []
let editingId: string | null = null
let credType: 'login' | 'note' | 'card' | 'identity' = 'login'
let totpInterval: ReturnType<typeof setInterval> | null = null

interface PopupOptions {
  clipboardClearSeconds: number
  hibpEnabled: boolean
  expiryWarningsEnabled: boolean
  genLength: number
  genUpper: boolean
  genDigits: boolean
  genSymbols: boolean
}
const OPTION_DEFAULTS: PopupOptions = {
  clipboardClearSeconds: 30, hibpEnabled: true, expiryWarningsEnabled: true,
  genLength: 20, genUpper: true, genDigits: true, genSymbols: true,
}
let cachedOptions: PopupOptions = { ...OPTION_DEFAULTS }
let clipboardClearTimer: ReturnType<typeof setTimeout> | null = null

async function loadCachedOptions(): Promise<void> {
  const stored = await chrome.storage.local.get('foilvault_options')
  cachedOptions = { ...OPTION_DEFAULTS, ...(stored.foilvault_options ?? {}) }
  genLen.value = String(cachedOptions.genLength)
  genUpper.checked = cachedOptions.genUpper
  genNums.checked = cachedOptions.genDigits
  genSyms.checked = cachedOptions.genSymbols
}

async function copyToClipboard(text: string): Promise<void> {
  await navigator.clipboard.writeText(text)
  if (clipboardClearTimer !== null) { clearTimeout(clipboardClearTimer); clipboardClearTimer = null }
  const secs = cachedOptions.clipboardClearSeconds
  if (secs <= 0) return
  clipboardClearTimer = setTimeout(async () => {
    clipboardClearTimer = null
    try { await navigator.clipboard.writeText('') } catch { /* popup lost focus */ }
  }, secs * 1000)
}

// ─── Init ──────────────────────────────────────────────────────────────────
async function init(): Promise<void> {
  show('loading')
  await loadCachedOptions()
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
  if (!cachedOptions.expiryWarningsEnabled) { expiryBanner.classList.add('hidden'); return }
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
    if (a.pinned && !b.pinned) return -1
    if (!a.pinned && b.pinned) return 1
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
    favicon.textContent = c.type === 'note' ? '📝' : c.type === 'card' ? '💳' : c.type === 'identity' ? '🪪' : c.site.charAt(0).toUpperCase()
    li.appendChild(favicon)

    const info = document.createElement('div')
    info.className = 'cred-info'
    const site = document.createElement('div'); site.className = 'cred-site'; site.textContent = c.site
    const sub = document.createElement('div'); sub.className = 'cred-user'
    if (c.type === 'note') sub.textContent = 'Secure note'
    else if (c.type === 'card') sub.textContent = c.cardNumber ? `•••• ${c.cardNumber.slice(-4)}` : 'Credit / debit card'
    else if (c.type === 'identity') sub.textContent = [c.idFirstName, c.idLastName].filter(Boolean).join(' ') || 'Identity'
    else sub.textContent = c.username + (c.folder ? ` · ${c.folder}` : '')
    info.appendChild(site); info.appendChild(sub); li.appendChild(info)

    // Pin button
    const pinBtn = document.createElement('button')
    pinBtn.className = `cred-copy${c.pinned ? ' cred-pin-active' : ''}`
    pinBtn.title = c.pinned ? 'Unpin' : 'Pin to top'
    pinBtn.textContent = '📌'
    pinBtn.addEventListener('click', async (e) => {
      e.stopPropagation()
      await pinCredential(c.id, !c.pinned)
      await loadList()
    })
    li.appendChild(pinBtn)

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
        await copyToClipboard(c.password)
        await logAuditEvent('credential_copy', c.site)
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
            await copyToClipboard(code)
            copyTotp.textContent = '✓'; setTimeout(() => { copyTotp.textContent = '🔑' }, 2000)
          } catch { copyTotp.textContent = '✗'; setTimeout(() => { copyTotp.textContent = '🔑' }, 1500) }
        })
        li.appendChild(copyTotp)
      }
    }

    li.addEventListener('click', async () => { await logAuditEvent('credential_view', c.site); openEdit(c) })
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
function setCredType(t: 'login' | 'note' | 'card' | 'identity'): void {
  credType = t
  typeBtnLogin.classList.toggle('active', t === 'login')
  typeBtnCard.classList.toggle('active', t === 'card')
  typeBtnId.classList.toggle('active', t === 'identity')
  typeBtnNote.classList.toggle('active', t === 'note')
  loginFields.classList.toggle('hidden', t !== 'login')
  cardFields.classList.toggle('hidden', t !== 'card')
  identityFields.classList.toggle('hidden', t !== 'identity')
  const ph: Record<typeof t, string> = { login: 'Site / App', card: 'Card name / label', identity: 'Identity name', note: 'Title' }
  fSite.placeholder = ph[t]
  if (t !== 'login') stopTotpPreview()
}
typeBtnLogin.addEventListener('click', () => setCredType('login'))
typeBtnCard.addEventListener('click', () => setCredType('card'))
typeBtnId.addEventListener('click', () => setCredType('identity'))
typeBtnNote.addEventListener('click', () => setCredType('note'))

// ─── Add / Edit ────────────────────────────────────────────────────────────
btnAdd.addEventListener('click', () => openAdd())

function clearForm(): void {
  fSite.value = ''; fUser.value = ''; fPass.value = ''; fNotes.value = ''
  fFolder.value = ''; fTotp.value = ''; fExpiry.value = ''
  fCardHolder.value = ''; fCardNumber.value = ''; fCardExpiry.value = ''; fCardCvv.value = ''
  fIdFirst.value = ''; fIdLast.value = ''; fIdEmail.value = ''; fIdPhone.value = ''; fIdAddress.value = ''; fIdDob.value = ''
  addStatus.textContent = ''; breachResult.classList.add('hidden')
  pwStrengthWrap.classList.add('hidden'); totpPreview.classList.add('hidden')
  $('pw-history-section').classList.add('hidden')
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
  fSite.value = c.site; fNotes.value = c.notes; fFolder.value = c.folder ?? ''
  if (c.type === 'login') {
    fUser.value = c.username; fPass.value = c.password; fTotp.value = c.totp ?? ''
    if (c.expiresAt) fExpiry.value = new Date(c.expiresAt).toISOString().slice(0, 10)
    if (c.password) fPass.dispatchEvent(new Event('input'))
    if (c.totp) startTotpPreview(c.totp)
  } else if (c.type === 'card') {
    fCardHolder.value = c.cardHolder ?? ''; fCardNumber.value = c.cardNumber ?? ''
    fCardExpiry.value = c.cardExpiry ?? ''; fCardCvv.value = c.cardCvv ?? ''
  } else if (c.type === 'identity') {
    fIdFirst.value = c.idFirstName ?? ''; fIdLast.value = c.idLastName ?? ''
    fIdEmail.value = c.idEmail ?? ''; fIdPhone.value = c.idPhone ?? ''
    fIdAddress.value = c.idAddress ?? ''; fIdDob.value = c.idDob ?? ''
  }
  btnDelete.classList.remove('hidden')
  btnBreachCheck.classList.toggle('hidden', !cachedOptions.hibpEnabled)
  // Password history
  const histSection = $('pw-history-section')
  const histList = $('pw-history-list')
  histList.innerHTML = ''
  if (c.passwordHistory?.length) {
    c.passwordHistory.forEach(h => {
      const entry = document.createElement('div'); entry.className = 'pw-hist-entry'
      const pw = document.createElement('span'); pw.className = 'pw-hist-pw'; pw.textContent = '••••••••'
      const copyBtn = document.createElement('button'); copyBtn.className = 'pw-hist-copy'; copyBtn.textContent = 'copy'
      copyBtn.addEventListener('click', async () => {
        await copyToClipboard(h.password); copyBtn.textContent = '✓'
        setTimeout(() => { copyBtn.textContent = 'copy' }, 1500)
      })
      const revBtn = document.createElement('button'); revBtn.className = 'pw-hist-copy'; revBtn.textContent = 'show'
      revBtn.addEventListener('click', () => {
        const hidden = pw.textContent === '••••••••'
        pw.textContent = hidden ? h.password : '••••••••'; revBtn.textContent = hidden ? 'hide' : 'show'
      })
      const date = document.createElement('span'); date.className = 'pw-hist-date'
      date.textContent = new Date(h.changedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
      entry.append(pw, copyBtn, revBtn, date); histList.appendChild(entry)
    })
    histSection.classList.remove('hidden')
  } else {
    histSection.classList.add('hidden')
  }
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
  const labels: Record<typeof credType, string> = { login: 'Site', card: 'Card name', identity: 'Identity name', note: 'Title' }
  if (!site) { addStatus.textContent = `${labels[credType]} is required.`; return }
  if (credType === 'login' && !fPass.value) { addStatus.textContent = 'Password is required.'; return }
  if (credType === 'login' && fTotp.value && !validateBase32Secret(fTotp.value)) { addStatus.textContent = 'Invalid TOTP secret — must be base32.'; return }
  btnSave.disabled = true
  const folder = fFolder.value.trim() || undefined
  try {
    let cred: Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>
    if (credType === 'login') {
      const expiresAt = fExpiry.value ? new Date(fExpiry.value).getTime() : undefined
      cred = { type: 'login', site, username: fUser.value.trim(), password: fPass.value, notes, folder, totp: fTotp.value.trim() || undefined, expiresAt }
    } else if (credType === 'card') {
      cred = { type: 'card', site, username: '', password: '', notes, folder, cardHolder: fCardHolder.value.trim(), cardNumber: fCardNumber.value.trim(), cardExpiry: fCardExpiry.value.trim(), cardCvv: fCardCvv.value.trim() }
    } else if (credType === 'identity') {
      cred = { type: 'identity', site, username: '', password: '', notes, folder, idFirstName: fIdFirst.value.trim(), idLastName: fIdLast.value.trim(), idEmail: fIdEmail.value.trim(), idPhone: fIdPhone.value.trim(), idAddress: fIdAddress.value.trim(), idDob: fIdDob.value || undefined }
    } else {
      cred = { type: 'note', site, username: '', password: '', notes, folder }
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
    await logAuditEvent('vault_import')
    importStatus.className = 'status-msg status-ok'; importStatus.textContent = `✓ Imported ${pendingImport.length} credentials.`
    btnImportConfirm.classList.add('hidden'); pendingImport = []; await loadList()
    setTimeout(() => show('unlocked'), 1200)
  } catch { importStatus.className = 'status-msg'; importStatus.textContent = 'Import failed.'; btnImportConfirm.disabled = false; btnImportConfirm.textContent = 'Import → add credentials' }
})

// ─── Generator ────────────────────────────────────────────────────────────
function genPw(): string {
  return generatePassword({
    length: Math.max(8, Math.min(64, Number(genLen.value) || 20)),
    upper: genUpper.checked,
    numbers: genNums.checked,
    symbols: genSyms.checked,
  })
}

function setGenMode(mode: 'pw' | 'pp'): void {
  genMode = mode
  genTabPw.classList.toggle('active', mode === 'pw')
  genTabPp.classList.toggle('active', mode === 'pp')
  genPwOpts.classList.toggle('hidden', mode !== 'pw')
  genPpOpts.classList.toggle('hidden', mode !== 'pp')
  genStrengthWrap.classList.toggle('hidden', mode !== 'pw')
  genEntropyLabel.classList.toggle('hidden', mode !== 'pp')
  refreshGen()
}

function refreshGen(): void {
  copyStatus.textContent = ''; copyStatus.className = 'status-msg'
  if (genMode === 'pw') {
    const pw = genPw(); genOutput.textContent = pw
    const r = measureStrength(pw)
    genStrengthBar.style.background = r.color; genStrengthBar.style.width = `${(r.score / 4) * 100}%`
    genStrengthLabel.textContent = r.label; (genStrengthLabel as HTMLElement).style.color = r.color
  } else {
    const words = Math.max(3, Math.min(8, Number(ppWords.value) || 4))
    const pp = generatePassphrase({ wordCount: words, separator: ppSep.value, capitalize: ppCap.checked, appendNumber: ppNum.checked })
    genOutput.textContent = pp
    genEntropyLabel.textContent = `~${passphraseEntropy(words)} bits of entropy · ${WORDLIST.length.toLocaleString()} word list`
  }
}

genTabPw.addEventListener('click', () => setGenMode('pw'))
genTabPp.addEventListener('click', () => setGenMode('pp'))
btnGen.addEventListener('click', () => { prevView = 'unlocked'; refreshGen(); show('gen') })
btnGenBack.addEventListener('click', () => show(prevView))
btnRegen.addEventListener('click', refreshGen)
btnCopy.addEventListener('click', async () => {
  await copyToClipboard(genOutput.textContent ?? '')
  copyStatus.textContent = 'Copied!'; copyStatus.className = 'status-msg status-ok'
  setTimeout(() => { copyStatus.textContent = ''; copyStatus.className = 'status-msg' }, 2000)
})
;[genLen, genUpper, genNums, genSyms].forEach(el => el.addEventListener('change', refreshGen))
;[ppWords, ppCap, ppNum].forEach(el => el.addEventListener('change', refreshGen))
ppSep.addEventListener('change', refreshGen)

init()
