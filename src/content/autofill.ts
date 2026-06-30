// Guard: never run inside an iframe (cross-origin credential injection risk)
if (window.self !== window.top) {
  throw new Error('foilvault:iframe-guard')
}

// Detects login forms on the page and injects a fill affordance
const VAULT_ICON = '🔒'
let fillBtn: HTMLButtonElement | null = null
let activePasswordField: HTMLInputElement | null = null
let activeUsernameField: HTMLInputElement | null = null
let fillMenu: HTMLDivElement | null = null

function findUsernameField(pwField: HTMLInputElement): HTMLInputElement | null {
  const form = pwField.form
  const inputs = form
    ? Array.from(form.querySelectorAll<HTMLInputElement>('input'))
    : Array.from(document.querySelectorAll<HTMLInputElement>('input'))

  const idx = inputs.indexOf(pwField)
  for (let i = idx - 1; i >= 0; i--) {
    const t = inputs[i].type.toLowerCase()
    if (t === 'text' || t === 'email' || t === 'tel') return inputs[i]
  }
  return null
}

function removeFillUI(): void {
  fillBtn?.remove(); fillBtn = null
  fillMenu?.remove(); fillMenu = null
}

function showFillButton(pwField: HTMLInputElement): void {
  removeFillUI()
  activePasswordField = pwField
  activeUsernameField = findUsernameField(pwField)

  const rect = pwField.getBoundingClientRect()
  const scrollY = window.scrollY
  const scrollX = window.scrollX

  const btn = document.createElement('button')
  btn.textContent = VAULT_ICON
  btn.title = 'Fill with FoilVault'
  btn.setAttribute('type', 'button')
  btn.style.cssText = `
    position: absolute;
    top: ${rect.top + scrollY + rect.height / 2 - 12}px;
    left: ${rect.right + scrollX - 28}px;
    width: 24px;
    height: 24px;
    border: none;
    background: none;
    cursor: pointer;
    font-size: 14px;
    line-height: 1;
    z-index: 2147483647;
    padding: 0;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: opacity 0.15s;
    opacity: 0.7;
  `
  btn.addEventListener('mouseenter', () => { btn.style.opacity = '1' })
  btn.addEventListener('mouseleave', () => { btn.style.opacity = '0.7' })
  btn.addEventListener('click', (e) => { e.stopPropagation(); e.preventDefault(); openFillMenu(btn) })

  document.body.appendChild(btn)
  fillBtn = btn
}

function openFillMenu(anchor: HTMLButtonElement): void {
  fillMenu?.remove()

  const menu = document.createElement('div')
  menu.style.cssText = `
    position: absolute;
    top: ${parseInt(anchor.style.top) + 28}px;
    left: ${parseInt(anchor.style.left) - 180}px;
    width: 220px;
    background: #0f1117;
    border: 1px solid rgba(129,140,248,0.3);
    border-radius: 8px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
    z-index: 2147483647;
    overflow: hidden;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  `

  const header = document.createElement('div')
  header.style.cssText = 'padding: 10px 14px 8px; font-size: 11px; color: #475569; font-weight: 600; border-bottom: 1px solid rgba(255,255,255,0.06); letter-spacing: 0.06em;'
  header.textContent = '🔒 FOILVAULT'
  menu.appendChild(header)

  const loading = document.createElement('div')
  loading.style.cssText = 'padding: 12px 14px; font-size: 13px; color: #64748b;'
  loading.textContent = 'Loading credentials…'
  menu.appendChild(loading)

  document.body.appendChild(menu)
  fillMenu = menu

  chrome.runtime.sendMessage({ type: 'autofill-get-credentials', hostname: location.hostname, url: location.href }, (res) => {
    loading.remove()
    if (chrome.runtime.lastError || !res) {
      const err = document.createElement('div')
      err.style.cssText = 'padding: 12px 14px; font-size: 12px; color: #ef4444;'
      err.textContent = 'Vault locked or unavailable.'
      menu.appendChild(err)
      return
    }
    const creds: Array<{ id: string; site: string; username: string; password: string }> = res.credentials ?? []
    if (creds.length === 0) {
      const empty = document.createElement('div')
      empty.style.cssText = 'padding: 12px 14px; font-size: 12px; color: #475569;'
      empty.textContent = 'No credentials for this site.'
      menu.appendChild(empty)
      return
    }
    for (const c of creds) {
      const row = document.createElement('button')
      row.setAttribute('type', 'button')
      row.style.cssText = `
        display: flex; flex-direction: column; gap: 2px;
        width: 100%; background: none; border: none;
        padding: 10px 14px; cursor: pointer; text-align: left;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        transition: background 0.1s;
      `
      row.addEventListener('mouseenter', () => { row.style.background = 'rgba(129,140,248,0.08)' })
      row.addEventListener('mouseleave', () => { row.style.background = 'none' })
      const site = document.createElement('span')
      site.style.cssText = 'font-size: 12px; font-weight: 600; color: #e2e8f0;'
      site.textContent = c.site
      const user = document.createElement('span')
      user.style.cssText = 'font-size: 11px; color: #475569;'
      user.textContent = c.username
      row.appendChild(site)
      row.appendChild(user)
      row.addEventListener('click', () => {
        fillCredential(c.username, c.password)
        removeFillUI()
      })
      menu.appendChild(row)
    }
  })

  setTimeout(() => {
    document.addEventListener('click', () => { fillMenu?.remove(); fillMenu = null }, { once: true })
  }, 50)
}

function fillCredential(username: string, password: string): void {
  if (activePasswordField) {
    activePasswordField.focus()
    activePasswordField.value = password
    activePasswordField.dispatchEvent(new Event('input', { bubbles: true }))
    activePasswordField.dispatchEvent(new Event('change', { bubbles: true }))
  }
  if (activeUsernameField && username) {
    activeUsernameField.value = username
    activeUsernameField.dispatchEvent(new Event('input', { bubbles: true }))
    activeUsernameField.dispatchEvent(new Event('change', { bubbles: true }))
  }
}

// ─── Watch for password fields ─────────────────────────────────────────────
function attachToPasswordFields(): void {
  document.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(field => {
    if (field.dataset.foilvaultAttached) return
    field.dataset.foilvaultAttached = '1'
    field.addEventListener('focus', () => showFillButton(field))
    field.addEventListener('blur', () => {
      setTimeout(() => {
        if (!fillMenu) removeFillUI()
      }, 200)
    })
  })
}

// Handle context-menu fill: background resolves matching credentials and sends them here
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== 'foilvault-context-fill') return
  const creds: Array<{ site: string; username: string; password: string }> = msg.credentials ?? []
  if (!activePasswordField) return
  if (creds.length === 1) {
    fillCredential(creds[0].username, creds[0].password)
  } else if (creds.length > 1) {
    showFillButton(activePasswordField)
  }
})

async function init(): Promise<void> {
  const stored = await chrome.storage.local.get('foilvault_options')
  const enabled: boolean = stored.foilvault_options?.autofillEnabled ?? true
  if (!enabled) return
  attachToPasswordFields()
  const observer = new MutationObserver(() => attachToPasswordFields())
  observer.observe(document.body, { childList: true, subtree: true })
}

init()
