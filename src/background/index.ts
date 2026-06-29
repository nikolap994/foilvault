import { clearSessionKey, getCredentials, isVaultUnlocked } from '../lib/vault'

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/onboarding/onboarding.html') })
  }
})

// Auto-lock on idle (15 min)
chrome.idle.setDetectionInterval(900)
chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === 'idle' || state === 'locked') {
    await clearSessionKey()
  }
})

// Autofill: content script asks for credentials matching the current hostname
chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  if (msg?.type !== 'autofill-get-credentials') return false
  const hostname: string = msg.hostname ?? ''

  ;(async () => {
    const unlocked = await isVaultUnlocked()
    if (!unlocked) { respond({ credentials: [] }); return }

    const all = await getCredentials()
    // Match by site name or URL hostname containment
    const matches = all.filter(c => {
      const s = c.site.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '')
      const h = hostname.toLowerCase().replace(/^www\./, '')
      return h.includes(s) || s.includes(h)
    })
    respond({ credentials: matches })
  })()

  return true
})
