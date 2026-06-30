# FoilVault — Chrome Web Store Listing

## Name
FoilVault

## Short description (132 chars max)
Encrypted local password manager. AES-GCM 256-bit. PBKDF2 600k. Autofill. TOTP. Passphrase gen. Health report. No cloud.

## Category
Productivity → Tools

## Language
English

---

## Full description

FoilVault is a fully local, encrypted credential manager for Chrome. Everything stays in your browser — no cloud sync, no account required, no data ever leaves your device.

**Encryption model:**
• AES-GCM 256-bit encryption for all stored credentials
• PBKDF2-SHA256 key derivation with 600 000 iterations — brute-force resistant
• Master password never stored — only a derived key is held in memory during the session
• Vault encrypted at rest in `chrome.storage.local`; wiped from memory on auto-lock

**What FoilVault stores:**
• Login credentials (site, username, password, TOTP)
• Credit card details (cardholder, number, expiry, CVV)
• Identity records (name, email, phone, address, DOB)
• Secure notes
• Custom folders, expiry dates, and notes per credential

**Features:**
• Autofill — detects login forms and fills credentials on demand; context-menu fill via right-click
• Password generator — configurable length, character sets, no external calls
• Passphrase generator — word-based passphrases with configurable separator, capitalization, and appended number
• Password history — last 10 passwords per credential, viewable in edit mode
• Security health report — detects weak, reused, expired, and old (90+ day) passwords in one scan
• HIBP breach check — per-credential and bulk vault audit via k-anonymity (first 5 chars of SHA-1 only)
• Import — CSV (Bitwarden, 1Password, LastPass) and encrypted `.foilvault` backup restore
• Export — plain CSV or encrypted JSON vault backup
• Auto-lock — locks after configurable idle period (1, 5, 15, 30 minutes)
• Clipboard auto-clear — copied passwords cleared after configurable delay
• Pinned credentials — pin important logins to the top of the list
• Lock badge — browser action badge turns red when vault is locked
• Keyboard shortcut — `Alt+Shift+V` opens the popup
• Audit log — timestamped record of unlock, autofill, export, import, and breach check events

**Privacy:**
• Zero telemetry — no analytics, no crash reporting, no usage tracking
• No account or sign-in
• HIBP check uses k-anonymity: only the first 5 hex characters of a SHA-1 hash are sent; the server never sees the full password or hash
• All cryptographic operations use the browser's built-in WebCrypto API — no third-party crypto libraries

**Open source:**
FoilVault is part of the Foil Security Suite, open source under AGPL-3.0.
Source: https://github.com/nikolap994/foilvault

---

## Screenshots
_(see store/screenshots/ — 1280×800 or 640×400 PNG)_

1. Vault unlocked — credential list with search, folder filter, and pinned entries
2. Add credential — type selector (Login / Card / ID / Note), strength meter, TOTP
3. TOTP view — 6-digit code with countdown ring
4. Password / passphrase generator — random and word-based modes
5. Security health report — weak, reused, expired, and old password cards
6. Options — autofill, auto-lock, HIBP, expiry warnings, clipboard clear settings
7. Onboarding — feature overview on first install
