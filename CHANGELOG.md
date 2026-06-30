# Changelog

All notable changes to FoilVault are documented here.

---

## [0.3.0] — 2026-06-30

### Added
- **Password history** — when a credential's password is updated, the previous password is stored (up to 10 entries, AES-GCM encrypted in the vault blob). Visible in the edit form with show/copy per entry
- **Passphrase generator** — second tab in the generator view; uses a curated 512-word list (~9 bits/word); configurable word count (3–8), separator (hyphen/dot/space/underscore), optional capitalization and number suffix; entropy shown in bits
- **Security health report** — options page "Security health" section scans the vault for weak passwords (strength score < 2), reused passwords (credentials sharing the same password), and expired passwords; all checks run locally
- **Vault breach audit** — options page "Vault audit" section runs HIBP k-anonymity checks on all saved passwords; shows per-credential results with breach count
- **Encrypted backup restore** — options page "Restore from backup" section imports credentials from `.foilvault` encrypted backup files using PBKDF2 + AES-GCM decryption
- **Audit log** — 11 event types tracked: vault create/unlock/lock, autofill, credential copy/view/add/delete, HIBP check, vault export/import; last 300 events stored locally; viewable and clearable in options page

### Changed
- Generator defaults (length, uppercase, numbers, symbols) now load from the options page on popup init — `btnFillGen` in the add form uses saved defaults
- Clipboard auto-clear is now wired to the `clipboardClearSeconds` option; each password/TOTP/generator copy schedules a clear; a new copy cancels the previous timer
- `expiryWarningsEnabled` option now correctly hides the expiry banner when disabled
- `hibpEnabled` option now correctly hides the breach check button when disabled
- Autofill content script respects the `autofillEnabled` option — if disabled in settings, no password fields are decorated
- HIBP breach check, plain export, and encrypted export now emit audit events

---

## [0.2.0] — 2026-06-30

### Added
- **Onboarding page** — opens automatically on first install; explains encryption model, key derivation, local-first design, and advanced features
- **Options page** — auto-lock timer, clipboard clear delay, HIBP breach check toggle, password generator defaults, and theme preference; settings persisted via `chrome.storage.local`
- **Light theme** — full `prefers-color-scheme: light` support across popup and onboarding
- **Architecture doc** (`docs/architecture.md`) — documents vault format, PBKDF2-SHA256 key derivation (600 k iterations), AES-GCM-256 encryption, and autofill design

### Changed
- `chrome.runtime.onInstalled` handler now opens onboarding tab on first install (was a no-op)

---

## [0.1.0] — 2026-06-01

### Added
- Initial release
- AES-GCM 256-bit encrypted credential store via WebCrypto
- PBKDF2-SHA256 key derivation (600 000 iterations)
- Master password create / unlock flow
- Credential list with search and folder filter
- Add / edit / delete credentials with site, username, password, TOTP secret, notes, folder, expiry
- Password generator (configurable length and character sets)
- TOTP code display with 30-second countdown
- HIBP breach check via k-anonymity API
- Import from CSV (Bitwarden / 1Password format)
- Export encrypted JSON vault
- Clipboard auto-clear after 30 seconds
- Autofill content script — detects login forms and injects credentials on demand
- Auto-lock on browser idle (configurable)
- Build pipeline with Vite + `@crxjs/vite-plugin`
