# FoilVault — Privacy Policy

_Last updated: 2026-06-30_

---

## Overview

FoilVault is a local, encrypted credential manager. This policy explains what data the extension handles, where it stays, and what — if anything — leaves your device.

---

## Data collected and stored

FoilVault stores the following data exclusively in `chrome.storage.local` on your device:

| Data | Where | Why |
|------|-------|-----|
| Encrypted vault blob | `chrome.storage.local` | Stores your credentials, encrypted with AES-GCM 256-bit |
| PBKDF2 salt | `chrome.storage.local` | Required to re-derive the decryption key from your master password |
| Derived key (session) | `chrome.storage.session` | Held in memory while the vault is unlocked; cleared on lock or browser close |
| User preferences | `chrome.storage.local` | Auto-lock timer, clipboard delay, generator settings |

**Your master password is never stored anywhere.** Only the derived key is held in memory during an active session, and only in `chrome.storage.session` (which clears when the browser closes).

---

## Data transmitted

FoilVault makes exactly one type of outbound network request:

**HIBP breach check (optional, user-initiated)**

When you click "Check for breaches" on a credential, FoilVault sends the **first 5 hex characters** of the SHA-1 hash of the password to the Have I Been Pwned k-anonymity API (`api.pwnedpasswords.com`). The server returns all hash suffixes that match that prefix. FoilVault checks locally whether your full hash is in the returned list.

- The full password is never transmitted
- The full SHA-1 hash is never transmitted
- The result is never logged or stored beyond the current popup session
- This request is opt-in and triggered only by an explicit user action

No other network requests are made. There is no cloud sync, no telemetry, no analytics, no crash reporting.

---

## Permissions

| Permission | Why it is needed |
|------------|-----------------|
| `storage` | Read/write the encrypted vault and preferences |
| `clipboardWrite` | Copy passwords to clipboard on request |
| `idle` | Detect when the browser is idle to trigger auto-lock |
| `host_permissions: <all_urls>` | Required for the autofill content script to detect login forms on any site |

---

## Data sharing

FoilVault shares no data with any third party. The only external request is the HIBP k-anonymity call described above, which by design reveals nothing about the full password.

---

## Security

- AES-GCM 256-bit encryption via the browser's built-in WebCrypto API
- PBKDF2-SHA256 key derivation, 600 000 iterations
- Vault is encrypted at rest; decryption key is never persisted to disk
- Auto-lock clears the session key from memory after a configurable idle period

---

## Contact

FoilVault is open source. Security issues: [github.com/nikolap994/foilvault/security](https://github.com/nikolap994/foilvault/security)

General contact: nikolap994@gmail.com
