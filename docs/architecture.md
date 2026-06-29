# FoilVault — Architecture

## Overview

FoilVault is a zero-knowledge, local-first browser password manager. The server (if any) never sees plaintext credentials or the master password. All cryptographic operations happen in the browser extension.

---

## Threat model

**Protects against:**
- Credential theft from autofill on suspicious or spoofed domains (via FoilGuard integration)
- Vault data exposure if the device is compromised (encryption at rest)
- Phishing sites capturing autofilled credentials

**Does not protect against:**
- Compromised browser or OS kernel
- User entering credentials on a page FoilVault has already autofilled (social engineering)
- Physical access with unlocked vault

---

## Vault format

The vault is a single encrypted JSON blob stored in `chrome.storage.local`.

```
{
  "v": 1,
  "kdf": "pbkdf2",
  "kdf_params": {
    "hash": "SHA-256",
    "iterations": 600000,
    "salt": "<base64>"
  },
  "cipher": "aes-gcm-256",
  "iv": "<base64>",
  "ciphertext": "<base64>"
}
```

**Plaintext vault (after decryption):**
```json
{
  "entries": [
    {
      "id": "uuid-v4",
      "domain": "example.com",
      "username": "user@example.com",
      "password": "...",
      "totp_secret": "...",
      "notes": "",
      "created_at": 1700000000000,
      "updated_at": 1700000000000
    }
  ]
}
```

---

## Key derivation

Master password → `PBKDF2-SHA256` → 256-bit vault key

Current implementation parameters:
- Algorithm: PBKDF2 with SHA-256 (via `WebCrypto` — no native dependencies)
- Iterations: 600,000 (OWASP 2023 recommended minimum)
- Salt: 32 bytes, random per vault, stored in `chrome.storage.local`

The derived key is held in memory only while the vault is unlocked. It is never written to storage or sent anywhere.

> **Planned upgrade:** Argon2id (memory-hard KDF) once a stable WASM build with acceptable bundle size is available. PBKDF2 at 600k iterations is secure today but memory-hard KDFs are harder to attack with GPUs.

---

## Encryption

Algorithm: **AES-GCM-256** via `WebCrypto` (`crypto.subtle`)

- Key: 256-bit derived from master password via PBKDF2-SHA256
- IV: 12 bytes, random per encryption operation
- Additional authenticated data (AAD): vault version byte

The ciphertext and IV are stored in `chrome.storage.local`. The master password and derived key are never stored.

---

## Auto-lock

The vault auto-locks after a configurable idle timeout (default: 15 minutes). On lock, the derived key is zeroed from memory. The user must re-enter the master password to unlock.

---

## Autofill + FoilGuard integration

Before autofilling on any page, FoilVault:

1. Calls `calculateRiskScoreSync(hostname)` from FoilGuard's detection library
2. If score ≥ 40, blocks autofill and shows a warning
3. If score = 0, proceeds with autofill

This is the core differentiator: FoilVault is the only password manager that checks domain safety before filling credentials.

---

## Import/export

**Import (supported):**
- Bitwarden JSON (`.json`)
- Chrome passwords CSV (`.csv`)
- Generic CSV (site, username, password columns)

**Export:**
- Encrypted vault blob (for backup)
- Plaintext CSV (requires vault unlock + confirmation)

---

## Extension architecture

```
┌─────────────────────────────────────┐
│           Browser Extension         │
│                                     │
│  popup.html ──► popup.ts            │
│       │                             │
│       └──► background/index.ts      │
│                │                    │
│                ├── vault.ts         │  PBKDF2 + AES-GCM encrypt/decrypt
│                ├── autofill.ts      │  Content script bridge
│                └── foilguard.ts     │  Risk score check
│                                     │
│  content/autofill.ts                │  Injected into pages
└─────────────────────────────────────┘
```

---

## Dependencies

- `@crxjs/vite-plugin` — Chrome/Firefox MV3 build tooling
- No runtime network calls — fully offline capable
- All cryptographic operations use the browser's native `WebCrypto` (`crypto.subtle`) — zero crypto dependencies

---

## Non-goals

- Cloud sync (by design — local-first)
- Browser history access
- Any telemetry or analytics
