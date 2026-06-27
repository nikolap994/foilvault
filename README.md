# FoilVault

Privacy-first browser password manager with built-in phishing autofill protection via FoilGuard integration.

> Part of the [Foil](../) security suite.

---

## Goals

1. **Provide a local, zero-knowledge password manager** with no mandatory cloud account
2. **Unique differentiator** — checks FoilGuard's risk score before every autofill and blocks credentials on suspicious domains
3. **Monetize the Foil brand** through a sync tier (cloud or self-hosted), once users build trust through FoilGuard and FoilLab
4. **Open an enterprise tier** — shared vault, SSO, admin console for teams

---

## Target audience

| Segment | Description |
|---------|-------------|
| **Primary** | Technical users who want an open-source, local PM with no mandatory cloud account (moving away from Bitwarden, 1Password) |
| **Secondary** | Existing FoilGuard users — a natural next step, already trust the brand |
| **B2B (long-term)** | Small teams and startups who want a self-hosted shared vault without enterprise pricing |

---

## Tech stack

| Layer | Technology | Why |
|-------|------------|-----|
| Extension | **TypeScript** + Manifest v3 | Consistent with FoilGuard, shared infrastructure |
| Encryption | **Web Crypto API** (AES-GCM-256) | Native to the browser, no external crypto libraries |
| KDF | **Argon2id** (via WASM) | State-of-the-art, resistant to GPU and ASIC attacks |
| Local storage | **IndexedDB** (encrypted) | Persistent, never leaves the device |
| Sync backend | **Node.js** + PostgreSQL | Server receives only encrypted blobs, never plaintext |
| Auth (sync) | **WebAuthn** + JWT | Passwordless login for the sync service |
| CI/CD | **GitHub Actions** | npm audit, SAST scan, build, package |

---

## Security model

```
Master Password  (never leaves the device)
       ↓  Argon2id  (m=64MB, t=3, p=4 — OWASP recommended parameters)
Encryption Key  (256-bit)
       ↓  AES-GCM-256  (unique nonce per encrypted record)
Encrypted vault
       ├──► IndexedDB  (local, offline-first)
       └──► Sync server  (encrypted blobs only — server is blind to content)
```

- Server **never** sees the master password, the key, or plaintext credentials
- **Zero-knowledge sync**: the encrypted blob is uploaded opaque — server has no knowledge of its structure
- **Nonce reuse prevention**: every record gets a cryptographically random nonce (CSPRNG)
- **Integrity check**: AEAD (Authenticated Encryption with Associated Data) — detects any vault tampering
- **Memory zeroing**: sensitive variables (master password, key) are cleared from memory immediately after use
- **Auto-lock**: vault locks after X minutes of inactivity, key is erased from memory

---

## Key integration — FoilGuard

Before autofill:
1. FoilVault sends the domain to the FoilGuard risk API (local call, not an external server)
2. If `risk_score > 60` → autofill is blocked, a warning is shown with an explanation
3. The user can explicitly override the warning (conscious decision, logged locally)

This is a feature no mainstream password manager offers.

---

## Integration with other Foil projects

- **FoilGuard** is a dependency — the risk API must be installed for phishing autofill protection
- **FoilLab** community = beta testers for vault and sync implementation (technical audience)
