# FoilVault

Privacy-first browser password manager sa ugrađenom zaštitom od phishing autofill-a kroz integraciju sa FoilGuard.

> Deo [Foil](../) security suite-a.

---

## Šta treba da postigne

1. **Pruži lokalni, zero-knowledge password manager** bez obaveznog cloud naloga
2. **Jedinstven differentiator** — pre svakog autofill-a proverava FoilGuard risk score i blokira autofill na sumnjivim domenima
3. **Monetizuje Foil brend** kroz sync tier (cloud ili self-hosted), kada korisnici izgrade poverenje kroz FoilGuard i FoilLab
4. **Otvori enterprise tier** — shared vault, SSO, admin konzola za timove

---

## Ciljna grupa

| Segment | Opis |
|---------|------|
| **Primarni** | Tehnički korisnici koji žele open-source, lokalni PM bez obaveznog cloud naloga (privuceni od Bitwarden, 1Password) |
| **Sekundarni** | Postojeći FoilGuard korisnici — prirodan sledeći korak (već veruju brendu) |
| **B2B (dugoročno)** | Mali timovi i startupi koji žele self-hosted shared vault bez enterprise cenovnika |

---

## Tehnologije

| Deo | Tehnologija | Zašto |
|-----|-------------|-------|
| Extension | **TypeScript** + Manifest v3 | Konzistentno sa FoilGuard, deli infrastrukturu |
| Enkripcija | **Web Crypto API** (AES-GCM 256) | Nativno u browseru, bez eksternih crypto libova |
| KDF | **Argon2id** (via wasm) | State-of-the-art key derivation, otporan na GPU napade |
| Lokalni storage | **IndexedDB** (enkriptovano) | Persistentno, ne odlazi na server |
| Sync backend | **Node.js** + PostgreSQL | Server prima samo enkriptovane blokove, nikad plaintext |
| Auth (sync) | **WebAuthn** + JWT | Passwordless login za sync servis |
| CI/CD | **GitHub Actions** | Automatski security audit (npm audit), build, package |

---

## Sigurnosni model

```
Master Password (nikad ne napušta uređaj)
       ↓ Argon2id (salt per-device)
Encryption Key
       ↓ AES-GCM-256
Enkriptovani vault  ──► IndexedDB (lokalno)
                    ──► Sync server (samo enkriptovani blokovi)
```

Server ne vidi master password, ključ, niti plaintext kredencijale.

---

## Ključna integracija — FoilGuard

Pre autofill-a:
1. FoilVault šalje domen FoilGuard risk API-ju (lokalni poziv, ne eksterni server)
2. Ako `risk_score > 60` → autofill je blokiran, prikazuje se upozorenje sa objašnjenjem
3. Korisnik može eksplicitno da overriduje upozorenje

Ovo je jedinstven feature koji nijedan mainstream PM ne nudi.

---

## Veze sa ostalim Foil projektima

- **FoilGuard** je dependency — risk API mora biti instaliran za phishing autofill zaštitu
- **FoilLab** zajednica = beta testeri za vault i sync implementaciju (tehničan auditorijum)
