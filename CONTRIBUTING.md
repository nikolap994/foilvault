# Contributing to FoilVault

## Running locally

```bash
cd foilvault
npm install
npm run dev       # watch build → dist/
```

Load the extension: open `chrome://extensions`, enable Developer mode, click "Load unpacked", select the `dist/` folder.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the vault format, key derivation, and autofill design before contributing to cryptographic or storage code.

## What to contribute

- **Vault library** (`src/lib/vault.ts`) — encryption, key derivation, credential CRUD
- **Popup UI** (`src/popup/`) — credential list, add/edit form, password generator
- **Autofill** (`src/content/autofill.ts`) — form detection and fill logic
- **Import parsers** (`src/lib/import.ts`) — Bitwarden, 1Password, LastPass CSV
- **TOTP** (`src/lib/totp.ts`) — one-time password generation
- **Breach detection** (`src/lib/hibp.ts`) — k-anonymity Have I Been Pwned integration

## Security contributions

If you find a vulnerability, please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

All cryptographic changes require a description of the threat model impact in the PR.

## Submitting changes

1. Fork the repo and create a branch from `main`.
2. Run `npm run type-check` before submitting.
3. Open a pull request with a clear description of what changed and the security reasoning behind it.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
