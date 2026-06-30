const STORAGE_KEY = "foilvault_audit_log";
const MAX_ENTRIES = 300;
async function logAuditEvent(event, site) {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const log = stored[STORAGE_KEY] ?? [];
  log.push({ event, ts: Date.now(), ...site ? { site } : {} });
  if (log.length > MAX_ENTRIES) log.splice(0, log.length - MAX_ENTRIES);
  await chrome.storage.local.set({ [STORAGE_KEY]: log });
}
async function getAuditLog() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const log = stored[STORAGE_KEY] ?? [];
  return [...log].reverse();
}
async function clearAuditLog() {
  await chrome.storage.local.remove(STORAGE_KEY);
}
function formatAuditEvent(event) {
  const labels = {
    vault_unlock: "Vault unlocked",
    vault_lock: "Vault locked",
    vault_create: "Vault created",
    autofill: "Autofill used",
    credential_copy: "Password copied",
    credential_view: "Credential viewed",
    credential_add: "Credential added",
    credential_delete: "Credential deleted",
    hibp_check: "Breach check run",
    vault_export: "Vault exported",
    vault_import: "Vault imported"
  };
  return labels[event] ?? event;
}
const SESSION_KEY = "foilvault_session_key";
const SALT_KEY = "foilvault_salt";
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer, iterations: 6e5, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}
async function exportKeyB64(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}
async function importKeyB64(b64) {
  const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptString(key, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
  const combined = new Uint8Array(12 + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), 12);
  return btoa(String.fromCharCode(...combined));
}
async function decryptString(key, b64) {
  const combined = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const cipher = combined.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(plain);
}
async function getOrCreateSalt() {
  const stored = await chrome.storage.local.get(SALT_KEY);
  if (stored[SALT_KEY]) {
    return Uint8Array.from(atob(stored[SALT_KEY]), (c) => c.charCodeAt(0));
  }
  const salt = crypto.getRandomValues(new Uint8Array(32));
  await chrome.storage.local.set({ [SALT_KEY]: btoa(String.fromCharCode(...salt)) });
  return salt;
}
async function getSessionKey() {
  const s = await chrome.storage.session.get(SESSION_KEY);
  if (!s[SESSION_KEY]) return null;
  try {
    return await importKeyB64(s[SESSION_KEY]);
  } catch {
    return null;
  }
}
async function setSessionKey(key) {
  await chrome.storage.session.set({ [SESSION_KEY]: await exportKeyB64(key) });
}
async function clearSessionKey() {
  await chrome.storage.session.remove(SESSION_KEY);
}
async function readVaultBlob() {
  const s = await chrome.storage.local.get("foilvault_blob");
  return s["foilvault_blob"] ?? null;
}
async function writeVaultBlob(blob) {
  await chrome.storage.local.set({ foilvault_blob: blob });
}
async function isVaultInitialized() {
  return await readVaultBlob() !== null;
}
async function isVaultUnlocked() {
  return await getSessionKey() !== null;
}
async function initVault(password) {
  const salt = await getOrCreateSalt();
  const key = await deriveKey(password, salt);
  const empty = { credentials: [], version: 1 };
  const blob = await encryptString(key, JSON.stringify(empty));
  await writeVaultBlob(blob);
  await setSessionKey(key);
  await logAuditEvent("vault_create");
}
async function unlockVault(password) {
  const blob = await readVaultBlob();
  if (!blob) return false;
  const salt = await getOrCreateSalt();
  const key = await deriveKey(password, salt);
  try {
    await decryptString(key, blob);
    await setSessionKey(key);
    await logAuditEvent("vault_unlock");
    return true;
  } catch {
    return false;
  }
}
async function lockVault() {
  await logAuditEvent("vault_lock");
  await clearSessionKey();
}
async function readData() {
  const key = await getSessionKey();
  if (!key) throw new Error("vault_locked");
  const blob = await readVaultBlob();
  if (!blob) throw new Error("vault_not_initialized");
  const json = await decryptString(key, blob);
  return JSON.parse(json);
}
async function writeData(data) {
  const key = await getSessionKey();
  if (!key) throw new Error("vault_locked");
  const blob = await encryptString(key, JSON.stringify(data));
  await writeVaultBlob(blob);
}
async function getCredentials() {
  return (await readData()).credentials;
}
async function getFolders() {
  const data = await readData();
  return [...new Set(data.credentials.map((c) => c.folder).filter((f) => !!f))].sort();
}
async function addCredential(cred) {
  const data = await readData();
  const now = Date.now();
  const full = {
    ...cred,
    id: crypto.randomUUID(),
    createdAt: now,
    updatedAt: now
  };
  data.credentials.push(full);
  await writeData(data);
  await logAuditEvent("credential_add", cred.site);
  return full;
}
async function updateCredential(id, patch) {
  const data = await readData();
  const idx = data.credentials.findIndex((c) => c.id === id);
  if (idx < 0) return;
  const current = data.credentials[idx];
  if (patch.password && patch.password !== current.password) {
    const prev = current.passwordHistory ?? [];
    patch = { ...patch, passwordHistory: [{ password: current.password, changedAt: current.updatedAt }, ...prev].slice(0, 10) };
  }
  data.credentials[idx] = { ...current, ...patch, updatedAt: Date.now() };
  await writeData(data);
}
async function pinCredential(id, pinned) {
  const data = await readData();
  const idx = data.credentials.findIndex((c) => c.id === id);
  if (idx < 0) return;
  data.credentials[idx] = { ...data.credentials[idx], pinned };
  await writeData(data);
}
async function deleteCredential(id) {
  const data = await readData();
  const cred = data.credentials.find((c) => c.id === id);
  data.credentials = data.credentials.filter((c) => c.id !== id);
  await writeData(data);
  await logAuditEvent("credential_delete", cred == null ? void 0 : cred.site);
}
async function exportCredentials(format) {
  await logAuditEvent("vault_export");
  const creds = await getCredentials();
  if (format === "json") return JSON.stringify(creds, null, 2);
  const header = "name,username,password,url,notes,folder,totp\n";
  const rows = creds.map((c) => {
    const esc = (s) => `"${(s ?? "").replace(/"/g, '""')}"`;
    return [esc(c.site), esc(c.username), esc(c.password), "", esc(c.notes), esc(c.folder ?? ""), esc(c.totp ?? "")].join(",");
  });
  return header + rows.join("\n");
}
async function exportEncrypted(password) {
  await logAuditEvent("vault_export");
  const creds = await getCredentials();
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer, iterations: 6e5, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(creds)));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const payload = {
    v: 1,
    kdf: "pbkdf2",
    hash: "SHA-256",
    iterations: 6e5,
    salt: toB64(salt.buffer),
    iv: toB64(iv.buffer),
    data: toB64(cipher)
  };
  return JSON.stringify(payload, null, 2);
}
async function importEncrypted(json, password) {
  const payload = JSON.parse(json);
  if (payload.v !== 1 || payload.kdf !== "pbkdf2") throw new Error("unsupported_format");
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const salt = fromB64(payload.salt);
  const iv = fromB64(payload.iv);
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer, iterations: payload.iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, fromB64(payload.data).buffer);
  return JSON.parse(new TextDecoder().decode(plain));
}
function generatePassword(opts) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  let pool = lower;
  if (opts.upper) pool += upper;
  if (opts.numbers) pool += numbers;
  if (opts.symbols) pool += symbols;
  const arr = new Uint32Array(opts.length);
  crypto.getRandomValues(arr);
  return Array.from(arr, (n) => pool[n % pool.length]).join("");
}
export {
  importEncrypted as a,
  addCredential as b,
  clearSessionKey as c,
  clearAuditLog as d,
  exportEncrypted as e,
  getAuditLog as f,
  getCredentials as g,
  formatAuditEvent as h,
  isVaultUnlocked as i,
  initVault as j,
  lockVault as k,
  logAuditEvent as l,
  getFolders as m,
  exportCredentials as n,
  updateCredential as o,
  pinCredential as p,
  deleteCredential as q,
  generatePassword as r,
  isVaultInitialized as s,
  unlockVault as u
};
//# sourceMappingURL=vault-XO-0w6qj.js.map
