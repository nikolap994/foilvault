import "./modulepreload-polyfill-DaKOjhqt.js";
import { e as exportEncrypted, g as getCredentials, a as importEncrypted, b as addCredential, l as logAuditEvent, d as clearAuditLog, f as getAuditLog, h as formatAuditEvent } from "./vault-XO-0w6qj.js";
import { m as measureStrength, e as el, r as replace, c as checkPasswordBreach } from "./dom-Ooi5XjY4.js";
const DEFAULTS = {
  autolockMinutes: 5,
  clipboardClearSeconds: 30,
  hibpEnabled: true,
  expiryWarningsEnabled: true,
  autofillEnabled: true,
  genLength: 20,
  genUpper: true,
  genLower: true,
  genDigits: true,
  genSymbols: true,
  genExcludeAmbiguous: false
};
async function loadOptions() {
  const stored = await chrome.storage.local.get("foilvault_options");
  return { ...DEFAULTS, ...stored.foilvault_options ?? {} };
}
async function saveOptions(opts) {
  await chrome.storage.local.set({ foilvault_options: opts });
}
function collectForm() {
  return {
    autolockMinutes: parseInt(document.getElementById("autolock-select").value, 10),
    clipboardClearSeconds: parseInt(document.getElementById("clipboard-select").value, 10),
    hibpEnabled: document.getElementById("hibp-toggle").checked,
    expiryWarningsEnabled: document.getElementById("expiry-toggle").checked,
    autofillEnabled: document.getElementById("autofill-toggle").checked,
    genLength: parseInt(document.getElementById("gen-length").value, 10),
    genUpper: document.getElementById("gen-upper").checked,
    genLower: document.getElementById("gen-lower").checked,
    genDigits: document.getElementById("gen-digits").checked,
    genSymbols: document.getElementById("gen-symbols").checked,
    genExcludeAmbiguous: document.getElementById("gen-ambiguous").checked
  };
}
function applyToForm(opts) {
  document.getElementById("autolock-select").value = String(opts.autolockMinutes);
  document.getElementById("clipboard-select").value = String(opts.clipboardClearSeconds);
  document.getElementById("hibp-toggle").checked = opts.hibpEnabled;
  document.getElementById("expiry-toggle").checked = opts.expiryWarningsEnabled;
  document.getElementById("autofill-toggle").checked = opts.autofillEnabled;
  document.getElementById("gen-length").value = String(opts.genLength);
  document.getElementById("gen-length-val").textContent = String(opts.genLength);
  document.getElementById("gen-upper").checked = opts.genUpper;
  document.getElementById("gen-lower").checked = opts.genLower;
  document.getElementById("gen-digits").checked = opts.genDigits;
  document.getElementById("gen-symbols").checked = opts.genSymbols;
  document.getElementById("gen-ambiguous").checked = opts.genExcludeAmbiguous;
}
function showStatus(msg, isError = false) {
  const el2 = document.getElementById("save-status");
  el2.textContent = msg;
  el2.className = "save-status" + (isError ? " error" : "");
  setTimeout(() => {
    el2.textContent = "";
  }, 2500);
}
document.addEventListener("DOMContentLoaded", async () => {
  const icon = document.getElementById("logo-icon");
  icon.src = chrome.runtime.getURL("icons/foilvault-32.png");
  const opts = await loadOptions();
  applyToForm(opts);
  document.getElementById("gen-length").addEventListener("input", (e) => {
    const val = e.target.value;
    document.getElementById("gen-length-val").textContent = val;
  });
  document.getElementById("btn-save").addEventListener("click", async () => {
    try {
      await saveOptions(collectForm());
      showStatus("Settings saved");
    } catch {
      showStatus("Failed to save", true);
    }
  });
  const overlay = document.getElementById("confirm-dialog");
  const btnClear = document.getElementById("btn-clear-vault");
  const btnCancel = document.getElementById("confirm-cancel");
  const btnConfirm = document.getElementById("confirm-ok");
  btnClear.addEventListener("click", () => overlay.classList.remove("hidden"));
  btnCancel.addEventListener("click", () => overlay.classList.add("hidden"));
  btnConfirm.addEventListener("click", async () => {
    await chrome.storage.local.clear();
    overlay.classList.add("hidden");
    showStatus("Vault cleared");
  });
  const exportPwInput = document.getElementById("export-password");
  const exportStatus = document.getElementById("export-status");
  document.getElementById("btn-export-enc").addEventListener("click", async () => {
    const pw = exportPwInput.value.trim();
    if (!pw) {
      exportStatus.textContent = "Enter a backup password first.";
      exportStatus.className = "export-status err";
      return;
    }
    try {
      const json = await exportEncrypted(pw);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const date = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
      a.href = url;
      a.download = `foilvault-${date}.foilvault`;
      a.click();
      URL.revokeObjectURL(url);
      exportPwInput.value = "";
      exportStatus.textContent = "Backup downloaded.";
      exportStatus.className = "export-status ok";
      setTimeout(() => {
        exportStatus.textContent = "";
      }, 3e3);
    } catch {
      exportStatus.textContent = "Export failed — vault may be locked.";
      exportStatus.className = "export-status err";
    }
  });
  document.getElementById("btn-health-check").addEventListener("click", async () => {
    const btn = document.getElementById("btn-health-check");
    const statusEl = document.getElementById("health-status");
    const resultsEl = document.getElementById("health-results");
    btn.disabled = true;
    statusEl.textContent = "Scanning vault…";
    statusEl.className = "export-status";
    resultsEl.classList.add("hidden");
    try {
      const creds = await getCredentials();
      const logins = creds.filter((c) => c.type !== "note" && c.password);
      const now = Date.now();
      const weak = logins.filter((c) => measureStrength(c.password).score < 2);
      const byPw = /* @__PURE__ */ new Map();
      for (const c of logins) {
        const g = byPw.get(c.password) ?? [];
        g.push(c);
        byPw.set(c.password, g);
      }
      const reusedGroups = [...byPw.values()].filter((g) => g.length > 1);
      const expired = creds.filter((c) => c.expiresAt && c.expiresAt <= now);
      const ninetyDaysMs = 90 * 24 * 60 * 60 * 1e3;
      const old = logins.filter((c) => now - c.updatedAt >= ninetyDaysMs && !c.expiresAt);
      const total = weak.length + reusedGroups.length + expired.length + old.length;
      statusEl.textContent = total === 0 ? "✓ Vault looks healthy — no issues found." : `⚠ ${total} issue${total !== 1 ? "s" : ""} found.`;
      statusEl.className = `export-status ${total > 0 ? "err" : "ok"}`;
      const setBadge = (id, n) => {
        const el2 = document.getElementById(id);
        el2.textContent = String(n);
        el2.className = `health-badge ${n > 0 ? "health-badge-warn" : "health-badge-ok"}`;
      };
      setBadge("health-weak-count", weak.length);
      setBadge("health-reused-count", reusedGroups.length);
      setBadge("health-expired-count", expired.length);
      setBadge("health-old-count", old.length);
      const row = (site, user, extra, extraColor) => el("div", { className: "health-item" }, [
        el("span", { className: "health-site", textContent: site }),
        el("span", { className: "health-user", textContent: user }),
        el("span", { className: "health-score", textContent: extra, ...extraColor ? { style: `color:${extraColor}` } : {} })
      ]);
      const empty = (msg) => el("p", { className: "health-empty", textContent: msg });
      replace(
        document.getElementById("health-weak-list"),
        ...weak.length === 0 ? [empty("All passwords are strong.")] : weak.map((c) => row(c.site, c.username, measureStrength(c.password).label))
      );
      replace(
        document.getElementById("health-reused-list"),
        ...reusedGroups.length === 0 ? [empty("No passwords are reused.")] : reusedGroups.map((g) => el("div", { className: "health-reuse-group" }, g.map((c) => row(c.site, c.username, ""))))
      );
      replace(
        document.getElementById("health-expired-list"),
        ...expired.length === 0 ? [empty("No expired passwords.")] : expired.map((c) => row(c.site, c.username, new Date(c.expiresAt).toLocaleDateString(), "#ef4444"))
      );
      replace(
        document.getElementById("health-old-list"),
        ...old.length === 0 ? [empty("All passwords updated recently.")] : old.map((c) => {
          const days = Math.floor((now - c.updatedAt) / (24 * 60 * 60 * 1e3));
          return row(c.site, c.username, `${days}d ago`, "#f59e0b");
        })
      );
      resultsEl.classList.remove("hidden");
    } catch {
      statusEl.textContent = "Failed — vault may be locked.";
      statusEl.className = "export-status err";
    }
    btn.disabled = false;
  });
  const btnAuditVault = document.getElementById("btn-audit-vault");
  const auditVaultProgress = document.getElementById("audit-vault-progress");
  const auditVaultResults = document.getElementById("audit-vault-results");
  btnAuditVault.addEventListener("click", async () => {
    btnAuditVault.disabled = true;
    auditVaultResults.classList.add("hidden");
    auditVaultProgress.textContent = "Loading credentials…";
    auditVaultProgress.className = "export-status";
    try {
      const creds = await getCredentials();
      const targets = creds.filter((c) => c.type !== "note" && c.password);
      if (targets.length === 0) {
        auditVaultProgress.textContent = "No passwords to check.";
        btnAuditVault.disabled = false;
        return;
      }
      const results = [];
      for (let i = 0; i < targets.length; i++) {
        const c = targets[i];
        auditVaultProgress.textContent = `Checking ${i + 1} of ${targets.length}…`;
        try {
          const r = await checkPasswordBreach(c.password);
          results.push({ site: c.site, username: c.username, ...r });
        } catch {
          results.push({ site: c.site, username: c.username, breached: false, count: 0, err: true });
        }
      }
      const breached = results.filter((r) => r.breached);
      auditVaultProgress.textContent = breached.length === 0 ? `✓ All ${targets.length} passwords are clean.` : `⚠ ${breached.length} of ${targets.length} passwords found in known breaches.`;
      auditVaultProgress.className = `export-status ${breached.length > 0 ? "err" : "ok"}`;
      replace(auditVaultResults, ...results.map((r) => {
        const statusStyle = r.err ? "color:#64748b" : r.breached ? "color:#ef4444" : "color:#41d07f";
        const statusText = r.err ? "check failed" : r.breached ? `⚠ ${r.count.toLocaleString()} breaches` : "✓ clean";
        return el("div", { className: "audit-entry" }, [
          el("span", { className: "audit-event", textContent: r.site }),
          el("span", { className: "audit-site", textContent: r.username }),
          el("span", { className: "audit-time", style: statusStyle, textContent: statusText })
        ]);
      }));
      auditVaultResults.classList.remove("hidden");
    } catch {
      auditVaultProgress.textContent = "Failed — vault may be locked.";
      auditVaultProgress.className = "export-status err";
    }
    btnAuditVault.disabled = false;
  });
  const importEncPwInput = document.getElementById("import-enc-password");
  const importEncFileInput = document.getElementById("import-enc-file");
  const importEncFilename = document.getElementById("import-enc-filename");
  const importEncStatus = document.getElementById("import-enc-status");
  document.getElementById("btn-import-enc-pick").addEventListener("click", () => importEncFileInput.click());
  importEncFileInput.addEventListener("change", () => {
    var _a, _b;
    importEncFilename.textContent = ((_b = (_a = importEncFileInput.files) == null ? void 0 : _a[0]) == null ? void 0 : _b.name) ?? "";
  });
  document.getElementById("btn-import-enc").addEventListener("click", async () => {
    var _a;
    const file = (_a = importEncFileInput.files) == null ? void 0 : _a[0];
    const pw = importEncPwInput.value.trim();
    if (!file) {
      importEncStatus.textContent = "Choose a .foilvault file first.";
      importEncStatus.className = "export-status err";
      return;
    }
    if (!pw) {
      importEncStatus.textContent = "Enter the backup password.";
      importEncStatus.className = "export-status err";
      return;
    }
    try {
      const text = await file.text();
      const creds = await importEncrypted(text, pw);
      if (!confirm(`Import ${creds.length} credential${creds.length !== 1 ? "s" : ""} into your vault?`)) return;
      for (const c of creds) await addCredential(c);
      await logAuditEvent("vault_import");
      importEncPwInput.value = "";
      importEncFileInput.value = "";
      importEncFilename.textContent = "";
      importEncStatus.textContent = `✓ Imported ${creds.length} credentials.`;
      importEncStatus.className = "export-status ok";
      setTimeout(() => {
        importEncStatus.textContent = "";
      }, 4e3);
    } catch {
      importEncStatus.textContent = "Failed — wrong password or invalid file.";
      importEncStatus.className = "export-status err";
    }
  });
  async function renderAuditLog() {
    const container = document.getElementById("audit-log");
    const entries = await getAuditLog();
    if (entries.length === 0) {
      replace(container, el("p", { className: "audit-empty", textContent: "No events recorded yet." }));
      return;
    }
    replace(container, ...entries.slice(0, 100).map((e) => {
      const time = new Date(e.ts).toLocaleString(void 0, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      return el("div", { className: "audit-entry" }, [
        el("span", { className: "audit-event", textContent: formatAuditEvent(e.event) }),
        e.site ? el("span", { className: "audit-site", textContent: e.site }) : el("span"),
        el("span", { className: "audit-time", textContent: time })
      ]);
    }));
  }
  await renderAuditLog();
  document.getElementById("btn-clear-log").addEventListener("click", async () => {
    await clearAuditLog();
    await renderAuditLog();
  });
});
//# sourceMappingURL=options-BWI2PFaO.js.map
