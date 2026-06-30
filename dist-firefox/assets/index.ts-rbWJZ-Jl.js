import { c as clearSessionKey, i as isVaultUnlocked, g as getCredentials, l as logAuditEvent } from "./vault-XO-0w6qj.js";
const DEFAULT_AUTOLOCK_MINUTES = 5;
async function getAutolockSeconds() {
  var _a;
  const stored = await chrome.storage.local.get("foilvault_options");
  const mins = ((_a = stored.foilvault_options) == null ? void 0 : _a.autolockMinutes) ?? DEFAULT_AUTOLOCK_MINUTES;
  return mins === 0 ? 0 : mins * 60;
}
async function applyAutolock() {
  const secs = await getAutolockSeconds();
  if (secs === 0) return;
  chrome.idle.setDetectionInterval(secs);
}
async function updateBadge() {
  const unlocked = await isVaultUnlocked();
  if (unlocked) {
    await chrome.action.setBadgeText({ text: "" });
  } else {
    await chrome.action.setBadgeText({ text: "●" });
    await chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  }
}
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("src/onboarding/onboarding.html") });
  }
  chrome.contextMenus.create({
    id: "foilvault-fill",
    title: "🔒 Fill with FoilVault",
    contexts: ["editable"]
  });
  updateBadge();
});
chrome.runtime.onStartup.addListener(() => {
  applyAutolock();
  updateBadge();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.foilvault_options) {
    applyAutolock();
  }
  if (area === "session" && "foilvault_session_key" in changes) {
    updateBadge();
  }
});
applyAutolock();
updateBadge();
chrome.idle.onStateChanged.addListener(async (state) => {
  const secs = await getAutolockSeconds();
  if (secs === 0) return;
  if (state === "idle" || state === "locked") {
    await clearSessionKey();
  }
});
const COMPOUND_TLDS = /* @__PURE__ */ new Set([
  "co.uk",
  "co.nz",
  "co.jp",
  "co.za",
  "co.in",
  "co.kr",
  "co.id",
  "co.il",
  "com.au",
  "com.br",
  "com.mx",
  "com.sg",
  "com.ar",
  "com.tr",
  "com.pe",
  "org.uk",
  "net.uk",
  "me.uk",
  "ltd.uk",
  "plc.uk",
  "gov.uk",
  "gov.au",
  "gov.br",
  "gov.in"
]);
function etld1(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, "");
  const parts = h.split(".");
  if (parts.length >= 3) {
    const candidate = parts.slice(-2).join(".");
    if (COMPOUND_TLDS.has(candidate)) return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}
function siteEtld1(site) {
  const stripped = site.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
  return etld1(stripped);
}
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "foilvault-fill" || !(tab == null ? void 0 : tab.id)) return;
  const unlocked = await isVaultUnlocked();
  if (!unlocked) return;
  let hostname = "";
  try {
    hostname = new URL(tab.url ?? "").hostname;
  } catch {
    return;
  }
  const all = await getCredentials();
  const pageEtld = etld1(hostname);
  const matches = all.filter((c) => c.type === "login" && siteEtld1(c.site) === pageEtld);
  chrome.tabs.sendMessage(tab.id, {
    type: "foilvault-context-fill",
    credentials: matches.map((c) => ({ site: c.site, username: c.username, password: c.password }))
  });
});
chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  if ((msg == null ? void 0 : msg.type) !== "autofill-get-credentials") return false;
  const hostname = msg.hostname ?? "";
  (async () => {
    const unlocked = await isVaultUnlocked();
    if (!unlocked) {
      respond({ credentials: [] });
      return;
    }
    const pageEtld1 = etld1(hostname);
    const all = await getCredentials();
    const matches = all.filter((c) => siteEtld1(c.site) === pageEtld1);
    if (matches.length > 0) await logAuditEvent("autofill", hostname);
    respond({ credentials: matches });
  })();
  return true;
});
//# sourceMappingURL=index.ts-rbWJZ-Jl.js.map
