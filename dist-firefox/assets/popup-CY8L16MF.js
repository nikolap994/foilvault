import "./modulepreload-polyfill-DaKOjhqt.js";
import { j as initVault, u as unlockVault, k as lockVault, g as getCredentials, m as getFolders, p as pinCredential, l as logAuditEvent, n as exportCredentials, o as updateCredential, b as addCredential, q as deleteCredential, r as generatePassword, s as isVaultInitialized, i as isVaultUnlocked } from "./vault-XO-0w6qj.js";
import { m as measureStrength, c as checkPasswordBreach, r as replace, e as el } from "./dom-Ooi5XjY4.js";
function parseCsv(text) {
  const lines = text.replace(/\r\n/g, "\n").split("\n").filter((l) => l.trim());
  if (lines.length < 2) return [];
  const headers = splitCsvLine(lines[0]).map((h) => h.toLowerCase().trim());
  return lines.slice(1).map((line) => {
    const vals = splitCsvLine(line);
    const row = {};
    headers.forEach((h, i) => {
      row[h] = (vals[i] ?? "").trim();
    });
    return row;
  });
}
function splitCsvLine(line) {
  const out = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQ = !inQ;
      }
    } else if (ch === "," && !inQ) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}
function fromBitwarden(text) {
  const rows = parseCsv(text);
  return rows.filter((r) => r["type"] === "login" || !r["type"]).map((r) => ({
    type: "login",
    site: r["name"] || r["login_uri"] || "Unknown",
    username: r["login_username"] || "",
    password: r["login_password"] || "",
    notes: r["notes"] || ""
  })).filter((r) => r.password);
}
function from1Password(text) {
  const rows = parseCsv(text);
  return rows.map((r) => ({
    type: "login",
    site: r["title"] || r["url"] || "Unknown",
    username: r["username"] || "",
    password: r["password"] || "",
    notes: r["notes"] || ""
  })).filter((r) => r.password);
}
function fromLastPass(text) {
  const rows = parseCsv(text);
  return rows.map((r) => ({
    type: "login",
    site: r["name"] || r["url"] || "Unknown",
    username: r["username"] || "",
    password: r["password"] || "",
    notes: r["extra"] || ""
  })).filter((r) => r.password);
}
function fromGeneric(text) {
  const rows = parseCsv(text);
  return rows.map((r) => {
    const site = r["name"] || r["title"] || r["site"] || r["url"] || r["website"] || "Unknown";
    const username = r["username"] || r["email"] || r["user"] || r["login"] || "";
    const password = r["password"] || r["pass"] || r["pwd"] || "";
    const notes = r["notes"] || r["note"] || r["comment"] || r["extra"] || "";
    return { type: "login", site, username, password, notes };
  }).filter((r) => r.password);
}
function detectFormat(text) {
  const firstLine = text.split("\n")[0].toLowerCase();
  if (firstLine.includes("login_uri") || firstLine.includes("login_username")) return "bitwarden";
  if (firstLine.includes("otpauth") || firstLine.includes("title,username,password,url")) return "1password";
  if (firstLine.includes("grouping") || firstLine.includes("fav") && firstLine.includes("totp")) return "lastpass";
  return "generic";
}
function importCredentials(text, format = "auto") {
  const fmt = format === "auto" ? detectFormat(text) : format;
  switch (fmt) {
    case "bitwarden":
      return fromBitwarden(text);
    case "1password":
      return from1Password(text);
    case "lastpass":
      return fromLastPass(text);
    default:
      return fromGeneric(text);
  }
}
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  const s = input.replace(/\s/g, "").replace(/=+$/, "").toUpperCase();
  const bits = [];
  for (const ch of s) {
    const idx = BASE32_CHARS.indexOf(ch);
    if (idx < 0) continue;
    for (let i = 4; i >= 0; i--) bits.push(idx >> i & 1);
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = b << 1 | (bits[i * 8 + j] ?? 0);
    bytes[i] = b;
  }
  return bytes;
}
function uint64ToBytes(n) {
  const buf = new Uint8Array(8);
  let v = Math.floor(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = v & 255;
    v = Math.floor(v / 256);
  }
  return buf;
}
async function generateTOTP(secret, period = 30, digits = 6) {
  const keyBytes = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1e3 / period);
  const msg = uint64ToBytes(counter);
  const key = await crypto.subtle.importKey("raw", keyBytes.buffer, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msg.buffer);
  const hmac = new Uint8Array(sig);
  const offset = hmac[hmac.length - 1] & 15;
  const code = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return String(code % Math.pow(10, digits)).padStart(digits, "0");
}
function secondsRemaining(period = 30) {
  return period - Math.floor(Date.now() / 1e3) % period;
}
function validateBase32Secret(s) {
  return /^[A-Z2-7\s=]+$/i.test(s) && s.replace(/\s/g, "").replace(/=+$/, "").length >= 8;
}
const WORDLIST = `
abbey abide abode abyss acorn actor acute admit adore adult agile agony alarm album alert amaze
amber amble angel ankle annex anvil apple apron ardor arena arson atlas attic audio audit axiom
azure badge baker banjo baron basic beach beard beast bench berry blade blank blast blaze blend
blind bliss block bloom blown blues blunt board boast bonus boost booth brave bread breed brick
broom broth brown brush build bulge bunch burst cabin cache camel cargo carry caste cedar chalk
charm chase chess chest chief chime choir claim clash cling cloak clone cloth cloud coast cobra
coral crane crash crate creek crest crisp cross crown cubic curve cycle dance daunt decay delta
demon depot depth devil drift dunes dusty dairy daisy dandy debut decal decoy derby digit disco
dodge donor doors draft drain drawl dream dried drink drive drums drunk dryer eagle earns earth
elder elite ember emote empty endow enter envy equal erase evade event exact exert exile extra
fable faint fairy false fancy fatal feast fence ferry fewer fifth final flake flame flank flask
fleet flesh flock flood flute forge fresh frost fruit fungi fixed found franc fraud freed frown
froze fumes fuzzy gable gauge gauze ghost gland gleam glide gloss glove glyph grace grade grain
grand grant grasp grave graze greed greet grief grill groan gross grove guard guide guild gusto
habit haiku haste haven hedge heist heron hitch hoard holly honor house hover hyena hazel image
inbox indie inlet input ivory jaunt jewel joust judge juicy jumbo knack label lance larva laser
latch later laugh layer leach ledge legal lemon level light lilac limit liner liver local lodge
logic loose lover lucid lucky lunar lyric magic maker mambo mango manor maple march match mercy
merge might model moody moral mount mouse muddy mural muted myrrh naive naval noble north novel
nudge nymph ocean offer olive orbit order ozone panic pasta patch pearl pedal perch pilot pinch
plain plank plaza plead pluck porch pound power press prime prism probe proof pulse punch purge
query queue quirk quota quote radar rally ranch razor rebel recap reign relay remix renew repay
rider ridge rival river rivet robot rocky rough round royal rugby runes runic salon salsa sandy
sauna savvy scale scant scarf scene scone scoop score scout scrub sedan seize shade shaft shape
sharp shelf shell shirt shock shore shrub sigma since skull slang slash slate slice slide sling
smash smear smell smoke snake snare snoop snore solid sonar south space spark spawn speak speed
spell spend spice spire stare stark start steer stern stick stone storm stout strap study surge
swamp sweep swift swirl syrup table tally talon tango tapir teach tempo tense theft theme thigh
thorn tiara tiger today token tough tower track trail train trait tramp truce truck truly trust
tuber tulip tumor tuner twirl twice twist umbra uncle unite until valor vault verge vigil viral
vista vital vivid vocal voice vouch wagon waist waltz waste watch weary weave wedge weird whale
wheat whelk while witch wispy wrath wreck wrist wrong yacht yield young zebra zesty zones zilch
`.trim().split(/\s+/);
function generatePassphrase(opts) {
  const count = Math.max(3, Math.min(8, opts.wordCount));
  const arr = new Uint32Array(count);
  crypto.getRandomValues(arr);
  const words = Array.from(arr, (n) => {
    const word = WORDLIST[n % WORDLIST.length];
    return opts.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word;
  });
  let phrase = words.join(opts.separator);
  if (opts.appendNumber) {
    const n = new Uint32Array(1);
    crypto.getRandomValues(n);
    phrase += opts.separator + String(n[0] % 100).padStart(2, "0");
  }
  return phrase;
}
function passphraseEntropy(wordCount) {
  return Math.floor(wordCount * Math.log2(WORDLIST.length));
}
const views = {
  loading: "view-loading",
  firstrun: "view-firstrun",
  locked: "view-locked",
  unlocked: "view-unlocked",
  add: "view-add",
  gen: "view-gen",
  import: "view-import"
};
let prevView = "unlocked";
function show(v) {
  for (const [key, id] of Object.entries(views)) {
    document.getElementById(id).classList.toggle("hidden", key !== v);
  }
  const ha = document.getElementById("header-actions");
  ha.style.display = v === "unlocked" || v === "add" || v === "import" ? "flex" : "none";
}
const $ = (id) => document.getElementById(id);
const $i = (id) => document.getElementById(id);
const $b = (id) => document.getElementById(id);
const $s = (id) => document.getElementById(id);
const btnCreate = $b("btn-create"), newMp = $i("new-mp"), newMp2 = $i("new-mp2");
const firstrunStatus = $("firstrun-status");
const mpInput = $i("mp-input"), btnUnlock = $b("btn-unlock"), lockedStatus = $("locked-status");
const searchInput = $i("search-input"), credList = $("cred-list"), credEmpty = $("cred-empty");
const btnAdd = $b("btn-add"), btnLock = $b("btn-lock"), btnGen = $b("btn-gen");
const folderFilter = $s("folder-filter"), sortSelect = $s("sort-select");
const expiryBanner = $("expiry-banner"), expiryBannerText = $("expiry-banner-text");
const btnCancel = $b("btn-cancel"), btnSave = $b("btn-save"), btnDelete = $b("btn-delete");
const formTitle = $("form-title"), addStatus = $("add-status");
const fSite = $i("f-site"), fUser = $i("f-user"), fPass = $i("f-pass");
const fNotes = document.getElementById("f-notes");
const fFolder = $i("f-folder"), fTotp = $i("f-totp"), fExpiry = $i("f-expiry");
const btnShowPass = $b("btn-show-pass"), btnFillGen = $b("btn-fill-gen");
const btnBreachCheck = $b("btn-breach-check"), breachResult = $("breach-result");
const pwStrengthWrap = $("pw-strength-wrap"), pwStrengthBar = $("pw-strength-bar");
const pwStrengthLabel = $("pw-strength-label"), pwStrengthEntropy = $("pw-strength-entropy");
const totpPreview = $("totp-preview"), loginFields = $("login-fields");
const cardFields = $("card-fields"), identityFields = $("identity-fields");
const typeBtnLogin = $b("type-login"), typeBtnNote = $b("type-note");
const typeBtnCard = $b("type-card"), typeBtnId = $b("type-id");
const folderDatalist = $("folder-list");
const fCardHolder = $i("f-card-holder"), fCardNumber = $i("f-card-number");
const fCardExpiry = $i("f-card-expiry"), fCardCvv = $i("f-card-cvv");
const fIdFirst = $i("f-id-first"), fIdLast = $i("f-id-last");
const fIdEmail = $i("f-id-email"), fIdPhone = $i("f-id-phone");
const fIdAddress = $i("f-id-address"), fIdDob = $i("f-id-dob");
const btnImport = $b("btn-import"), btnImportBack = $b("btn-import-back");
const importFileInput = $i("import-file-input"), fileDropZone = $("file-drop-zone");
const importFileName = $("import-file-name"), importPreview = $("import-preview");
const importStatus = $("import-status"), btnImportConfirm = $b("btn-import-confirm");
const btnExport = $b("btn-export");
const genOutput = $("gen-output"), genLen = $i("gen-len"), genUpper = $i("gen-upper");
const genNums = $i("gen-nums"), genSyms = $i("gen-syms"), btnRegen = $b("btn-regen");
const btnCopy = $b("btn-copy"), copyStatus = $("copy-status"), btnGenBack = $b("btn-gen-back");
const genStrengthBar = $("gen-strength-bar"), genStrengthLabel = $("gen-strength-label");
const genStrengthWrap = $("gen-strength-wrap"), genEntropyLabel = $("gen-entropy-label");
const genPwOpts = $("gen-pw-opts"), genPpOpts = $("gen-pp-opts");
const genTabPw = $b("gen-tab-pw"), genTabPp = $b("gen-tab-pp");
const ppWords = $i("pp-words"), ppSep = $s("pp-sep");
const ppCap = $i("pp-cap"), ppNum = $i("pp-num");
let genMode = "pw";
let allCreds = [];
let editingId = null;
let credType = "login";
let totpInterval = null;
const OPTION_DEFAULTS = {
  clipboardClearSeconds: 30,
  hibpEnabled: true,
  expiryWarningsEnabled: true,
  genLength: 20,
  genUpper: true,
  genDigits: true,
  genSymbols: true
};
let cachedOptions = { ...OPTION_DEFAULTS };
let clipboardClearTimer = null;
async function loadCachedOptions() {
  const stored = await chrome.storage.local.get("foilvault_options");
  cachedOptions = { ...OPTION_DEFAULTS, ...stored.foilvault_options ?? {} };
  genLen.value = String(cachedOptions.genLength);
  genUpper.checked = cachedOptions.genUpper;
  genNums.checked = cachedOptions.genDigits;
  genSyms.checked = cachedOptions.genSymbols;
}
async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
  if (clipboardClearTimer !== null) {
    clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
  }
  const secs = cachedOptions.clipboardClearSeconds;
  if (secs <= 0) return;
  clipboardClearTimer = setTimeout(async () => {
    clipboardClearTimer = null;
    try {
      await navigator.clipboard.writeText("");
    } catch {
    }
  }, secs * 1e3);
}
async function init() {
  show("loading");
  await loadCachedOptions();
  if (!await isVaultInitialized()) {
    show("firstrun");
    setupStrengthOnInput(newMp, "new-mp-strength", "new-mp-bar", "new-mp-label");
    return;
  }
  if (await isVaultUnlocked()) {
    await loadList();
  } else {
    show("locked");
    mpInput.focus();
  }
}
function setupStrengthOnInput(input, wrapId, barId, labelId) {
  const wrap = $(wrapId), bar = $(barId), label = $(labelId);
  input.addEventListener("input", () => {
    const r = measureStrength(input.value);
    if (!input.value) {
      wrap.classList.add("hidden");
      return;
    }
    wrap.classList.remove("hidden");
    bar.style.background = r.color;
    bar.style.width = `${r.score / 4 * 100}%`;
    label.textContent = r.label;
    label.style.color = r.color;
  });
}
btnCreate.addEventListener("click", async () => {
  const pw = newMp.value, pw2 = newMp2.value;
  if (!pw || pw.length < 8) {
    firstrunStatus.textContent = "Password must be at least 8 characters.";
    return;
  }
  if (pw !== pw2) {
    firstrunStatus.textContent = "Passwords do not match.";
    return;
  }
  firstrunStatus.textContent = "";
  btnCreate.disabled = true;
  btnCreate.textContent = "Creating…";
  try {
    await initVault(pw);
    await loadList();
  } catch {
    firstrunStatus.textContent = "Failed to create vault.";
    btnCreate.disabled = false;
    btnCreate.textContent = "Create vault →";
  }
});
newMp2.addEventListener("keydown", (e) => {
  if (e.key === "Enter") btnCreate.click();
});
btnUnlock.addEventListener("click", async () => {
  const pw = mpInput.value;
  if (!pw) return;
  btnUnlock.disabled = true;
  btnUnlock.textContent = "Unlocking…";
  const ok = await unlockVault(pw);
  if (ok) {
    mpInput.value = "";
    lockedStatus.textContent = "";
    await loadList();
  } else {
    lockedStatus.textContent = "Incorrect password.";
    btnUnlock.disabled = false;
    btnUnlock.textContent = "Unlock vault →";
    mpInput.select();
  }
});
mpInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") btnUnlock.click();
});
btnLock.addEventListener("click", async () => {
  await lockVault();
  show("locked");
  mpInput.value = "";
  mpInput.focus();
});
async function loadList() {
  allCreds = await getCredentials();
  await refreshFolderUI();
  renderList(allCreds);
  checkExpiry();
  show("unlocked");
}
async function refreshFolderUI() {
  const folders = await getFolders();
  folderDatalist.innerHTML = "";
  folders.forEach((f) => {
    const o = document.createElement("option");
    o.value = f;
    folderDatalist.appendChild(o);
  });
  const cur = folderFilter.value;
  folderFilter.innerHTML = '<option value="">All folders</option>';
  folders.forEach((f) => {
    const o = document.createElement("option");
    o.value = f;
    o.textContent = f;
    folderFilter.appendChild(o);
  });
  folderFilter.value = folders.includes(cur) ? cur : "";
  folderFilter.classList.toggle("hidden", folders.length === 0);
}
function checkExpiry() {
  if (!cachedOptions.expiryWarningsEnabled) {
    expiryBanner.classList.add("hidden");
    return;
  }
  const now = Date.now();
  const expiring = allCreds.filter((c) => c.expiresAt && c.expiresAt <= now + 7 * 864e5);
  if (expiring.length === 0) {
    expiryBanner.classList.add("hidden");
    return;
  }
  const expired = expiring.filter((c) => c.expiresAt <= now);
  const soon = expiring.filter((c) => c.expiresAt > now);
  const parts = [];
  if (expired.length) parts.push(`${expired.length} password${expired.length > 1 ? "s" : ""} expired`);
  if (soon.length) parts.push(`${soon.length} expiring soon`);
  expiryBannerText.textContent = "⚠ " + parts.join(" · ");
  expiryBanner.classList.remove("hidden");
}
function sortedCreds(creds) {
  const order = sortSelect.value;
  return [...creds].sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    if (order === "added") return b.createdAt - a.createdAt;
    if (order === "updated") return b.updatedAt - a.updatedAt;
    return a.site.localeCompare(b.site);
  });
}
function renderList(creds) {
  credList.innerHTML = "";
  credEmpty.classList.toggle("hidden", creds.length > 0);
  const now = Date.now();
  for (const c of sortedCreds(creds)) {
    const li = document.createElement("li");
    li.className = "cred-item";
    if (c.expiresAt && c.expiresAt <= now) li.classList.add("cred-expired");
    const favicon = document.createElement("div");
    favicon.className = "cred-favicon";
    favicon.textContent = c.type === "note" ? "📝" : c.type === "card" ? "💳" : c.type === "identity" ? "🪪" : c.site.charAt(0).toUpperCase();
    li.appendChild(favicon);
    const info = document.createElement("div");
    info.className = "cred-info";
    const site = document.createElement("div");
    site.className = "cred-site";
    site.textContent = c.site;
    const sub = document.createElement("div");
    sub.className = "cred-user";
    if (c.type === "note") sub.textContent = "Secure note";
    else if (c.type === "card") sub.textContent = c.cardNumber ? `•••• ${c.cardNumber.slice(-4)}` : "Credit / debit card";
    else if (c.type === "identity") sub.textContent = [c.idFirstName, c.idLastName].filter(Boolean).join(" ") || "Identity";
    else sub.textContent = c.username + (c.folder ? ` · ${c.folder}` : "");
    info.appendChild(site);
    info.appendChild(sub);
    li.appendChild(info);
    const pinBtn = document.createElement("button");
    pinBtn.className = `cred-copy${c.pinned ? " cred-pin-active" : ""}`;
    pinBtn.title = c.pinned ? "Unpin" : "Pin to top";
    pinBtn.textContent = "📌";
    pinBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await pinCredential(c.id, !c.pinned);
      await loadList();
    });
    li.appendChild(pinBtn);
    if (c.type !== "note") {
      if (c.username) {
        const copyUser = document.createElement("button");
        copyUser.className = "cred-copy";
        copyUser.title = "Copy username";
        copyUser.textContent = "👤";
        copyUser.addEventListener("click", async (e) => {
          e.stopPropagation();
          await navigator.clipboard.writeText(c.username);
          copyUser.textContent = "✓";
          setTimeout(() => {
            copyUser.textContent = "👤";
          }, 1500);
        });
        li.appendChild(copyUser);
      }
      const copyPw = document.createElement("button");
      copyPw.className = "cred-copy";
      copyPw.title = "Copy password";
      copyPw.textContent = "📋";
      copyPw.addEventListener("click", async (e) => {
        e.stopPropagation();
        await copyToClipboard(c.password);
        await logAuditEvent("credential_copy", c.site);
        copyPw.textContent = "✓";
        setTimeout(() => {
          copyPw.textContent = "📋";
        }, 1500);
      });
      li.appendChild(copyPw);
      if (c.totp && validateBase32Secret(c.totp)) {
        const copyTotp = document.createElement("button");
        copyTotp.className = "cred-copy";
        copyTotp.title = "Copy 2FA code";
        copyTotp.textContent = "🔑";
        copyTotp.addEventListener("click", async (e) => {
          e.stopPropagation();
          try {
            const code = await generateTOTP(c.totp);
            await copyToClipboard(code);
            copyTotp.textContent = "✓";
            setTimeout(() => {
              copyTotp.textContent = "🔑";
            }, 2e3);
          } catch {
            copyTotp.textContent = "✗";
            setTimeout(() => {
              copyTotp.textContent = "🔑";
            }, 1500);
          }
        });
        li.appendChild(copyTotp);
      }
    }
    li.addEventListener("click", async () => {
      await logAuditEvent("credential_view", c.site);
      openEdit(c);
    });
    credList.appendChild(li);
  }
}
function applyFilters() {
  const q = searchInput.value.toLowerCase();
  const folder = folderFilter.value;
  renderList(allCreds.filter(
    (c) => (c.site.toLowerCase().includes(q) || c.username.toLowerCase().includes(q) || c.notes.toLowerCase().includes(q)) && (!folder || c.folder === folder)
  ));
}
searchInput.addEventListener("input", applyFilters);
folderFilter.addEventListener("change", applyFilters);
sortSelect.addEventListener("change", applyFilters);
btnExport.addEventListener("click", async () => {
  const fmt = confirm("Export as JSON? (Cancel = CSV)") ? "json" : "csv";
  const content = await exportCredentials(fmt);
  const mime = fmt === "json" ? "application/json" : "text/csv";
  const dataUri = `data:${mime};charset=utf-8,${encodeURIComponent(content)}`;
  const a = document.createElement("a");
  a.href = dataUri;
  a.download = `foilvault-export-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.${fmt}`;
  a.click();
});
function setCredType(t) {
  credType = t;
  typeBtnLogin.classList.toggle("active", t === "login");
  typeBtnCard.classList.toggle("active", t === "card");
  typeBtnId.classList.toggle("active", t === "identity");
  typeBtnNote.classList.toggle("active", t === "note");
  loginFields.classList.toggle("hidden", t !== "login");
  cardFields.classList.toggle("hidden", t !== "card");
  identityFields.classList.toggle("hidden", t !== "identity");
  const ph = { login: "Site / App", card: "Card name / label", identity: "Identity name", note: "Title" };
  fSite.placeholder = ph[t];
  if (t !== "login") stopTotpPreview();
}
typeBtnLogin.addEventListener("click", () => setCredType("login"));
typeBtnCard.addEventListener("click", () => setCredType("card"));
typeBtnId.addEventListener("click", () => setCredType("identity"));
typeBtnNote.addEventListener("click", () => setCredType("note"));
btnAdd.addEventListener("click", () => openAdd());
function clearForm() {
  fSite.value = "";
  fUser.value = "";
  fPass.value = "";
  fNotes.value = "";
  fFolder.value = "";
  fTotp.value = "";
  fExpiry.value = "";
  fCardHolder.value = "";
  fCardNumber.value = "";
  fCardExpiry.value = "";
  fCardCvv.value = "";
  fIdFirst.value = "";
  fIdLast.value = "";
  fIdEmail.value = "";
  fIdPhone.value = "";
  fIdAddress.value = "";
  fIdDob.value = "";
  addStatus.textContent = "";
  breachResult.classList.add("hidden");
  pwStrengthWrap.classList.add("hidden");
  totpPreview.classList.add("hidden");
  $("pw-history-section").classList.add("hidden");
  stopTotpPreview();
}
function openAdd() {
  editingId = null;
  clearForm();
  setCredType("login");
  formTitle.textContent = "Add credential";
  btnDelete.classList.add("hidden");
  btnBreachCheck.classList.add("hidden");
  prevView = "unlocked";
  show("add");
  fSite.focus();
}
function openEdit(c) {
  var _a;
  editingId = c.id;
  clearForm();
  setCredType(c.type ?? "login");
  formTitle.textContent = "Edit credential";
  fSite.value = c.site;
  fNotes.value = c.notes;
  fFolder.value = c.folder ?? "";
  if (c.type === "login") {
    fUser.value = c.username;
    fPass.value = c.password;
    fTotp.value = c.totp ?? "";
    if (c.expiresAt) fExpiry.value = new Date(c.expiresAt).toISOString().slice(0, 10);
    if (c.password) fPass.dispatchEvent(new Event("input"));
    if (c.totp) startTotpPreview(c.totp);
  } else if (c.type === "card") {
    fCardHolder.value = c.cardHolder ?? "";
    fCardNumber.value = c.cardNumber ?? "";
    fCardExpiry.value = c.cardExpiry ?? "";
    fCardCvv.value = c.cardCvv ?? "";
  } else if (c.type === "identity") {
    fIdFirst.value = c.idFirstName ?? "";
    fIdLast.value = c.idLastName ?? "";
    fIdEmail.value = c.idEmail ?? "";
    fIdPhone.value = c.idPhone ?? "";
    fIdAddress.value = c.idAddress ?? "";
    fIdDob.value = c.idDob ?? "";
  }
  btnDelete.classList.remove("hidden");
  btnBreachCheck.classList.toggle("hidden", !cachedOptions.hibpEnabled);
  const histSection = $("pw-history-section");
  const histList = $("pw-history-list");
  histList.innerHTML = "";
  if ((_a = c.passwordHistory) == null ? void 0 : _a.length) {
    c.passwordHistory.forEach((h) => {
      const entry = document.createElement("div");
      entry.className = "pw-hist-entry";
      const pw = document.createElement("span");
      pw.className = "pw-hist-pw";
      pw.textContent = "••••••••";
      const copyBtn = document.createElement("button");
      copyBtn.className = "pw-hist-copy";
      copyBtn.textContent = "copy";
      copyBtn.addEventListener("click", async () => {
        await copyToClipboard(h.password);
        copyBtn.textContent = "✓";
        setTimeout(() => {
          copyBtn.textContent = "copy";
        }, 1500);
      });
      const revBtn = document.createElement("button");
      revBtn.className = "pw-hist-copy";
      revBtn.textContent = "show";
      revBtn.addEventListener("click", () => {
        const hidden = pw.textContent === "••••••••";
        pw.textContent = hidden ? h.password : "••••••••";
        revBtn.textContent = hidden ? "hide" : "show";
      });
      const date = document.createElement("span");
      date.className = "pw-hist-date";
      date.textContent = new Date(h.changedAt).toLocaleDateString(void 0, { month: "short", day: "numeric", year: "numeric" });
      entry.append(pw, copyBtn, revBtn, date);
      histList.appendChild(entry);
    });
    histSection.classList.remove("hidden");
  } else {
    histSection.classList.add("hidden");
  }
  prevView = "unlocked";
  show("add");
  fSite.focus();
}
btnCancel.addEventListener("click", () => {
  stopTotpPreview();
  show("unlocked");
});
fPass.addEventListener("input", () => {
  const r = measureStrength(fPass.value);
  if (!fPass.value) {
    pwStrengthWrap.classList.add("hidden");
    return;
  }
  pwStrengthWrap.classList.remove("hidden");
  pwStrengthBar.style.background = r.color;
  pwStrengthBar.style.width = `${r.score / 4 * 100}%`;
  pwStrengthLabel.textContent = r.label;
  pwStrengthLabel.style.color = r.color;
  pwStrengthEntropy.textContent = `${r.entropy} bits`;
});
btnShowPass.addEventListener("click", () => {
  fPass.type = fPass.type === "password" ? "text" : "password";
  btnShowPass.textContent = fPass.type === "password" ? "👁" : "🙈";
});
btnFillGen.addEventListener("click", () => {
  fPass.value = genPw();
  fPass.dispatchEvent(new Event("input"));
});
function startTotpPreview(secret) {
  stopTotpPreview();
  if (!validateBase32Secret(secret)) return;
  async function update() {
    try {
      const code = await generateTOTP(secret);
      const secs = secondsRemaining();
      totpPreview.textContent = `${code.slice(0, 3)} ${code.slice(3)} · ${secs}s`;
      totpPreview.classList.remove("hidden");
    } catch {
      totpPreview.classList.add("hidden");
    }
  }
  update();
  totpInterval = setInterval(update, 1e3);
}
function stopTotpPreview() {
  if (totpInterval) {
    clearInterval(totpInterval);
    totpInterval = null;
  }
  totpPreview.classList.add("hidden");
}
fTotp.addEventListener("input", () => {
  const val = fTotp.value.trim();
  if (val && validateBase32Secret(val)) startTotpPreview(val);
  else stopTotpPreview();
});
btnSave.addEventListener("click", async () => {
  const site = fSite.value.trim();
  const notes = fNotes.value;
  const labels = { login: "Site", card: "Card name", identity: "Identity name", note: "Title" };
  if (!site) {
    addStatus.textContent = `${labels[credType]} is required.`;
    return;
  }
  if (credType === "login" && !fPass.value) {
    addStatus.textContent = "Password is required.";
    return;
  }
  if (credType === "login" && fTotp.value && !validateBase32Secret(fTotp.value)) {
    addStatus.textContent = "Invalid TOTP secret — must be base32.";
    return;
  }
  btnSave.disabled = true;
  const folder = fFolder.value.trim() || void 0;
  try {
    let cred;
    if (credType === "login") {
      const expiresAt = fExpiry.value ? new Date(fExpiry.value).getTime() : void 0;
      cred = { type: "login", site, username: fUser.value.trim(), password: fPass.value, notes, folder, totp: fTotp.value.trim() || void 0, expiresAt };
    } else if (credType === "card") {
      cred = { type: "card", site, username: "", password: "", notes, folder, cardHolder: fCardHolder.value.trim(), cardNumber: fCardNumber.value.trim(), cardExpiry: fCardExpiry.value.trim(), cardCvv: fCardCvv.value.trim() };
    } else if (credType === "identity") {
      cred = { type: "identity", site, username: "", password: "", notes, folder, idFirstName: fIdFirst.value.trim(), idLastName: fIdLast.value.trim(), idEmail: fIdEmail.value.trim(), idPhone: fIdPhone.value.trim(), idAddress: fIdAddress.value.trim(), idDob: fIdDob.value || void 0 };
    } else {
      cred = { type: "note", site, username: "", password: "", notes, folder };
    }
    if (editingId) await updateCredential(editingId, cred);
    else await addCredential(cred);
    stopTotpPreview();
    await loadList();
  } catch {
    addStatus.textContent = "Failed to save.";
    btnSave.disabled = false;
  }
});
btnDelete.addEventListener("click", async () => {
  if (!editingId || !confirm("Delete this credential?")) return;
  try {
    stopTotpPreview();
    await deleteCredential(editingId);
    await loadList();
  } catch {
    addStatus.textContent = "Failed to delete.";
  }
});
btnBreachCheck.addEventListener("click", async () => {
  const pw = fPass.value;
  if (!pw) {
    breachResult.textContent = "Enter a password first.";
    breachResult.className = "breach-result";
    breachResult.classList.remove("hidden");
    return;
  }
  btnBreachCheck.textContent = "Checking…";
  btnBreachCheck.disabled = true;
  breachResult.classList.remove("hidden");
  breachResult.className = "breach-result";
  breachResult.textContent = "";
  try {
    const res = await checkPasswordBreach(pw);
    breachResult.className = `breach-result ${res.breached ? "breach-danger" : "breach-safe"}`;
    breachResult.textContent = res.breached ? `⚠ Seen ${res.count.toLocaleString()} times in data breaches — change this password.` : "✓ Not found in known data breaches.";
  } catch {
    breachResult.textContent = "Breach check failed (network error).";
  }
  btnBreachCheck.textContent = "Check for breaches 🔍";
  btnBreachCheck.disabled = false;
});
let pendingImport = [];
btnImport.addEventListener("click", () => {
  pendingImport = [];
  importPreview.classList.add("hidden");
  importStatus.textContent = "";
  btnImportConfirm.classList.add("hidden");
  importFileName.textContent = "no file selected";
  prevView = "unlocked";
  show("import");
});
btnImportBack.addEventListener("click", () => show("unlocked"));
fileDropZone.addEventListener("click", () => importFileInput.click());
importFileInput.addEventListener("change", () => {
  var _a;
  const file = (_a = importFileInput.files) == null ? void 0 : _a[0];
  if (!file) return;
  importFileName.textContent = file.name;
  const reader = new FileReader();
  reader.onload = (e) => {
    var _a2;
    const text = (_a2 = e.target) == null ? void 0 : _a2.result;
    const fmt = detectFormat(text);
    try {
      const raw = importCredentials(text, fmt);
      pendingImport = raw.map((r) => ({ ...r, type: "login" }));
      replace(
        importPreview,
        "Detected: ",
        el("strong", { textContent: fmt }),
        " · ",
        el("strong", { textContent: String(pendingImport.length) }),
        ` credential${pendingImport.length !== 1 ? "s" : ""}`
      );
      importPreview.classList.remove("hidden");
      importStatus.textContent = "";
      btnImportConfirm.classList.toggle("hidden", pendingImport.length === 0);
    } catch {
      importStatus.textContent = "Failed to parse CSV.";
    }
  };
  reader.readAsText(file);
  importFileInput.value = "";
});
btnImportConfirm.addEventListener("click", async () => {
  if (!pendingImport.length) return;
  btnImportConfirm.disabled = true;
  btnImportConfirm.textContent = "Importing…";
  try {
    for (const c of pendingImport) await addCredential(c);
    await logAuditEvent("vault_import");
    importStatus.className = "status-msg status-ok";
    importStatus.textContent = `✓ Imported ${pendingImport.length} credentials.`;
    btnImportConfirm.classList.add("hidden");
    pendingImport = [];
    await loadList();
    setTimeout(() => show("unlocked"), 1200);
  } catch {
    importStatus.className = "status-msg";
    importStatus.textContent = "Import failed.";
    btnImportConfirm.disabled = false;
    btnImportConfirm.textContent = "Import → add credentials";
  }
});
function genPw() {
  return generatePassword({
    length: Math.max(8, Math.min(64, Number(genLen.value) || 20)),
    upper: genUpper.checked,
    numbers: genNums.checked,
    symbols: genSyms.checked
  });
}
function setGenMode(mode) {
  genMode = mode;
  genTabPw.classList.toggle("active", mode === "pw");
  genTabPp.classList.toggle("active", mode === "pp");
  genPwOpts.classList.toggle("hidden", mode !== "pw");
  genPpOpts.classList.toggle("hidden", mode !== "pp");
  genStrengthWrap.classList.toggle("hidden", mode !== "pw");
  genEntropyLabel.classList.toggle("hidden", mode !== "pp");
  refreshGen();
}
function refreshGen() {
  copyStatus.textContent = "";
  copyStatus.className = "status-msg";
  if (genMode === "pw") {
    const pw = genPw();
    genOutput.textContent = pw;
    const r = measureStrength(pw);
    genStrengthBar.style.background = r.color;
    genStrengthBar.style.width = `${r.score / 4 * 100}%`;
    genStrengthLabel.textContent = r.label;
    genStrengthLabel.style.color = r.color;
  } else {
    const words = Math.max(3, Math.min(8, Number(ppWords.value) || 4));
    const pp = generatePassphrase({ wordCount: words, separator: ppSep.value, capitalize: ppCap.checked, appendNumber: ppNum.checked });
    genOutput.textContent = pp;
    genEntropyLabel.textContent = `~${passphraseEntropy(words)} bits of entropy · ${WORDLIST.length.toLocaleString()} word list`;
  }
}
genTabPw.addEventListener("click", () => setGenMode("pw"));
genTabPp.addEventListener("click", () => setGenMode("pp"));
btnGen.addEventListener("click", () => {
  prevView = "unlocked";
  refreshGen();
  show("gen");
});
btnGenBack.addEventListener("click", () => show(prevView));
btnRegen.addEventListener("click", refreshGen);
btnCopy.addEventListener("click", async () => {
  await copyToClipboard(genOutput.textContent ?? "");
  copyStatus.textContent = "Copied!";
  copyStatus.className = "status-msg status-ok";
  setTimeout(() => {
    copyStatus.textContent = "";
    copyStatus.className = "status-msg";
  }, 2e3);
});
[genLen, genUpper, genNums, genSyms].forEach((el2) => el2.addEventListener("change", refreshGen));
[ppWords, ppCap, ppNum].forEach((el2) => el2.addEventListener("change", refreshGen));
ppSep.addEventListener("change", refreshGen);
init();
//# sourceMappingURL=popup-CY8L16MF.js.map
