import { l as logAuditEvent } from "./vault-XO-0w6qj.js";
async function checkPasswordBreach(password) {
  const msgBuf = new TextEncoder().encode(password);
  const hashBuf = await crypto.subtle.digest("SHA-1", msgBuf);
  const hex = Array.from(new Uint8Array(hashBuf), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" }
  });
  if (!res.ok) throw new Error(`HIBP API error: ${res.status}`);
  const text = await res.text();
  await logAuditEvent("hibp_check");
  for (const line of text.split("\r\n")) {
    const [s, countStr] = line.split(":");
    if (s === suffix) {
      const count = parseInt(countStr, 10);
      return { breached: true, count };
    }
  }
  return { breached: false, count: 0 };
}
function measureStrength(pw) {
  if (!pw) return { score: 0, label: "", color: "transparent", entropy: 0, feedback: "" };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const entropy = pw.length * Math.log2(pool || 1);
  const uniqueRatio = new Set(pw).size / pw.length;
  const adjusted = entropy * (0.5 + 0.5 * uniqueRatio);
  let score;
  let label;
  let color;
  let feedback;
  if (adjusted < 28) {
    score = 0;
    label = "Very weak";
    color = "#ef4444";
    feedback = "Too short or too simple — easily cracked.";
  } else if (adjusted < 40) {
    score = 1;
    label = "Weak";
    color = "#f97316";
    feedback = "Add more characters or mix uppercase, numbers, and symbols.";
  } else if (adjusted < 55) {
    score = 2;
    label = "Fair";
    color = "#f59e0b";
    feedback = "Decent, but a longer password would be stronger.";
  } else if (adjusted < 70) {
    score = 3;
    label = "Strong";
    color = "#84cc16";
    feedback = "Good password. A symbol or two would make it excellent.";
  } else {
    score = 4;
    label = "Very strong";
    color = "#22c55e";
    feedback = "Excellent password strength.";
  }
  return { score, label, color, entropy: Math.round(adjusted), feedback };
}
function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  if (props.className !== void 0) node.className = props.className;
  if (props.textContent !== void 0) node.textContent = props.textContent;
  if (props.style !== void 0) node.setAttribute("style", props.style);
  if (props.title !== void 0) node.title = props.title;
  for (const c of children) node.append(c);
  return node;
}
function replace(node, ...children) {
  node.replaceChildren(...children);
}
export {
  checkPasswordBreach as c,
  el as e,
  measureStrength as m,
  replace as r
};
//# sourceMappingURL=dom-Ooi5XjY4.js.map
