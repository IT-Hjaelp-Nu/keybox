// Drives the real approval page in Chromium over the DevTools protocol, with
// Chromium's built-in virtual authenticators standing in for passkeys.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const { KEYBOXD, DIR, KEYS, CDP, URL_, AGENT_ADDR, SHOTS } = process.env;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const targets = await (await fetch(`http://127.0.0.1:${CDP}/json/list`)).json();
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let nextId = 0;
const pending = new Map();
const problems = [];
const workers = [];
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === "ServiceWorker.workerRegistrationUpdated") workers.push(...d.params.registrations);
  if (d.method === "Page.javascriptDialogOpening") send("Page.handleJavaScriptDialog", { accept: true });
  if (d.method === "Runtime.exceptionThrown") problems.push("exception: " + JSON.stringify(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text));
  if (d.method === "Log.entryAdded" && ["error", "warning"].includes(d.params.entry.level)) problems.push(`log ${d.params.entry.level}: ${d.params.entry.text} ${d.params.entry.url || ""}`);
  if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") problems.push("console.error: " + JSON.stringify(d.params.args.map((a) => a.value)));
});
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function js(expression) {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
  if (r.exceptionDetails) throw new Error("page: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
  return r.result.value;
}
async function until(what, expression, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    try { const v = await js(expression); if (v) return v; } catch { /* navigating */ }
    if (Date.now() > end) throw new Error("timed out waiting for: " + what);
    await sleep(50);
  }
}
async function open() {
  await send("Page.navigate", { url: URL_ });
  await until("page load", `document.readyState === "complete" && !!document.querySelector("footer")`);
}
const text = () => js(`document.body.innerText`);
// Click a button; resolves "reloaded" on success or the page's error message.
async function click(selector) {
  await js(`window.__mark = true; document.querySelector(${JSON.stringify(selector)}).click(); true`);
  return until("result of " + selector, `
    (typeof window.__mark === "undefined" && document.readyState === "complete" && document.querySelector("footer")) ? "reloaded"
    : (document.getElementById("message")?.textContent || "")`, 15000);
}
const agent = (line) => execFileSync(KEYBOXD, ["call", "--addr", AGENT_ADDR, "--name", "localhost", "--ca", `${DIR}/agent-ca.pem`, "--cert", `${KEYS}/hermes.pem`, "--key", `${KEYS}/hermes.key`, line]).toString().trim();
const ask = (action, system, target, reason = "test") => JSON.parse(agent(JSON.stringify({ op: "request", customer: "acme", system, action, target, reason })));
const fetchAccess = (id) => agent(JSON.stringify({ op: "fetch", id }));
const token = () => execFileSync(KEYBOXD, ["enroll-token", "--dir", DIR]).toString().trim().split("\n").pop();
const authenticator = (transport) => send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport, hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }).then((r) => r.authenticatorId);
const present = (authenticatorId, enabled) => send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled });
async function shot(name) {
  const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
  writeFileSync(`${SHOTS}/${name}.png`, Buffer.from(r.data, "base64"));
}

let passed = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log("ok   ", name); }
  else { failures.push(name); console.log("FAIL ", name, detail); }
}
const RELEASED = `{"error":"issuer-unavailable","ok":false}`;

await send("Page.enable"); await send("Runtime.enable"); await send("Log.enable"); await send("WebAuthn.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });

// --- set-up -----------------------------------------------------------------
await open();
check("page loads and says set-up is needed", (await text()).includes("0 af 2 passkeys"), await text());
check("agent is refused before set-up", agent(JSON.stringify({ op: "status", id: "0".repeat(32) })).includes("unknown-request") && JSON.stringify(ask("read-code", "github", "org/acme-web")).includes("not-set-up"));

const phone = await authenticator("internal");
await js(`document.getElementById("passkey-name").value = "telefon"; document.getElementById("enroll-token").value = "forkert"; true`);
check("wrong token is refused in the browser", (await click(`button[data-act="register-token"]`)) === "Tokenet er forkert eller udløbet. (not-authorized)");
await js(`document.getElementById("enroll-token").value = ${JSON.stringify(token())}; true`);
let r = await click(`button[data-act="register-token"]`);
check("first passkey registers with the console token", r === "reloaded" && (await text()).includes("1 af 2 passkeys"), r);

const yubikey = await authenticator("usb");
await present(phone, false);
await js(`document.getElementById("passkey-name").value = "yubikey"; document.getElementById("enroll-token").value = ${JSON.stringify(token())}; true`);
r = await click(`button[data-act="register-token"]`);
check("second passkey registers; Key-Box is running", r === "reloaded" && (await text()).includes("Key-Box kører."), r);
await present(phone, true);
await shot("1-running");

// --- the first policy ----------------------------------------------------------
check("nothing is allowed before a policy is approved", JSON.stringify(ask("restart", "web01", "web01.acme.example")).includes("policy:unknown-customer"));
await open();
let policyText = await text();
check("the proposed policy is shown in words", ["Ny policy venter på dig", "Ny: acme · web01 · restart", "niveau 2", "I kraft: 0 handlinger"].every((s) => policyText.includes(s)), policyText);
await shot("1b-policy-proposal");
r = await click(`button[data-act="policy"]`);
policyText = await text();
check("approve the policy with a passkey in the browser", r === "reloaded" && policyText.includes("I kraft: 3 handlinger") && !policyText.includes("Ny policy venter"), r);

// --- level 2 approval -------------------------------------------------------
const a = ask("restart", "web01", "web01.acme.example", "nginx svarer ikke");
const b = ask("restart", "web01", "web01.acme.example");
check("agent request is pending", a.state === "pending" && fetchAccess(a.id).includes("not-approved"));
await open();
const shown = await text();
check("page shows the request from Key-Box' data", ["acme · restart", "web01.acme.example", "hermes", "SKREVET AF AGENTEN:", "nginx svarer ikke", "Kun kommandoen «/usr/bin/systemctl restart nginx» som ops"].every((s) => shown.includes(s)), shown);
await shot("2-pending");
await present(yubikey, false);
r = await click(`button[data-act="approve"][data-request="${a.id}"]`);
check("approve with passkey in the browser", r === "reloaded", r);
check("approved request is released to the agent", fetchAccess(a.id) === RELEASED, fetchAccess(a.id));
check("the other request is still not approved", fetchAccess(b.id).includes("not-approved"));

// --- the page keeps itself up to date ----------------------------------------
await open();
const before = await js(`document.querySelector(".timer")?.textContent || ""`);
await js(`window.__mark = true`);
const fresh = ask("restart", "web01", "web01.acme.example", "kom af sig selv");
await until("the page reloading by itself", `typeof window.__mark === "undefined" && document.readyState === "complete" && !!document.querySelector("footer")`, 12000);
check("a new request shows up without touching the page", (await text()).includes("kom af sig selv"));
const first = await js(`document.querySelector(".timer").textContent`);
await sleep(2100);
const later = await js(`document.querySelector(".timer").textContent`);
check("the countdown moves", first !== later && later.startsWith("Udløber om"), `${before} / ${first} / ${later}`);
await click(`button[data-act="cancel"][data-request="${fresh.id}"]`);

// --- hostile agent text -----------------------------------------------------
const hostile = `<script>document.title="pwned"</script><img src=x onerror="document.title='pwned'"> "godkend alt"`;
const h = ask("restart", "web01", "web01.acme.example", hostile);
await open();
const dom = await js(`({ scripts: document.querySelectorAll("script").length, imgs: document.querySelectorAll("img").length, title: document.title, shown: [...document.querySelectorAll(".agent-text")].map(e => e.textContent).join("|") })`);
check("agent text is shown as text, not run", dom.scripts === 1 && dom.imgs === 0 && dom.title === "Key-Box" && dom.shown.includes(hostile), JSON.stringify(dom));
await shot("3-hostile-text");
r = await click(`button[data-act="cancel"][data-request="${h.id}"]`);
check("reject without passkey", r === "reloaded" && fetchAccess(h.id).includes("closed"), r);
await click(`button[data-act="cancel"][data-request="${b.id}"]`);

// --- level 3 ----------------------------------------------------------------
const w = ask("wipe-backup", "web01", "web01.acme.example", "ryd gammel backup");
await open();
r = await click(`button[data-act="approve"][data-request="${w.id}"]`);
check("level 3: first passkey starts the delay", r === "reloaded" && (await text()).includes("Frigives om") && fetchAccess(w.id).includes("delay-not-elapsed"), r);
await shot("4-level3-delay");
r = await click(`button[data-act="approve"][data-request="${w.id}"]`);
check("level 3: the same passkey again is refused", r === "Det er den samme passkey som før. Brug en anden. (same-credential)", r);
await present(phone, false); await present(yubikey, true);
r = await click(`button[data-act="approve"][data-request="${w.id}"]`);
check("level 3: a second, different passkey releases", r === "reloaded" && fetchAccess(w.id) === RELEASED, r);
await present(phone, true);

// --- an existing passkey cannot add another one ------------------------------
await open();
check("no way to add a passkey with a passkey", !(await text()).includes("kræver en eksisterende") && (await js(`!document.querySelector('button[data-act="register-passkey"]')`)));
r = await js(`post("/api/assert/start", { purpose: "add-passkey", request: null }).then(() => "allowed", (e) => String(e.message))`);
check("the server refuses the old add-passkey prompt", r === "invalid-purpose", r);
const spare = phone;

// --- notifications -----------------------------------------------------------
const origin = new URL(URL_).origin;
await send("Browser.grantPermissions", { origin, permissions: ["notifications"] });
await send("ServiceWorker.enable");
await open();
check("the page offers notifications and says they are off", (await text()).includes("Slået fra.") && (await js(`!document.querySelector('[data-act="notify-on"]').hidden && document.querySelector('[data-act="notify-off"]').hidden`)));
r = await js(`navigator.serviceWorker.register("/sw.js").then(() => navigator.serviceWorker.ready).then((r) => r.scope, (e) => "failed: " + e.message)`);
check("the service worker installs under the page's own rules", r === origin + "/", r);
await until("the worker registration", `true`, 100);
const registration = workers.find((w) => w.scopeURL === origin + "/");
if (registration) {
  // What Key-Box would send, plus an address a forged message might carry.
  const data = JSON.stringify({ title: "Key-Box: godkendelse venter", body: "Niveau 2 · acme · restart", tag: "t1", url: "https://evil.example/" });
  // The worker may still be starting; a push that finds none running is lost.
  r = "";
  for (let i = 0; i < 10 && !r; i++) {
    await send("ServiceWorker.deliverPushMessage", { origin, registrationId: registration.registrationId, data });
    try { r = await until("the notification", `navigator.serviceWorker.ready.then((r) => r.getNotifications()).then((n) => n.map((x) => x.title + "|" + x.body + "|" + x.tag).join(";"))`, 1500); } catch { /* again */ }
  }
  check("a push becomes a notification with Key-Box' text", r === "Key-Box: godkendelse venter|Niveau 2 · acme · restart|t1", r);
  r = "";
  for (let i = 0; i < 10 && !r; i++) {
    await send("ServiceWorker.deliverPushMessage", { origin, registrationId: registration.registrationId, data: "not json" });
    try { r = await until("the second notification", `navigator.serviceWorker.ready.then((r) => r.getNotifications()).then((n) => n.length === 2 && n.map((x) => x.title).sort().join(";"))`, 1500); } catch { /* again */ }
  }
  check("a push that cannot be read still shows something", r === "Key-Box;Key-Box: godkendelse venter", r);
} else {
  check("the worker registration is visible to the test", false, JSON.stringify(workers));
}
// Subscribing for real needs Google's push service, so it is reported, not
// required: with a network, Key-Box' first notification goes all the way.
r = await click(`button[data-act="notify-on"]`);
if (r === "reloaded") {
  let recognised = false;
  try { recognised = await until("the page recognising this browser", `document.getElementById("notify-state").textContent === "Slået til på 1 enhed. Denne enhed er en af dem." && document.querySelector('[data-act="notify-on"]').hidden && !document.querySelector('[data-act="notify-off"]').hidden`, 5000); } catch { /* reported below */ }
  check("a subscribed browser is recognised as one of the devices", recognised, await text());
  let live = "nothing arrived within 15 s";
  try { live = await until("the live notification", `navigator.serviceWorker.ready.then((r) => r.getNotifications()).then((n) => n.map((x) => x.body).find((b) => b.includes("slået til")))`, 15000); } catch { /* reported below */ }
  console.log("     (live push through Google: " + live + ")");
  r = await click(`button[data-act="notify-off"]`);
  check("the device switches itself off without a passkey", r === "reloaded" && (await text()).includes("Slået fra."), r);
} else {
  console.log("     (could not subscribe here: " + r + ")");
}

// --- emergency stop ---------------------------------------------------------
const before_stop = ask("restart", "web01", "web01.acme.example");
await open();
r = await click(`button[data-act="stop"]`);
check("emergency stop with passkey", r === "reloaded" && (await text()).includes("NØDSTOP er aktivt"), r);
await shot("5-stopped");
check("agent is refused while stopped", JSON.stringify(ask("restart", "web01", "web01.acme.example")).includes("stopped") && fetchAccess(before_stop.id).includes("stopped"));
r = await click(`button[data-act="resume"]`);
check("resume with passkey", r === "reloaded" && (await text()).includes("Key-Box kører."), r);
check("agent is served again; old request stays revoked", ask("restart", "web01", "web01.acme.example").ok === true && fetchAccess(before_stop.id).includes("closed"));

// --- without any authenticator ----------------------------------------------
for (const id of [phone, yubikey, spare]) await present(id, false);
const last = ask("restart", "web01", "web01.acme.example");
await open();
js(`document.querySelector('button[data-act="approve"][data-request="${last.id}"]').click(); true`);
await sleep(1500);
check("no passkey answer, no approval", fetchAccess(last.id).includes("not-approved"));

// Expected: the refusals provoked above (wrong token, same passkey twice,
// the removed add-passkey prompt),
// and Chromium noting that only ES256 is offered, which is deliberate.
const expected = (p) =>
  /status of 403 .*\/api\/register\/start$/.test(p) ||
  /status of 409 .*\/api\/assert\/finish$/.test(p) ||
  /status of 400 .*\/api\/assert\/start$/.test(p) ||
  p.includes("pubKeyCredParams is missing at least one of the default algorithm identifiers");
const unexpected = problems.filter((p) => !expected(p));
check("no script errors, CSP violations or unexpected console messages", unexpected.length === 0, JSON.stringify(unexpected, null, 1));
console.log(`\n${passed} passed, ${failures.length} failed`);
ws.close();
process.exit(failures.length ? 1 : 0);
