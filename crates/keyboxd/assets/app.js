"use strict";

// Browser side of the approval page. It only passes bytes between Key-Box and
// the passkey; every decision is made by the server.

const b64 = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const unb64 = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  });
  const reply = await response.json();
  if (!reply.ok) throw new Error(reply.error);
  return reply;
}

const allow = (ids) => ids.map((id) => ({ type: "public-key", id: unb64(id) }));

// Ask a registered passkey to sign the challenge Key-Box made for this purpose.
// For notifications the browser's subscription is sent along, and the
// signature then covers exactly that subscription.
async function sign(purpose, request, subscription) {
  const start = await post("/api/assert/start", { purpose, request, subscription });
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: unb64(start.challenge),
      rpId: start.rp_id,
      allowCredentials: allow(start.credentials),
      userVerification: "required",
      timeout: 120000,
    },
  });
  return post("/api/assert/finish", {
    challenge_id: start.challenge_id,
    credential_id: b64(credential.rawId),
    client_data: b64(credential.response.clientDataJSON),
    auth_data: b64(credential.response.authenticatorData),
    signature: b64(credential.response.signature),
  });
}

async function register(name, token) {
  const start = await post("/api/register/start", { name, token });
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: start.rp_id, name: "Key-Box" },
      user: { id: unb64(start.user_id), name: "christian", displayName: "Christian" },
      challenge: unb64(start.challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: allow(start.credentials),
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      attestation: "none",
      timeout: 120000,
    },
  });
  return post("/api/register/finish", {
    challenge_id: start.challenge_id,
    client_data: b64(credential.response.clientDataJSON),
    auth_data: b64(credential.response.getAuthenticatorData()),
  });
}

const value = (id) => (document.getElementById(id)?.value || "").trim();

// What Key-Box' refusals mean. The word itself is shown too.
const MEANING = {
  "not-authorized": "Tokenet er forkert eller udløbet.",
  "same-credential": "Det er den samme passkey som før. Brug en anden.",
  "unknown-request": "Anmodningen findes ikke længere.",
  "closed": "Anmodningen er allerede lukket.",
  "expired": "Anmodningen er udløbet.",
  "unknown-credential": "Den passkey er ikke registreret her.",
  "NotAllowedError": "Passkey blev afbrudt eller afvist.",
  "notifications-blocked": "Browseren har ikke fået lov til at vise notifikationer. Giv lov i browserens indstillinger for siden.",
  "unsupported-push-service": "Denne browser bruger en notifikationstjeneste, Key-Box ikke må kalde. Brug Chrome eller Samsung Internet.",
  "unknown-subscription": "Denne enhed var ikke slået til.",
};

// --- notifications -----------------------------------------------------------

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const part = (bytes) => {
  const out = new Uint8Array(8 + bytes.length);
  new DataView(out.buffer).setUint32(4, bytes.length);
  out.set(bytes, 8);
  return out;
};

// This browser's subscription, if it has one.
async function subscribed() {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) return null;
  const registration = await navigator.serviceWorker.getRegistration("/");
  return registration ? registration.pushManager.getSubscription() : null;
}

// The name Key-Box knows a subscription by: a hash, never the address.
async function mark(subscription) {
  const parts = [
    new TextEncoder().encode(subscription.endpoint),
    new Uint8Array(subscription.getKey("p256dh")),
    new Uint8Array(subscription.getKey("auth")),
  ].map(part);
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((at, p) => (all.set(p, at), at + p.length), 0);
  return hex(await crypto.subtle.digest("SHA-256", all)).slice(0, 16);
}

async function notifyOn(card) {
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    throw new Error("unsupported-push-service");
  }
  if ((await Notification.requestPermission()) !== "granted") throw new Error("notifications-blocked");
  await navigator.serviceWorker.register("/sw.js");
  const registration = await navigator.serviceWorker.ready;
  let subscription = await registration.pushManager.getSubscription();
  // A subscription made for another Key-Box key cannot be sent to.
  if (subscription && b64(subscription.options.applicationServerKey) !== card.dataset.key) {
    await subscription.unsubscribe();
    subscription = null;
  }
  subscription ||= await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: unb64(card.dataset.key),
  });
  await sign("notify", null, {
    endpoint: subscription.endpoint,
    p256dh: b64(subscription.getKey("p256dh")),
    auth: b64(subscription.getKey("auth")),
  });
}

async function notifyOff() {
  const subscription = await subscribed();
  if (!subscription) throw new Error("unknown-subscription");
  try {
    await post("/api/notify/off", { endpoint: subscription.endpoint });
  } finally {
    await subscription.unsubscribe();
  }
}

// Say whether this browser is one of the subscribed devices.
async function showNotifyState() {
  const card = document.getElementById("notify");
  if (!card) return;
  const state = document.getElementById("notify-state");
  const [on, off] = ["notify-on", "notify-off"].map((act) => card.querySelector(`[data-act="${act}"]`));
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    state.textContent = "Denne browser kan ikke vise notifikationer.";
    on.hidden = true;
    return;
  }
  const subscription = await subscribed();
  const known = subscription && card.dataset.known.split(",").includes(await mark(subscription));
  if (known) state.textContent += " Denne enhed er en af dem.";
  on.hidden = Boolean(known);
  off.hidden = !known;
}
showNotifyState().catch(() => {});

function explain(error) {
  const word = (error && (MEANING[error.name] ? error.name : error.message)) || "ukendt";
  return MEANING[word] ? `${MEANING[word]} (${word})` : `Fejl: ${word}`;
}

let busy = false;

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-act]");
  if (!button || busy) return;
  const message = document.getElementById("message");
  message.textContent = "";
  button.disabled = true;
  busy = true;
  try {
    const request = button.dataset.request || null;
    switch (button.dataset.act) {
      case "approve":
        await sign("approve", request);
        break;
      case "cancel":
        await post("/api/cancel", { request });
        break;
      case "stop":
        if (!confirm("Nødstop: træk alt tilbage og afvis alt?")) return;
        await sign("stop", null);
        break;
      case "resume":
        await sign("resume", null);
        break;
      case "policy":
        await sign("policy", null);
        break;
      case "notify-on":
        await notifyOn(button.closest("#notify"));
        break;
      case "notify-off":
        await notifyOff();
        break;
      case "register-token":
        await register(value("passkey-name"), value("enroll-token"));
        break;
    }
    location.reload();
  } catch (error) {
    message.textContent = explain(error);
  } finally {
    button.disabled = false;
    busy = false;
  }
});

// Keep the countdowns moving. The seconds left came from Key-Box; when one
// runs out, ask Key-Box what is true now.
const loaded = performance.now();
function tick() {
  const passed = Math.floor((performance.now() - loaded) / 1000);
  for (const timer of document.querySelectorAll(".timer")) {
    const left = Number(timer.dataset.left) - passed;
    if (left < 0) return refresh(true);
    timer.textContent = `${timer.dataset.label} ${Math.floor(left / 60)} min ${left % 60} sek`;
    timer.classList.toggle("soon", left < 60);
  }
}

// Reload when Key-Box has something new to show, but never under a passkey
// prompt and never while something is being typed.
async function refresh(force) {
  const typing = [...document.querySelectorAll("input")].some((i) => i.value !== "");
  if (busy || typing || document.visibilityState !== "visible") return;
  try {
    const response = await fetch("/state", { credentials: "omit", cache: "no-store" });
    const state = await response.json();
    if (!busy && (force || state.v !== document.body.dataset.v)) location.reload();
  } catch {
    // Offline for a moment. The next round tries again.
  }
}

setInterval(tick, 1000);
setInterval(refresh, 5000);
document.addEventListener("visibilitychange", () => refresh(false));
