//! Notifications to Christian's phone: "something is waiting for you".
//!
//! This is Web Push. The browser on the phone gives Key-Box an address at
//! the browser maker's push service and a public key. Key-Box encrypts a
//! short message to that key (RFC 8291) and posts it to the address, signed
//! as coming from this Key-Box (VAPID, RFC 8292). The push service sees
//! that a message was sent and when, never what it says.
//!
//! A notification grants nothing. It carries no link: tapping it opens
//! Key-Box' own page, where everything still needs the passkey. What it says
//! comes from Key-Box' own validated data, never from an agent's free text.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::Method;
use keybox_core::ident::{AgentId, RequestId};
use keybox_core::policy::Level;
use keybox_core::request::RequestSpec;
use keybox_webauthn::{base64url, base64url_decode};
use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use ring::digest::{Context, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use ring::{aead, hkdf};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::core::Core;
use crate::https::HttpsClient;

/// The only places Key-Box will post to: Google's push service, which Chrome
/// and Samsung Internet on Android use, under the two names it hands out
/// (the second since 2025). The service's firewall is opened for it and
/// nothing else.
pub const PUSH_ORIGINS: [&str; 2] = ["https://fcm.googleapis.com", "https://jmt17.google.com"];
pub const MAX_SUBSCRIPTIONS: usize = 4;
pub const MAX_ENDPOINT_BYTES: usize = 1024;
/// Notices waiting to be sent. More than this are dropped.
pub const QUEUE: usize = 16;
/// At least this long between two rounds of notifications. What arrives in
/// between becomes one notification, so a looping agent cannot flood the phone.
pub const GAP: Duration = Duration::from_secs(3);
/// How long VAPID's proof of sender is valid. The standard allows a day.
const VAPID_LIFETIME_SECS: u64 = 3600;
const PUBLIC_KEY_BYTES: usize = 65;
const AUTH_BYTES: usize = 16;
/// One record holds the whole message.
const RECORD_SIZE: u32 = 4096;

/// Where one browser receives notifications. The address is a capability:
/// whoever has it and the keys can be sent to, so it is never logged or shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Subscription {
    endpoint: String,
    /// How much of the address is the push service's origin.
    origin_len: usize,
    p256dh: [u8; PUBLIC_KEY_BYTES],
    auth: [u8; AUTH_BYTES],
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subscription(..)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    endpoint: String,
    p256dh: String,
    auth: String,
}

impl Subscription {
    /// Accept a subscription only if its address is at one of `origins`, the
    /// push service Key-Box may call. Anything else would let whoever
    /// subscribes point Key-Box' own requests at an address of their choosing.
    pub fn new<S: AsRef<str>>(
        origins: &[S],
        endpoint: &str,
        p256dh: &[u8],
        auth: &[u8],
    ) -> Result<Self, &'static str> {
        let plain = |c: char| c.is_ascii_alphanumeric() || "-_.~:/=%".contains(c);
        let (origin, path) = origins
            .iter()
            .find_map(|origin| Some((origin.as_ref(), endpoint.strip_prefix(origin.as_ref())?)))
            .filter(|(_, path)| path.starts_with('/') && path.chars().all(plain))
            .ok_or("unsupported-push-service")?;
        if path.len() < 2 || endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err("unsupported-push-service");
        }
        let p256dh: [u8; PUBLIC_KEY_BYTES] = p256dh.try_into().map_err(|_| "malformed")?;
        let auth: [u8; AUTH_BYTES] = auth.try_into().map_err(|_| "malformed")?;
        // An uncompressed point on the curve.
        if p256dh[0] != 4 {
            return Err("malformed");
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            origin_len: origin.len(),
            p256dh,
            auth,
        })
    }

    pub fn is(&self, endpoint: &str) -> bool {
        self.endpoint == endpoint
    }

    /// What a passkey signs to accept this subscription, and (as hex) the
    /// name it goes by in the log and on the page. Says nothing of the address.
    pub fn mark(&self) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        for part in [self.endpoint.as_bytes(), &self.p256dh, &self.auth] {
            context.update(&(part.len() as u64).to_be_bytes());
            context.update(part);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(context.finish().as_ref());
        out
    }

    /// The push service this address is at.
    pub fn origin(&self) -> &str {
        self.endpoint.get(..self.origin_len).unwrap_or("")
    }

    /// The path of the address, to post to.
    fn path(&self) -> &str {
        self.endpoint.get(self.origin_len..).unwrap_or("/")
    }
}

/// The saved list as text, and back. An entry that is not at one of
/// `origins` is left out.
pub fn to_text(list: &[Subscription]) -> String {
    let stored: Vec<Stored> = list
        .iter()
        .map(|s| Stored {
            endpoint: s.endpoint.clone(),
            p256dh: base64url(&s.p256dh),
            auth: base64url(&s.auth),
        })
        .collect();
    serde_json::to_string(&stored).unwrap_or_else(|_| "[]".into())
}

pub fn from_text<S: AsRef<str>>(origins: &[S], text: &str) -> Vec<Subscription> {
    let stored: Vec<Stored> = serde_json::from_str(text).unwrap_or_default();
    stored
        .iter()
        .filter_map(|s| {
            let (p256dh, auth) = (base64url_decode(&s.p256dh)?, base64url_decode(&s.auth)?);
            Subscription::new(origins, &s.endpoint, &p256dh, &auth).ok()
        })
        .collect()
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn derive(salt: &[u8], secret: &[u8], info: &[&[u8]], out: &mut [u8]) -> Option<()> {
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(secret)
        .expand(info, Len(out.len()))
        .ok()?
        .fill(out)
        .ok()
}

/// RFC 8291, from the shared secret on: derive the keys and encrypt
/// `plaintext` as one `aes128gcm` record. `ua_public` is the browser's key,
/// `as_public` the one-time key this message was agreed with.
pub fn seal(
    shared: &[u8],
    auth: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: [u8; 16],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if plaintext.len() + 104 > RECORD_SIZE as usize {
        return None;
    }
    let mut ikm = Zeroizing::new([0u8; 32]);
    derive(
        auth,
        shared,
        &[b"WebPush: info\0", ua_public, as_public],
        ikm.as_mut(),
    )?;
    let mut key = Zeroizing::new([0u8; 16]);
    derive(
        &salt,
        ikm.as_ref(),
        &[b"Content-Encoding: aes128gcm\0"],
        key.as_mut(),
    )?;
    let mut nonce = [0u8; 12];
    derive(
        &salt,
        ikm.as_ref(),
        &[b"Content-Encoding: nonce\0"],
        &mut nonce,
    )?;

    // The message, then the mark of the last record.
    let mut record = plaintext.to_vec();
    record.push(2);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, key.as_ref()).ok()?);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut record,
    )
    .ok()?;

    let mut body = Vec::with_capacity(21 + as_public.len() + record.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(u8::try_from(as_public.len()).ok()?);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&record);
    Some(body)
}

/// Encrypt `plaintext` so that only the subscribed browser can read it. A
/// fresh key pair and salt for every message.
pub fn encrypt(to: &Subscription, plaintext: &[u8]) -> Option<Vec<u8>> {
    let rng = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&ECDH_P256, &rng).ok()?;
    let public = private.compute_public_key().ok()?;
    let salt = crate::random::<16>().ok()?;
    let peer = UnparsedPublicKey::new(&ECDH_P256, to.p256dh);
    agree_ephemeral(private, &peer, |shared| {
        seal(
            shared,
            &to.auth,
            &to.p256dh,
            public.as_ref(),
            salt,
            plaintext,
        )
    })
    .ok()?
}

/// The key that says a notification comes from this Key-Box. It is made
/// here and never leaves. No `Debug`; wiped on drop.
pub struct Vapid(Zeroizing<Vec<u8>>);

impl Vapid {
    pub fn generate() -> Option<Self> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .ok()?;
        Some(Self(Zeroizing::new(document.as_ref().to_vec())))
    }

    pub fn from_text(text: &str) -> Option<Self> {
        let key = Self(Zeroizing::new(base64url_decode(text)?));
        key.pair().map(|_| key)
    }

    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(base64url(&self.0))
    }

    fn pair(&self) -> Option<EcdsaKeyPair> {
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &self.0,
            &SystemRandom::new(),
        )
        .ok()
    }

    /// The public half, as the browser wants it when it subscribes.
    pub fn public(&self) -> Option<String> {
        Some(base64url(self.pair()?.public_key().as_ref()))
    }

    /// The `Authorization` header: a short-lived statement, signed with this
    /// key, that the sender is `subject` and the message is for `audience`.
    pub fn authorization(&self, now: u64, audience: &str, subject: &str) -> Option<String> {
        let pair = self.pair()?;
        let header = base64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = json!({ "aud": audience, "exp": now + VAPID_LIFETIME_SECS, "sub": subject });
        let signed = format!("{header}.{}", base64url(claims.to_string().as_bytes()));
        let signature = pair.sign(&SystemRandom::new(), signed.as_bytes()).ok()?;
        Some(format!(
            "vapid t={signed}.{}, k={}",
            base64url(signature.as_ref()),
            base64url(pair.public_key().as_ref())
        ))
    }
}

/// What one notification says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// A fixed word for the log.
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    /// A later notice with the same tag replaces the earlier one on the phone.
    pub tag: String,
    /// How long the push service keeps it for a phone that is offline.
    pub ttl_secs: u64,
}

impl Notice {
    /// A request is waiting for a passkey. Identifiers only; the agent's own
    /// text stays on the page, where it is labelled as the agent's.
    pub fn request(id: &RequestId, agent: &AgentId, level: Level, spec: &RequestSpec) -> Self {
        let level = match level {
            Level::One => 1,
            Level::Two => 2,
            Level::Three => 3,
        };
        Self {
            kind: "request",
            title: "Key-Box: godkendelse venter".into(),
            body: format!(
                "Niveau {level} · {} · {}\n{} · {agent}",
                spec.customer, spec.action, spec.target
            ),
            tag: id.to_string(),
            ttl_secs: keybox_core::engine::APPROVAL_WINDOW_SECS,
        }
    }

    pub fn policy(changes: usize) -> Self {
        Self {
            kind: "policy",
            title: "Key-Box: ny policy venter".into(),
            body: format!("{changes} ændringer venter på din godkendelse."),
            tag: "policy".into(),
            ttl_secs: 24 * 3600,
        }
    }

    /// Sent when a device is subscribed, so Christian sees that it works.
    pub fn enabled() -> Self {
        Self {
            kind: "enabled",
            title: "Key-Box".into(),
            body: "Notifikationer er slået til på denne enhed.".into(),
            tag: "enabled".into(),
            ttl_secs: 300,
        }
    }

    fn several(count: usize) -> Self {
        Self {
            kind: "several",
            title: format!("Key-Box: {count} ting venter på dig"),
            body: "Åbn Key-Box for at se dem.".into(),
            tag: "several".into(),
            ttl_secs: keybox_core::engine::APPROVAL_WINDOW_SECS,
        }
    }

    fn json(&self) -> String {
        json!({ "title": self.title, "body": self.body, "tag": self.tag }).to_string()
    }
}

/// Host and port of an `https://host[:port]` origin.
fn host_port(origin: &str) -> Option<(&str, u16)> {
    let host = origin.strip_prefix("https://")?;
    match host.split_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((host, 443)),
    }
}

enum Sent {
    Ok,
    /// The push service says the subscription no longer exists.
    Gone,
    Failed,
}

async fn post(
    client: &HttpsClient,
    authorization: &str,
    to: &Subscription,
    notice: &Notice,
) -> Sent {
    let (Some((host, port)), Some(body)) = (
        host_port(to.origin()),
        encrypt(to, notice.json().as_bytes()),
    ) else {
        return Sent::Failed;
    };
    let ttl = notice.ttl_secs.to_string();
    let headers = [
        ("authorization", authorization),
        ("ttl", ttl.as_str()),
        ("urgency", "high"),
        ("content-encoding", "aes128gcm"),
        ("content-type", "application/octet-stream"),
    ];
    match client
        .send(host, port, Method::POST, to.path(), &headers, body)
        .await
    {
        Ok((200..=299, _)) => Sent::Ok,
        Ok((404 | 410, _)) => Sent::Gone,
        _ => Sent::Failed,
    }
}

/// Send what `Core` queues, for as long as Key-Box runs. Done outside the
/// lock: a slow push service must not stall an approval.
pub async fn run(
    mut notices: mpsc::Receiver<Notice>,
    core: Arc<Mutex<Core>>,
    client: HttpsClient,
    gap: Duration,
) {
    while let Some(mut notice) = notices.recv().await {
        let mut count = 1;
        while let Ok(next) = notices.try_recv() {
            notice = next;
            count += 1;
        }
        if count > 1 {
            notice = Notice::several(count);
        }
        let now = crate::now();
        let Ok(devices) = core.lock().map(|mut core| core.push_targets(now)) else {
            continue;
        };
        if devices.is_empty() {
            continue;
        }
        let (mut sent, mut failed, mut gone) = (0u64, 0u64, Vec::new());
        for (device, authorization) in &devices {
            let Some(authorization) = authorization else {
                failed += 1;
                continue;
            };
            match post(&client, authorization, device, &notice).await {
                Sent::Ok => sent += 1,
                Sent::Gone => gone.push(device.clone()),
                Sent::Failed => failed += 1,
            }
        }
        if let Ok(mut core) = core.lock() {
            core.push_done(crate::now(), notice.kind, sent, failed, &gone);
        }
        tokio::time::sleep(gap).await;
    }
}

/// Look at the policy files now and then, and say so once when a new
/// proposal is waiting.
pub async fn watch_policy(core: Arc<Mutex<Core>>, every: Duration) {
    let mut announced = None;
    loop {
        if let Ok(core) = core.lock()
            && let crate::policy::Proposal::Pending { hash, changes, .. } = core.proposal()
            && announced != Some(hash)
        {
            announced = Some(hash);
            core.notify(Notice::policy(changes.len()));
        }
        tokio::time::sleep(every).await;
    }
}
