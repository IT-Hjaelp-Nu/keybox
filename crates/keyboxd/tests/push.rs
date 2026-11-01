//! Notifications: who can subscribe a browser, where Key-Box will post, and
//! what a notification says. The push service is a stand-in on localhost
//! that keeps what it was sent; the "phone" decrypts it the way a browser would.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Authenticator, Box, READ, RESTART, TIMEOUT, block_on, id_of};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use keybox_webauthn::{base64url, base64url_decode};
use keyboxd::https::HttpsClient;
use keyboxd::pki;
use keyboxd::push::{self, Subscription};
use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey as VerifyKey};
use ring::{aead, hkdf};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};

fn unb64(text: &str) -> Vec<u8> {
    base64url_decode(text).unwrap()
}

// ------------------------------------------------------------- encryption

/// The worked example in RFC 8291, section 5 and appendix A.
#[test]
fn encryption_matches_the_example_in_the_standard() {
    let body = push::seal(
        &unb64("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"),
        &unb64("BTBZMqHH6r4Tts7J_aSIgg"),
        &unb64(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        ),
        &unb64(
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
        ),
        unb64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap(),
        b"When I grow up, I want to be a watermelon",
    )
    .unwrap();
    assert_eq!(
        base64url(&body),
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS\
         6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Q\
         ulcy4a-fN"
    );
}

// ------------------------------------------------------------ the "phone"

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn derive(salt: &[u8], secret: &[u8], info: &[&[u8]], out: &mut [u8]) {
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(secret)
        .expand(info, Len(out.len()))
        .unwrap()
        .fill(out)
        .unwrap();
}

/// A browser's side of a subscription. Its key can decrypt one message.
struct Device {
    private: EphemeralPrivateKey,
    public: Vec<u8>,
    auth: [u8; 16],
    endpoint: String,
}

impl Device {
    fn new(port: u16, name: &str) -> Self {
        let private = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()).unwrap();
        let public = private.compute_public_key().unwrap().as_ref().to_vec();
        Self {
            private,
            public,
            auth: keyboxd::random().unwrap(),
            endpoint: format!("https://localhost:{port}/fcm/send/{name}:APA91b-SECRET_{name}"),
        }
    }

    fn subscription(&self) -> Value {
        json!({
            "endpoint": self.endpoint,
            "p256dh": base64url(&self.public),
            "auth": base64url(&self.auth),
        })
    }

    /// Decrypt a message the way a browser does (RFC 8291).
    fn open(self, body: &[u8]) -> Value {
        let (salt, rest) = body.split_at(16);
        assert_eq!(rest[..4], 4096u32.to_be_bytes());
        assert_eq!(rest[4], 65);
        let (sender, sealed) = rest[5..].split_at(65);
        let mut ikm = [0u8; 32];
        let peer = UnparsedPublicKey::new(&ECDH_P256, sender);
        agree_ephemeral(self.private, &peer, |shared| {
            let info: [&[u8]; 3] = [b"WebPush: info\0", &self.public, sender];
            derive(&self.auth, shared, &info, &mut ikm);
        })
        .unwrap();
        let (mut key, mut nonce) = ([0u8; 16], [0u8; 12]);
        derive(salt, &ikm, &[b"Content-Encoding: aes128gcm\0"], &mut key);
        derive(salt, &ikm, &[b"Content-Encoding: nonce\0"], &mut nonce);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        let mut sealed = sealed.to_vec();
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut sealed,
            )
            .unwrap();
        assert_eq!(plain.last(), Some(&2), "last-record mark");
        serde_json::from_slice(&plain[..plain.len() - 1]).unwrap()
    }
}

// ------------------------------------------------------ the push service

#[derive(Clone)]
struct Post {
    path: String,
    authorization: String,
    ttl: String,
    encoding: String,
    body: Vec<u8>,
}

type Posts = Arc<Mutex<Vec<Post>>>;

async fn answer(
    req: Request<Incoming>,
    status: u16,
    posts: Posts,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let header = |name: &str| {
        let value = req.headers().get(name).and_then(|v| v.to_str().ok());
        value.unwrap_or("").to_owned()
    };
    let mut post = Post {
        path: req.uri().path().to_owned(),
        authorization: header("authorization"),
        ttl: header("ttl"),
        encoding: header("content-encoding"),
        body: Vec::new(),
    };
    post.body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
    posts.lock().unwrap().push(post);
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    Ok(response)
}

/// A stand-in push service that answers every post with `status`.
async fn service(b: &Box, status: u16) -> (u16, Posts) {
    let cert = CertificateDer::from_pem_file(b.dir.join(pki::SERVER_CERT)).unwrap();
    let key = PrivateKeyDer::from_pem_file(b.dir.join(pki::SERVER_KEY)).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts: Posts = Arc::default();
    let seen = posts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (acceptor, posts) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |req| answer(req, status, posts.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, posts)
}

// -------------------------------------------------------------- the rig

struct Rig {
    b: Box,
    agents: SocketAddr,
    web: SocketAddr,
    phone: Authenticator,
    port: u16,
    posts: Posts,
}

/// A running Key-Box with one passkey, whose push service is the stand-in.
async fn rig(name: &str, status: u16) -> Rig {
    let b = Box::new(name);
    let (port, posts) = service(&b, status).await;
    let mut core = b.core();
    let (notices, queue) = tokio::sync::mpsc::channel(push::QUEUE);
    {
        let core = Arc::get_mut(&mut core).unwrap().get_mut().unwrap();
        core.min_passkeys = 1;
        core.push_origins = vec![format!("https://localhost:{port}")];
        core.notices = Some(notices);
        core.policy_dir = Some(b.dir.join("policy.d"));
    }
    std::fs::create_dir_all(b.dir.join("policy.d")).unwrap();
    std::fs::write(b.dir.join("policy.d/test.toml"), common::POLICY).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(b.dir.join(pki::CA_CERT)).unwrap())
        .unwrap();
    let client = HttpsClient::new(roots, Duration::from_millis(1500)).unwrap();
    tokio::spawn(push::run(
        queue,
        core.clone(),
        client,
        Duration::from_millis(150),
    ));
    tokio::spawn(push::watch_policy(core.clone(), Duration::from_millis(40)));
    let agents = b.start_agents(core.clone(), TIMEOUT).await;
    let web = b.start_web(core, TIMEOUT).await;
    let phone = Authenticator::new("phone");
    b.enroll(web, "phone", &phone).await;
    Rig {
        b,
        agents,
        web,
        phone,
        port,
        posts,
    }
}

impl Rig {
    async fn page(&self) -> String {
        self.b.get(self.web, "/").await.2
    }

    async fn start(&self, subscription: &Value) -> (u16, Value) {
        let start = json!({"purpose": "notify", "request": null, "subscription": subscription});
        self.b.post(self.web, "/api/assert/start", &start).await
    }

    /// Subscribe `device` the way the page does: its subscription, then a passkey.
    async fn subscribe(&self, device: &Device) -> u16 {
        let (status, start) = self.start(&device.subscription()).await;
        assert_eq!(status, 200, "{start}");
        let mut finish = self.phone.get(start["challenge"].as_str().unwrap());
        finish["challenge_id"] = start["challenge_id"].clone();
        self.b.post(self.web, "/api/assert/finish", &finish).await.0
    }

    /// Wait until the push service has been posted to `count` times.
    async fn posts(&self, count: usize) -> Vec<Post> {
        for _ in 0..200 {
            let posts = self.posts.lock().unwrap().clone();
            if posts.len() >= count {
                return posts;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "expected {count} posts, saw {}",
            self.posts.lock().unwrap().len()
        );
    }

    /// Give anything that should not happen time to happen.
    async fn settled(&self) -> usize {
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.posts.lock().unwrap().len()
    }
}

fn error(reply: &(u16, Value)) -> (u16, &str) {
    (reply.0, reply.1["error"].as_str().unwrap_or(""))
}

fn key_on(page: &str) -> Vec<u8> {
    let at = page.find("data-key=\"").expect("the page offers a key") + 10;
    unb64(&page[at..at + page[at..].find('"').unwrap()])
}

// ---------------------------------------------------------------- tests

#[test]
fn subscribing_takes_a_passkey_and_the_first_notification_proves_it_works() {
    block_on(async {
        let r = rig("push-subscribe", 201).await;
        let page = r.page().await;
        assert!(page.contains("Slået fra."), "{page}");
        let key = key_on(&page);
        assert!(key.len() == 65 && key[0] == 4);

        let device = Device::new(r.port, "phone");
        // Asking is not enough: nothing is stored and nothing is sent.
        assert_eq!(r.start(&device.subscription()).await.0, 200);
        assert_eq!(r.settled().await, 0);
        assert!(r.page().await.contains("Slået fra."));
        // A prompt for something else does not subscribe either.
        let stop =
            json!({"purpose": "stop", "request": null, "subscription": device.subscription()});
        let (_, start) = r.b.post(r.web, "/api/assert/start", &stop).await;
        let mut finish = r.phone.get(start["challenge"].as_str().unwrap());
        finish["challenge_id"] = start["challenge_id"].clone();
        assert_eq!(r.b.post(r.web, "/api/assert/finish", &finish).await.0, 200);
        assert!(r.page().await.contains("Slået fra."));
        let resume = json!({"purpose": "resume", "request": null});
        let (_, start) = r.b.post(r.web, "/api/assert/start", &resume).await;
        let mut finish = r.phone.get(start["challenge"].as_str().unwrap());
        finish["challenge_id"] = start["challenge_id"].clone();
        assert_eq!(r.b.post(r.web, "/api/assert/finish", &finish).await.0, 200);

        assert_eq!(r.subscribe(&device).await, 200);
        assert!(r.page().await.contains("Slået til på 1 enhed."));
        // The same device again is still one device.
        assert_eq!(r.subscribe(&device).await, 200);
        assert!(r.page().await.contains("Slået til på 1 enhed."));

        let post = r.posts(1).await.remove(0);
        assert_eq!(post.path, "/fcm/send/phone:APA91b-SECRET_phone");
        assert_eq!(
            (post.ttl.as_str(), post.encoding.as_str()),
            ("300", "aes128gcm")
        );

        // Signed as this Key-Box, for this push service, for a short while.
        let (token, sender) = post
            .authorization
            .strip_prefix("vapid t=")
            .and_then(|rest| rest.split_once(", k="))
            .expect("a VAPID header");
        assert_eq!(unb64(sender), key);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        VerifyKey::new(&ECDSA_P256_SHA256_FIXED, &key)
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &unb64(parts[2]),
            )
            .expect("signed with the key on the page");
        let claims: Value = serde_json::from_slice(&unb64(parts[1])).unwrap();
        let now = keyboxd::now();
        assert_eq!(claims["aud"], format!("https://localhost:{}", r.port));
        let exp = claims["exp"].as_u64().unwrap();
        assert!(exp > now && exp <= now + 24 * 3600, "{claims}");

        // Only the phone can read it.
        let note = device.open(&post.body);
        assert_eq!(note["title"], "Key-Box");
        assert!(note["body"].as_str().unwrap().contains("slået til"));

        let log = r.b.log_text();
        assert!(log.contains(r#""kind":"notify-on""#) && log.contains(r#""kind":"notified""#));
        assert!(
            !log.contains("APA91b") && !log.contains("fcm/send"),
            "{log}"
        );
    });
}

#[test]
fn key_box_posts_only_to_the_one_push_service() {
    block_on(async {
        let r = rig("push-origin", 201).await;
        let good = Device::new(r.port, "phone");
        let at = |endpoint: String| {
            let mut s = good.subscription();
            s["endpoint"] = json!(endpoint);
            s
        };
        for endpoint in [
            "https://evil.example/fcm/send/x".to_owned(),
            format!("http://localhost:{}/fcm/send/x", r.port),
            format!("https://localhost:{}.evil.example/fcm/send/x", r.port),
            format!("https://localhost:{}@evil.example/fcm/send/x", r.port),
            format!("https://localhost:{}", r.port),
            format!("https://localhost:{}/", r.port),
            format!("https://localhost:{}/a?b=c", r.port),
            format!("https://localhost:{}/a b", r.port),
            format!("https://localhost:{}/{}", r.port, "a".repeat(1100)),
            "https://fcm.googleapis.com/fcm/send/x".to_owned(),
            "https://jmt17.google.com/fcm/send/x".to_owned(),
        ] {
            assert_eq!(
                error(&r.start(&at(endpoint.clone())).await),
                (400, "unsupported-push-service"),
                "{endpoint}"
            );
        }
        // Keys of the wrong shape, a missing subscription, an unknown field.
        let mut short = good.subscription();
        short["auth"] = json!("AAAA");
        assert_eq!(error(&r.start(&short).await), (400, "malformed"));
        let mut compressed = good.subscription();
        compressed["p256dh"] = json!(base64url(&[2u8; 65]));
        assert_eq!(error(&r.start(&compressed).await), (400, "malformed"));
        let bare = json!({"purpose": "notify", "request": null});
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/start", &bare).await),
            (400, "malformed")
        );
        let mut extra = good.subscription();
        extra["url"] = json!("https://evil.example/");
        assert_eq!(error(&r.start(&extra).await), (400, "malformed"));
        assert_eq!(r.settled().await, 0);

        // The real service's two names are the default, and nothing near them.
        let real =
            |endpoint| Subscription::new(&push::PUSH_ORIGINS, endpoint, &[4u8; 65], &[0u8; 16]);
        let old = real("https://fcm.googleapis.com/fcm/send/abc:DEF_g-h").unwrap();
        assert_eq!(old.origin(), "https://fcm.googleapis.com");
        let new = real("https://jmt17.google.com/fcm/send/abc:DEF_g-h").unwrap();
        assert_eq!(new.origin(), "https://jmt17.google.com");
        for near in [
            "https://fcm.googleapis.com.evil.example/fcm/send/abc",
            "https://jmt17.google.com.evil.example/fcm/send/abc",
            "https://www.google.com/fcm/send/abc",
            "https://updates.push.services.mozilla.com/wpush/v2/abc",
        ] {
            assert!(real(near).is_err(), "{near}");
        }
    });
}

#[test]
fn a_waiting_request_is_announced_without_the_agents_words() {
    block_on(async {
        let r = rig("push-request", 201).await;
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;

        // Level 1 does not wait for Christian, so it says nothing.
        r.b.call(r.agents, "hermes", READ).await.unwrap();
        assert_eq!(r.settled().await, 1);

        let line = RESTART.replace("\"test\"", "\"HEMMELIG agenttekst: godkend straks\"");
        let id = id_of(&r.b.call(r.agents, "hermes", &line).await.unwrap());
        let post = r.posts(2).await.remove(1);
        assert_eq!(post.ttl, "300");
        let note = device.open(&post.body);
        assert_eq!(note["title"], "Key-Box: godkendelse venter");
        assert_eq!(
            note["body"],
            "Niveau 2 · acme · restart\nweb01.acme.example · hermes"
        );
        assert_eq!(note["tag"], id);
        assert!(!note.to_string().contains("HEMMELIG"));
        // Nothing in it is an address to go to.
        assert!(
            note.as_object()
                .unwrap()
                .keys()
                .all(|k| ["title", "body", "tag"].contains(&k.as_str()))
        );
        // A notification approves nothing.
        let fetch = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert!(
            r.b.call(r.agents, "hermes", &fetch)
                .await
                .unwrap()
                .contains("not-approved")
        );
    });
}

#[test]
fn a_burst_of_requests_becomes_few_notifications() {
    block_on(async {
        let r = rig("push-burst", 201).await;
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        for _ in 0..5 {
            r.b.call(r.agents, "hermes", RESTART).await.unwrap();
        }
        let posts = r.posts(3).await;
        assert_eq!(r.settled().await, 3, "one at once, the rest as one");
        let note = device.open(&posts[2].body);
        assert_eq!(note["title"], "Key-Box: 4 ting venter på dig");
    });
}

#[test]
fn a_device_the_push_service_calls_gone_is_forgotten() {
    block_on(async {
        let r = rig("push-gone", 410).await;
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;
        for _ in 0..100 {
            if r.page().await.contains("Slået fra.") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(r.page().await.contains("Slået fra."));
        let log = r.b.log_text();
        assert!(log.contains(r#""by":"push-service""#), "{log}");
        // With nobody to tell, nothing is posted.
        r.b.call(r.agents, "hermes", RESTART).await.unwrap();
        assert_eq!(r.settled().await, 1);
    });
}

#[test]
fn a_push_service_that_fails_stops_nothing() {
    block_on(async {
        let r = rig("push-fails", 500).await;
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;
        let id = id_of(&r.b.call(r.agents, "hermes", RESTART).await.unwrap());
        r.posts(2).await;
        assert!(r.page().await.contains(&id) && r.page().await.contains("Slået til på 1 enhed."));
        for _ in 0..100 {
            if r.b.log_text().contains(r#""failed":1"#) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the failure is not in the log: {}", r.b.log_text());
    });
}

#[test]
fn only_the_device_itself_can_be_switched_off_without_a_passkey() {
    block_on(async {
        let r = rig("push-off", 201).await;
        let (phone, tablet) = (Device::new(r.port, "phone"), Device::new(r.port, "tablet"));
        assert_eq!(r.subscribe(&phone).await, 200);
        assert_eq!(r.subscribe(&tablet).await, 200);
        assert!(r.page().await.contains("Slået til på 2 enheder."));

        let guess = json!({"endpoint": format!("https://localhost:{}/fcm/send/guess", r.port)});
        assert_eq!(
            error(&r.b.post(r.web, "/api/notify/off", &guess).await),
            (404, "unknown-subscription")
        );
        let off = json!({"endpoint": phone.endpoint});
        assert_eq!(r.b.post(r.web, "/api/notify/off", &off).await.0, 200);
        assert_eq!(
            error(&r.b.post(r.web, "/api/notify/off", &off).await),
            (404, "unknown-subscription")
        );
        assert!(r.page().await.contains("Slået til på 1 enhed."));

        // The page never gives the addresses away, only marks.
        let page = r.page().await;
        assert!(
            !page.contains("fcm/send") && !page.contains("APA91b"),
            "{page}"
        );
        // At most a handful of devices; the oldest gives way.
        for n in 0..6 {
            assert_eq!(
                r.subscribe(&Device::new(r.port, &format!("d{n}"))).await,
                200
            );
        }
        assert!(r.page().await.contains("Slået til på 4 enheder."));
    });
}

#[test]
fn a_new_policy_proposal_is_announced_once() {
    block_on(async {
        let r = rig("push-policy", 201).await;
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;
        assert_eq!(r.settled().await, 1, "the policy in force is no proposal");

        let changed = common::POLICY.replace("level = 3", "level = 2");
        std::fs::write(r.b.dir.join("policy.d/test.toml"), changed).unwrap();
        let post = r.posts(2).await.remove(1);
        assert_eq!(post.ttl, "86400");
        let note = device.open(&post.body);
        assert_eq!(note["title"], "Key-Box: ny policy venter");
        assert_eq!(note["body"], "1 ændringer venter på din godkendelse.");
        assert_eq!(
            r.settled().await,
            2,
            "said once, not every time it is looked at"
        );
    });
}

#[test]
fn the_worker_is_served_and_subscriptions_are_kept_on_disk() {
    block_on(async {
        let r = rig("push-worker", 201).await;
        let (status, headers, script) = r.b.get(r.web, "/sw.js").await;
        assert!(
            status == 200 && headers.contains("text/javascript"),
            "{headers}"
        );
        assert!(headers.contains("worker-src 'self'"));
        assert!(script.contains("showNotification") && !script.contains("\"fetch\""));
        // The worker opens Key-Box' own page and nothing a message names.
        assert!(script.contains("openWindow(\"/\")"));

        let key = key_on(&r.page().await);
        let device = Device::new(r.port, "phone");
        assert_eq!(r.subscribe(&device).await, 200);
        r.posts(1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Both are on disk, so they are still there after a restart.
        let store = keyboxd::store::Store::open(&r.b.dir).unwrap();
        let saved = push::Vapid::from_text(&store.meta("push-key").unwrap().unwrap()).unwrap();
        assert_eq!(unb64(&saved.public().unwrap()), key);
        let origin = [format!("https://localhost:{}", r.port)];
        let devices = store.meta("push-subscriptions").unwrap().unwrap();
        assert_eq!(push::from_text(&origin, &devices).len(), 1);
        // Read back for another push service, the address is not used.
        assert!(push::from_text(&push::PUSH_ORIGINS, &devices).is_empty());
    });
}
