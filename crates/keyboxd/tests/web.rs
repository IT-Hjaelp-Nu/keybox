//! The approval page, end to end: an agent asks over mTLS, Christian answers
//! over HTTPS with a (software) passkey, and nothing else moves a request.

mod common;

use std::net::SocketAddr;

use common::{Authenticator, Box, ORIGIN, READ, RESTART, TIMEOUT, WIPE, block_on, id_of};
use keyboxd::passkeys::{TOKEN_TTL_SECS, new_token};
use serde_json::{Value, json};

/// A running Key-Box with both listeners and two registered passkeys.
struct Rig {
    b: Box,
    agents: SocketAddr,
    web: SocketAddr,
    phone: Authenticator,
    yubikey: Authenticator,
}

async fn rig(name: &str) -> Rig {
    let b = Box::new(name);
    let core = b.core();
    let agents = b.start_agents(core.clone(), TIMEOUT).await;
    let web = b.start_web(core, TIMEOUT).await;
    let (phone, yubikey) = (Authenticator::new("phone"), Authenticator::new("yubikey"));
    b.enroll(web, "phone", &phone).await;
    b.enroll(web, "yubikey", &yubikey).await;
    Rig {
        b,
        agents,
        web,
        phone,
        yubikey,
    }
}

impl Rig {
    /// The agent asks; returns the request id.
    async fn ask(&self, line: &str) -> String {
        id_of(&self.b.call(self.agents, "hermes", line).await.unwrap())
    }

    async fn fetch(&self, id: &str) -> String {
        let line = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        self.b.call(self.agents, "hermes", &line).await.unwrap()
    }

    async fn page(&self) -> String {
        self.b.get(self.web, "/").await.2
    }
}

/// What `fetch` answers once the engine has released the access. (The
/// issuers are not built yet, so this is as far as an approval can go.)
const RELEASED: &str = r#"{"error":"issuer-unavailable","ok":false}"#;
const NOT_APPROVED: &str = r#"{"error":"not-approved","ok":false}"#;

fn error(reply: &(u16, Value)) -> (u16, &str) {
    (reply.0, reply.1["error"].as_str().unwrap_or(""))
}

// ----------------------------------------------------------------- set-up

#[test]
fn the_first_passkey_needs_the_console_token() {
    let b = Box::new("token");
    block_on(async {
        let web = b.start_web(b.core(), TIMEOUT).await;
        let start = |token: Value| {
            let b = &b;
            async move {
                b.post(
                    web,
                    "/api/register/start",
                    &json!({"name": "phone", "token": token}),
                )
                .await
            }
        };
        assert_eq!(error(&start(Value::Null).await), (403, "not-authorized"));
        assert_eq!(error(&start(json!("guess")).await), (403, "not-authorized"));

        let token = new_token(&b.dir, keyboxd::now()).unwrap();
        assert_eq!(error(&start(json!("guess")).await), (403, "not-authorized"));
        let (status, begun) = start(json!(token)).await;
        assert_eq!(status, 200, "{begun}");
        // The token is used up, whether or not the registration is completed.
        assert_eq!(error(&start(json!(token)).await), (403, "not-authorized"));

        let phone = Authenticator::new("phone");
        let mut finish = phone.create(begun["challenge"].as_str().unwrap());
        finish["challenge_id"] = begun["challenge_id"].clone();
        let (status, done) = b.post(web, "/api/register/finish", &finish).await;
        assert_eq!((status, done["name"].as_str()), (200, Some("phone")));
        // A registration answer cannot be replayed.
        assert_eq!(
            error(&b.post(web, "/api/register/finish", &finish).await),
            (403, "challenge")
        );

        // A token past its ten minutes is refused.
        let old = new_token(&b.dir, keyboxd::now() - TOKEN_TTL_SECS - 1).unwrap();
        let again = b
            .post(
                web,
                "/api/register/start",
                &json!({"name": "spare", "token": old}),
            )
            .await;
        assert_eq!(error(&again), (403, "not-authorized"));
    });
    let log = b.log_text();
    assert!(log.contains(r#""kind":"passkey-added""#) && log.contains(r#""by":"console-token""#));
    // The token itself is never stored or logged.
    assert!(log.contains("register-refused") && !log.contains("guess"));
}

#[test]
fn registration_is_checked_like_any_passkey_answer() {
    let b = Box::new("badreg");
    block_on(async {
        let web = b.start_web(b.core(), TIMEOUT).await;
        for (case, want) in [
            ("origin", "wrong-origin"),
            ("rp", "wrong-rp-id"),
            ("uv", "user-not-verified"),
        ] {
            let mut auth = Authenticator::new("x");
            match case {
                "origin" => auth.origin = "https://evil.example".into(),
                "rp" => auth.rp_id = "evil.example".into(),
                _ => auth.uv = false,
            }
            let token = new_token(&b.dir, keyboxd::now()).unwrap();
            let (_, begun) = b
                .post(
                    web,
                    "/api/register/start",
                    &json!({"name": "phone", "token": token}),
                )
                .await;
            let mut finish = auth.create(begun["challenge"].as_str().unwrap());
            finish["challenge_id"] = begun["challenge_id"].clone();
            assert_eq!(
                error(&b.post(web, "/api/register/finish", &finish).await),
                (403, want)
            );
        }
        assert!(b.get(web, "/").await.2.contains("0 af 2 passkeys"));
    });
}

#[test]
fn agents_are_refused_until_two_passkeys_exist() {
    let b = Box::new("setup");
    block_on(async {
        let core = b.core();
        let agents = b.start_agents(core.clone(), TIMEOUT).await;
        let web = b.start_web(core, TIMEOUT).await;
        let not_set_up = r#"{"error":"not-set-up","ok":false}"#;
        assert_eq!(b.call(agents, "hermes", READ).await.unwrap(), not_set_up);
        b.enroll(web, "phone", &Authenticator::new("phone")).await;
        assert_eq!(b.call(agents, "hermes", READ).await.unwrap(), not_set_up);
        assert!(b.get(web, "/").await.2.contains("1 af 2 passkeys"));
        b.enroll(web, "yubikey", &Authenticator::new("yubikey"))
            .await;
        assert!(
            b.call(agents, "hermes", READ)
                .await
                .unwrap()
                .contains(r#""ok":true"#)
        );
        assert!(b.get(web, "/").await.2.contains("Key-Box kører."));
    });
}

#[test]
fn a_passkey_cannot_add_another_passkey() {
    block_on(async {
        let r = rig("add").await;
        // There is no prompt for it at all.
        let start = json!({"purpose": "add-passkey", "request": null});
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/start", &start).await),
            (400, "invalid-purpose")
        );
        // And nothing a passkey can sign opens registration.
        assert_eq!(r.b.sign(r.web, &r.phone, "stop", None).await.0, 200);
        assert_eq!(r.b.sign(r.web, &r.phone, "resume", None).await.0, 200);
        for token in [Value::Null, json!("guess"), json!("")] {
            let out =
                r.b.post(
                    r.web,
                    "/api/register/start",
                    &json!({"name": "spare", "token": token}),
                )
                .await;
            assert_eq!(error(&out), (403, "not-authorized"));
        }
        assert!(!r.page().await.contains("kræver en eksisterende"));

        // Only the console token does, and a name can be taken once.
        let token = new_token(&r.b.dir, keyboxd::now()).unwrap();
        let (status, begun) =
            r.b.post(
                r.web,
                "/api/register/start",
                &json!({"name": "spare", "token": token}),
            )
            .await;
        assert_eq!(status, 200, "{begun}");
        let spare = Authenticator::new("spare");
        let mut finish = spare.create(begun["challenge"].as_str().unwrap());
        finish["challenge_id"] = begun["challenge_id"].clone();
        assert_eq!(
            r.b.post(r.web, "/api/register/finish", &finish).await.0,
            200
        );
        assert!(r.page().await.contains("<li>spare</li>"));
        let token = new_token(&r.b.dir, keyboxd::now()).unwrap();
        let dup =
            r.b.post(
                r.web,
                "/api/register/start",
                &json!({"name": "spare", "token": token}),
            )
            .await;
        assert_eq!(error(&dup), (409, "name-taken"));
    });
}

#[test]
fn two_registrations_started_together_cannot_share_a_name() {
    block_on(async {
        let b = Box::new("samename");
        let web = b.start_web(b.core(), TIMEOUT).await;
        let mut begun = Vec::new();
        for _ in 0..2 {
            let token = new_token(&b.dir, keyboxd::now()).unwrap();
            let (status, start) = b
                .post(
                    web,
                    "/api/register/start",
                    &json!({"name": "phone", "token": token}),
                )
                .await;
            assert_eq!(status, 200, "{start}");
            begun.push(start);
        }
        let finish = |start: &Value, auth: Authenticator| {
            let mut f = auth.create(start["challenge"].as_str().unwrap());
            f["challenge_id"] = start["challenge_id"].clone();
            f
        };
        let first = finish(&begun[0], Authenticator::new("one"));
        let second = finish(&begun[1], Authenticator::new("two"));
        assert_eq!(b.post(web, "/api/register/finish", &first).await.0, 200);
        assert_eq!(
            error(&b.post(web, "/api/register/finish", &second).await),
            (409, "name-taken")
        );
    });
}

// --------------------------------------------------------------- approval

#[test]
fn a_passkey_approval_releases_exactly_that_request() {
    block_on(async {
        let r = rig("approve").await;
        let (a, b) = (r.ask(RESTART).await, r.ask(RESTART).await);
        assert_eq!(r.fetch(&a).await, NOT_APPROVED);

        let (status, done) = r.b.sign(r.web, &r.phone, "approve", Some(&a)).await;
        assert_eq!((status, done["done"].as_str()), (200, Some("approve")));

        assert_eq!(r.fetch(&b).await, NOT_APPROVED);
        assert_eq!(r.fetch(&a).await, RELEASED);
        // The approval is spent: neither a second fetch nor a second approval works.
        assert_eq!(r.fetch(&a).await, r#"{"error":"closed","ok":false}"#);
        assert_eq!(
            error(&r.b.sign(r.web, &r.phone, "approve", Some(&a)).await),
            (404, "unknown-request")
        );

        let log = r.b.log_text();
        assert!(
            log.contains(r#""kind":"passkey-verified""#) && log.contains(r#""credential":"phone""#)
        );
        assert!(keybox_log::verify(&r.b.log()).is_ok());
    });
}

#[test]
fn an_answer_cannot_be_replayed_or_moved_to_another_request() {
    block_on(async {
        let r = rig("replay").await;
        let (a, b) = (r.ask(RESTART).await, r.ask(RESTART).await);
        let start = |id: String| {
            let r = &r;
            async move {
                r.b.post(
                    r.web,
                    "/api/assert/start",
                    &json!({"purpose": "approve", "request": id}),
                )
                .await
                .1
            }
        };
        let (for_a, for_b) = (start(a.clone()).await, start(b.clone()).await);
        assert_ne!(for_a["challenge"], for_b["challenge"]);

        // A genuine signature over B's challenge, sent as the answer for A.
        let mut moved = r.phone.get(for_b["challenge"].as_str().unwrap());
        moved["challenge_id"] = for_a["challenge_id"].clone();
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/finish", &moved).await),
            (403, "wrong-challenge")
        );
        assert_eq!(r.fetch(&a).await, NOT_APPROVED);
        assert_eq!(r.fetch(&b).await, NOT_APPROVED);

        // A's challenge was used up by the failed attempt.
        let mut late = r.phone.get(for_a["challenge"].as_str().unwrap());
        late["challenge_id"] = for_a["challenge_id"].clone();
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/finish", &late).await),
            (403, "challenge")
        );

        // B's own answer works once, and only once.
        let mut good = r.phone.get(for_b["challenge"].as_str().unwrap());
        good["challenge_id"] = for_b["challenge_id"].clone();
        assert_eq!(r.b.post(r.web, "/api/assert/finish", &good).await.0, 200);
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/finish", &good).await),
            (403, "challenge")
        );
        assert_eq!(r.fetch(&a).await, NOT_APPROVED);
        assert_eq!(r.fetch(&b).await, RELEASED);
    });
}

#[test]
fn only_a_registered_passkey_with_user_verification_on_our_site_counts() {
    block_on(async {
        let r = rig("badsig").await;
        let a = r.ask(RESTART).await;

        let stranger = Authenticator::new("stranger");
        assert_eq!(
            error(&r.b.sign(r.web, &stranger, "approve", Some(&a)).await),
            (403, "unknown-passkey")
        );

        // Same credential id as the phone, different key.
        let mut forged = Authenticator::new("phone");
        forged.id = r.phone.id.clone();
        assert_eq!(
            error(&r.b.sign(r.web, &forged, "approve", Some(&a)).await),
            (403, "bad-signature")
        );

        assert_eq!(r.fetch(&a).await, NOT_APPROVED);
        let log = r.b.log_text();
        assert!(
            log.contains(r#""why":"unknown-passkey""#) && log.contains(r#""why":"bad-signature""#)
        );
    });
}

#[test]
fn phishing_and_missing_biometrics_are_refused() {
    block_on(async {
        let b = Box::new("phish-web");
        let core = b.core();
        let agents = b.start_agents(core.clone(), TIMEOUT).await;
        let web = b.start_web(core, TIMEOUT).await;
        let mut phone = Authenticator::new("phone");
        b.enroll(web, "phone", &phone).await;
        b.enroll(web, "yubikey", &Authenticator::new("yubikey"))
            .await;
        let id = id_of(&b.call(agents, "hermes", RESTART).await.unwrap());

        phone.origin = "https://keybox.evil.example".into();
        assert_eq!(
            error(&b.sign(web, &phone, "approve", Some(&id)).await),
            (403, "wrong-origin")
        );
        phone.origin = ORIGIN.into();
        phone.rp_id = "evil.example".into();
        assert_eq!(
            error(&b.sign(web, &phone, "approve", Some(&id)).await),
            (403, "wrong-rp-id")
        );
        phone.rp_id = "localhost".into();
        phone.uv = false;
        assert_eq!(
            error(&b.sign(web, &phone, "approve", Some(&id)).await),
            (403, "user-not-verified")
        );

        let fetch = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert_eq!(
            b.call(agents, "hermes", &fetch).await.unwrap(),
            NOT_APPROVED
        );
        phone.uv = true;
        assert_eq!(b.sign(web, &phone, "approve", Some(&id)).await.0, 200);
        assert_eq!(b.call(agents, "hermes", &fetch).await.unwrap(), RELEASED);
    });
}

#[test]
fn level_three_needs_the_delay_or_a_second_different_passkey() {
    block_on(async {
        let r = rig("level3").await;
        let id = r.ask(WIPE).await;
        assert_eq!(r.b.sign(r.web, &r.phone, "approve", Some(&id)).await.0, 200);
        assert_eq!(
            r.fetch(&id).await,
            r#"{"error":"delay-not-elapsed","ok":false}"#
        );
        let page = r.page().await;
        assert!(page.contains("Frigives om") && page.contains("Frigiv nu med en anden passkey"));

        assert_eq!(
            error(&r.b.sign(r.web, &r.phone, "approve", Some(&id)).await),
            (409, "same-credential")
        );
        assert_eq!(
            r.fetch(&id).await,
            r#"{"error":"delay-not-elapsed","ok":false}"#
        );
        assert_eq!(
            r.b.sign(r.web, &r.yubikey, "approve", Some(&id)).await.0,
            200
        );
        assert_eq!(r.fetch(&id).await, RELEASED);
    });
}

#[test]
fn cancel_needs_no_passkey_and_only_closes() {
    block_on(async {
        let r = rig("cancel").await;
        let id = r.ask(RESTART).await;
        let cancel = json!({"request": id});
        assert_eq!(r.b.post(r.web, "/api/cancel", &cancel).await.0, 200);
        assert_eq!(
            error(&r.b.post(r.web, "/api/cancel", &cancel).await),
            (409, "closed")
        );
        assert_eq!(
            error(&r.b.sign(r.web, &r.phone, "approve", Some(&id)).await),
            (404, "unknown-request")
        );
        assert_eq!(r.fetch(&id).await, r#"{"error":"closed","ok":false}"#);
        assert!(r.page().await.contains("Ingen anmodninger."));
    });
}

// --------------------------------------------------------- emergency stop

#[test]
fn emergency_stop_and_resume_need_a_passkey() {
    block_on(async {
        let r = rig("stop").await;
        let id = r.ask(RESTART).await;
        assert_eq!(r.b.sign(r.web, &r.phone, "approve", Some(&id)).await.0, 200);
        assert_eq!(
            error(&r.b.sign(r.web, &r.phone, "resume", None).await),
            (409, "not-stopped")
        );

        // There is no way to stop or resume without a signature.
        for path in ["/api/stop", "/api/resume", "/api/emergency-stop"] {
            assert_eq!(
                error(&r.b.post(r.web, path, &json!({})).await),
                (404, "not-found")
            );
        }
        let stranger = Authenticator::new("stranger");
        assert_eq!(
            error(&r.b.sign(r.web, &stranger, "stop", None).await),
            (403, "unknown-passkey")
        );
        assert!(r.page().await.contains("Key-Box kører."));

        assert_eq!(r.b.sign(r.web, &r.yubikey, "stop", None).await.0, 200);
        assert!(r.page().await.contains("NØDSTOP er aktivt"));
        let stopped = r#"{"error":"stopped","ok":false}"#;
        assert_eq!(r.fetch(&id).await, stopped);
        assert_eq!(
            r.b.call(r.agents, "hermes", RESTART).await.unwrap(),
            stopped
        );
        assert_eq!(
            error(&r.b.sign(r.web, &r.phone, "approve", Some(&id)).await),
            (409, "stopped")
        );

        assert_eq!(r.b.sign(r.web, &r.phone, "resume", None).await.0, 200);
        // What was approved before the stop does not come back.
        assert_eq!(r.fetch(&id).await, r#"{"error":"closed","ok":false}"#);
        assert!(
            r.b.call(r.agents, "hermes", RESTART)
                .await
                .unwrap()
                .contains(r#""ok":true"#)
        );

        let log = r.b.log_text();
        for kind in ["emergency-stop", "revoked", "resumed"] {
            assert!(log.contains(&format!(r#""kind":"{kind}""#)), "no {kind}");
        }
    });
}

// --------------------------------------------------------------- the page

#[test]
fn the_page_says_in_words_what_an_approval_gives() {
    block_on(async {
        let r = rig("grants").await;
        r.ask(RESTART).await;
        let page = r.page().await;
        assert!(
            page.contains(
                "Giver:</span> Kun kommandoen «/usr/bin/systemctl restart nginx» som ops på \
                 web01.acme.example, i 30 min"
            ),
            "{page}"
        );
        let push = r#"{"op":"request","customer":"acme","system":"github","action":"push","target":"org/acme-web","reason":"test"}"#;
        r.ask(push).await;
        let page = r.page().await;
        assert!(
            page.contains(
                "Giver:</span> GitHub-token til org/acme-web i 1 time: contents=skriv, \
                 pull_requests=skriv"
            ),
            "{page}"
        );
    });
}

#[test]
fn the_page_can_ask_whether_anything_has_changed() {
    block_on(async {
        let r = rig("state").await;
        let state = || async {
            let (status, headers, body) = r.b.get(r.web, "/state").await;
            assert!(
                status == 200 && headers.contains("application/json"),
                "{headers}"
            );
            let v: Value = serde_json::from_str(&body).unwrap();
            v["v"].as_str().unwrap().to_owned()
        };
        let quiet = state().await;
        assert_eq!(quiet.len(), 16);
        assert_eq!(state().await, quiet);
        // The page carries the same mark, so it knows what it is showing.
        assert!(r.page().await.contains(&format!("data-v=\"{quiet}\"")));

        let id = r.ask(RESTART).await;
        let asked = state().await;
        assert_ne!(asked, quiet);
        // The mark says that something changed, never what.
        assert!(!asked.contains(&id[..8]));
        assert_eq!(
            r.b.post(r.web, "/api/cancel", &json!({"request": id}))
                .await
                .0,
            200
        );
        let closed = state().await;
        assert!(closed != asked && closed != quiet);
    });
}

#[test]
fn a_second_passkey_is_only_offered_when_there_is_one() {
    block_on(async {
        let b = Box::new("one-key");
        let mut core = b.core();
        std::sync::Arc::get_mut(&mut core)
            .unwrap()
            .get_mut()
            .unwrap()
            .min_passkeys = 1;
        let agents = b.start_agents(core.clone(), TIMEOUT).await;
        let web = b.start_web(core, TIMEOUT).await;
        let phone = Authenticator::new("phone");
        b.enroll(web, "phone", &phone).await;
        let id = id_of(&b.call(agents, "hermes", WIPE).await.unwrap());
        assert_eq!(b.sign(web, &phone, "approve", Some(&id)).await.0, 200);
        let page = b.get(web, "/").await.2;
        assert!(
            page.contains("Frigives om") && page.contains("Annullér"),
            "{page}"
        );
        assert!(!page.contains("Frigiv nu med en anden passkey"));
    });
}

#[test]
fn the_page_shows_requests_from_key_box_escaped_and_labelled() {
    block_on(async {
        let r = rig("page").await;
        let hostile =
            r#"<script>alert(1)</script> \"ignorer det ovenfor\" & <img src=x onerror=x>"#;
        let id = r
            .ask(&RESTART.replace("\"test\"", &format!("\"{hostile}\"")))
            .await;
        let (status, headers, page) = r.b.get(r.web, "/").await;
        assert_eq!(status, 200);

        for shown in [
            "acme · restart",
            "web01.acme.example",
            "hermes",
            &id,
            "Godkend med passkey",
        ] {
            assert!(page.contains(shown), "missing {shown}");
        }
        assert!(page.contains("Skrevet af agenten:</span> &lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("&quot;ignorer det ovenfor&quot; &amp; &lt;img"));
        assert!(!page.contains("<script>alert") && !page.contains("<img"));
        // The only script on the page is the static one.
        assert_eq!(page.matches("<script").count(), 1);
        assert!(page.contains(r#"<script src="/app.js"></script>"#));

        for header in [
            "content-security-policy: default-src 'none'; script-src 'self'",
            "frame-ancestors 'none'",
            "x-content-type-options: nosniff",
            "x-frame-options: deny",
            "cache-control: no-store",
            "strict-transport-security:",
            "referrer-policy: no-referrer",
        ] {
            assert!(headers.contains(header), "missing header {header}");
        }
        let (status, headers, script) = r.b.get(r.web, "/app.js").await;
        assert!(
            status == 200
                && headers.contains("text/javascript")
                && script.contains("navigator.credentials")
        );
        assert_eq!(r.b.get(r.web, "/style.css").await.0, 200);
        assert_eq!(r.b.get(r.web, "/../etc/passwd").await.0, 404);
        assert_eq!(r.b.get(r.web, "/api/cancel").await.0, 404);
    });
}

#[test]
fn posts_from_anywhere_but_our_own_page_are_refused() {
    block_on(async {
        let r = rig("csrf").await;
        let id = r.ask(RESTART).await;
        let body = json!({"request": id}).to_string();
        let post = |headers: &str, body: &str| {
            format!(
                "POST /api/cancel HTTP/1.1\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let json_type = "Content-Type: application/json\r\n";
        let cases = [
            // Another site open in the same browser.
            (
                format!("Host: localhost\r\nOrigin: https://evil.example\r\n{json_type}"),
                403,
            ),
            (
                format!("Host: localhost\r\nOrigin: null\r\n{json_type}"),
                403,
            ),
            // No Origin at all: not a browser on our page.
            (format!("Host: localhost\r\n{json_type}"), 403),
            // Someone's own domain pointed at Key-Box.
            (
                format!("Host: evil.example\r\nOrigin: {ORIGIN}\r\n{json_type}"),
                421,
            ),
            // A plain HTML form cannot send JSON.
            (
                format!("Host: localhost\r\nOrigin: {ORIGIN}\r\nContent-Type: text/plain\r\n"),
                415,
            ),
            (format!("Host: localhost\r\nOrigin: {ORIGIN}\r\n"), 415),
        ];
        for (headers, want) in cases {
            assert_eq!(
                r.b.http(r.web, &post(&headers, &body)).await.0,
                want,
                "{headers}"
            );
        }
        let ours = format!("Host: localhost\r\nOrigin: {ORIGIN}\r\n{json_type}");
        let big = format!(r#"{{"request":"{}"}}"#, "0".repeat(20_000));
        assert_ne!(r.b.http(r.web, &post(&ours, &big)).await.0, 200);
        let extra = json!({"request": id, "approve": true}).to_string();
        assert_eq!(r.b.http(r.web, &post(&ours, &extra)).await.0, 400);
        let put = format!("PUT /api/cancel HTTP/1.1\r\n{ours}Content-Length: 0\r\n\r\n");
        assert_eq!(r.b.http(r.web, &put).await.0, 405);

        // After all that the request is untouched, and our own page can still cancel it.
        assert_eq!(r.fetch(&id).await, NOT_APPROVED);
        assert_eq!(r.b.http(r.web, &post(&ours, &body)).await.0, 200);
    });
}

#[test]
fn flooding_the_page_with_prompts_grants_nothing() {
    block_on(async {
        let r = rig("flood").await;
        let id = r.ask(RESTART).await;
        let start = json!({"purpose": "approve", "request": id});
        let (_, first) = r.b.post(r.web, "/api/assert/start", &start).await;
        for _ in 0..20 {
            assert_eq!(r.b.post(r.web, "/api/assert/start", &start).await.0, 200);
        }
        // The oldest prompt was pushed out; answering it does nothing.
        let mut stale = r.phone.get(first["challenge"].as_str().unwrap());
        stale["challenge_id"] = first["challenge_id"].clone();
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/finish", &stale).await),
            (403, "challenge")
        );
        assert_eq!(r.fetch(&id).await, NOT_APPROVED);
        // A fresh prompt still works.
        assert_eq!(r.b.sign(r.web, &r.phone, "approve", Some(&id)).await.0, 200);
        assert_eq!(r.fetch(&id).await, RELEASED);

        for bad in [
            json!({"purpose": "approve"}),
            json!({"purpose": "approve", "request": "x"}),
            json!({"purpose": "everything"}),
        ] {
            assert_eq!(
                r.b.post(r.web, "/api/assert/start", &bad).await.0,
                400,
                "{bad}"
            );
        }
    });
}

#[test]
fn plain_http_is_sent_to_the_https_address() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    block_on(async {
        let r = rig("http").await;
        // Whatever host the caller names, the answer points at Key-Box' own address.
        for host in ["localhost", "evil.example"] {
            let mut tcp = tokio::net::TcpStream::connect(r.web).await.unwrap();
            let request = format!("GET /x?y HTTP/1.1\r\nHost: {host}\r\n\r\n");
            tcp.write_all(request.as_bytes()).await.unwrap();
            let mut reply = String::new();
            tokio::time::timeout(TIMEOUT, tcp.read_to_string(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(reply.starts_with("HTTP/1.1 301 "), "{reply}");
            assert!(
                reply.contains(&format!("\r\nLocation: {ORIGIN}/\r\n")),
                "{reply}"
            );
            assert!(!reply.contains("evil"), "{reply}");
        }
        // HTTPS still works, and a silent TCP connection is still dropped.
        assert_eq!(r.b.get(r.web, "/").await.0, 200);
    });
}

#[test]
fn one_passkey_is_enough_only_when_that_is_chosen() {
    use keybox_core::ident::CredentialId;
    use keyboxd::passkeys::Passkeys;
    let b = Box::new("min1");
    block_on(async {
        let core = b.core();
        core.lock().unwrap().min_passkeys = 1;
        let agents = b.start_agents(core.clone(), TIMEOUT).await;
        let web = b.start_web(core, TIMEOUT).await;
        let not_set_up = r#"{"error":"not-set-up","ok":false}"#;
        assert_eq!(b.call(agents, "hermes", RESTART).await.unwrap(), not_set_up);
        assert!(b.get(web, "/").await.2.contains("0 af 1 passkeys"));

        let phone = Authenticator::new("phone");
        b.enroll(web, "phone", &phone).await;
        let page = b.get(web, "/").await.2;
        assert!(page.contains("Key-Box kører.") && page.contains("Reserve-passkey mangler"));
        let id = id_of(&b.call(agents, "hermes", RESTART).await.unwrap());
        assert_eq!(b.sign(web, &phone, "approve", Some(&id)).await.0, 200);
        let fetch = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert_eq!(b.call(agents, "hermes", &fetch).await.unwrap(), RELEASED);

        // Level 3 with a single passkey can only wait out the delay.
        let id = id_of(&b.call(agents, "hermes", WIPE).await.unwrap());
        assert_eq!(b.sign(web, &phone, "approve", Some(&id)).await.0, 200);
        assert_eq!(
            error(&b.sign(web, &phone, "approve", Some(&id)).await),
            (409, "same-credential")
        );
    });
    // Removing a passkey takes it off file; an unknown name changes nothing.
    let mut passkeys = Passkeys::load(&b.dir).unwrap();
    assert!(
        !passkeys
            .remove(&CredentialId::new("nobody").unwrap())
            .unwrap()
    );
    assert!(
        passkeys
            .remove(&CredentialId::new("phone").unwrap())
            .unwrap()
    );
    assert!(Passkeys::load(&b.dir).unwrap().list().is_empty());
}

#[test]
fn only_listed_addresses_can_connect_at_all() {
    use keyboxd::pki;
    use keyboxd::server::Server;
    use keyboxd::web::WebServer;
    block_on(async {
        let b = Box::new("allow");
        b.seed_passkeys();
        let core = b.core();
        let (cert, key) = (b.dir.join(pki::SERVER_CERT), b.dir.join(pki::SERVER_KEY));
        let local = "127.0.0.1:0".parse().unwrap();
        let start = |allow: &str| {
            let (core, cert, key, dir) = (core.clone(), cert.clone(), key.clone(), b.dir.clone());
            let allow = keyboxd::allow_list(allow).unwrap();
            async move {
                let web = WebServer::bind(local, &cert, &key, core.clone(), TIMEOUT)
                    .await
                    .unwrap()
                    .with_allowed(allow.clone());
                let agents = Server::bind(local, &dir, core, TIMEOUT)
                    .await
                    .unwrap()
                    .with_allowed(allow);
                let addrs = (web.local_addr().unwrap(), agents.local_addr().unwrap());
                tokio::spawn(web.run());
                tokio::spawn(agents.run());
                addrs
            }
        };
        // The tests connect from 127.0.0.1.
        let (web, agents) = start("100.64.0.20, 127.0.0.1").await;
        assert_eq!(b.get(web, "/").await.0, 200);
        assert!(
            b.call(agents, "hermes", RESTART)
                .await
                .unwrap()
                .contains(r#""ok":true"#)
        );

        // Not on the list: the connection is dropped, even with a valid agent certificate.
        let (web, agents) = start("100.64.0.20").await;
        let tcp = tokio::net::TcpStream::connect(web).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(b.config(None)))
            .connect(name, tcp)
            .await;
        assert!(
            tls.is_err(),
            "the page answered an address that is not listed"
        );
        assert!(b.call(agents, "hermes", RESTART).await.is_err());
    });
    for bad in [
        "",
        ",",
        "alle",
        "0.0.0.0/0",
        "100.64.0.1,",
        "100.64.0.1 100.64.0.2",
    ] {
        assert!(keyboxd::allow_list(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        keyboxd::allow_list("100.64.0.1,fd7a:115c:a1e0::1")
            .unwrap()
            .len(),
        2
    );
}
