//! GitHub tokens, against a stand-in for GitHub that checks Key-Box' proof of
//! identity the way GitHub does and can be told to misbehave.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Authenticator, Box, READ, TIMEOUT, block_on, id_of};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use keybox_webauthn::base64url_decode;
use keyboxd::github::Github;
use keyboxd::https::HttpsClient;
use keyboxd::issuer::Issuer;
use keyboxd::pki;
use keyboxd::secrets::{DirSecrets, Secrets};
use keyboxd::server::Server;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};

const APP_KEY: &str = include_str!("fixtures/test-app-key-a.txt");
const OTHER_KEY: &str = include_str!("fixtures/test-app-key-b.txt");
const TOKEN: &str = "ghs_MockInstallationToken0123456789abcdefAB";
const PUSH: &str = r#"{"op":"request","customer":"acme","system":"github","action":"push","target":"org/acme-web","reason":"test"}"#;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    NotInstalled,
    Refuse,
    Garbage,
    Huge,
    Slow,
    ExtraRepository,
    AllRepositories,
    SelectionAll,
    OtherRepository,
    MorePermission,
    HigherPermission,
    OddToken,
}

/// What the stand-in remembers of each call: method, path, bearer, body.
type Calls = Arc<Mutex<Vec<(String, String, String, String)>>>;

/// Installations the stand-in currently has suspended.
type Suspended = Arc<Mutex<std::collections::BTreeSet<u64>>>;

struct Mock {
    port: u16,
    calls: Calls,
    suspended: Suspended,
}

fn public_key() -> Vec<u8> {
    let PrivateKeyDer::Pkcs1(der) = PrivateKeyDer::from_pem_slice(APP_KEY.as_bytes()).unwrap()
    else {
        panic!("fixture is PKCS#1");
    };
    RsaKeyPair::from_der(der.secret_pkcs1_der())
        .unwrap()
        .public()
        .as_ref()
        .to_vec()
}

/// GitHub's own checks on an App JWT: RS256 by the App's key, issued by the
/// App, not expired, and living at most ten minutes.
fn jwt_ok(jwt: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    let [header, claims, signature] = parts.as_slice() else {
        return false;
    };
    let signed = format!("{header}.{claims}");
    let Some(signature) = base64url_decode(signature) else {
        return false;
    };
    if UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key())
        .verify(signed.as_bytes(), &signature)
        .is_err()
    {
        return false;
    }
    let json =
        |part: &str| -> Option<Value> { serde_json::from_slice(&base64url_decode(part)?).ok() };
    let (Some(header), Some(claims)) = (json(header), json(claims)) else {
        return false;
    };
    let now = keyboxd::now();
    let (iat, exp) = (
        claims["iat"].as_u64().unwrap_or(0),
        claims["exp"].as_u64().unwrap_or(0),
    );
    header["alg"] == "RS256"
        && claims["iss"] == "Iv23liTESTCLIENTID"
        && iat <= now
        && exp > now
        && exp - iat <= 600
}

async fn answer(
    req: Request<Incoming>,
    mode: Mode,
    calls: Calls,
    suspended: Suspended,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned();
    let body =
        String::from_utf8_lossy(&req.into_body().collect().await.unwrap().to_bytes()).into_owned();
    calls
        .lock()
        .unwrap()
        .push((method.clone(), path.clone(), bearer.clone(), body.clone()));
    let reply = |status: u16, body: String| {
        Ok(Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(body)))
            .unwrap())
    };

    if method == "DELETE" && path == "/installation/token" {
        return reply(204, String::new());
    }
    if !jwt_ok(&bearer) {
        return reply(
            401,
            r#"{"message":"A JSON web token could not be decoded"}"#.into(),
        );
    }
    if mode == Mode::Slow {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    // Two installations: 4242, and 4343 which someone suspended earlier.
    if method == "GET" && path == "/app/installations" {
        let now = suspended.lock().unwrap().clone();
        let state = |id: u64| {
            if now.contains(&id) {
                json!("2026-10-01T00:00:00Z")
            } else {
                Value::Null
            }
        };
        let list = json!([{"id": 4242, "suspended_at": state(4242)}, {"id": 4343, "suspended_at": state(4343)}]);
        return reply(200, list.to_string());
    }
    if let Some(id) = path
        .strip_prefix("/app/installations/")
        .and_then(|p| p.strip_suffix("/suspended"))
    {
        let id: u64 = id.parse().unwrap();
        match method.as_str() {
            "PUT" => suspended.lock().unwrap().insert(id),
            "DELETE" => suspended.lock().unwrap().remove(&id),
            _ => return reply(405, String::new()),
        };
        return reply(204, String::new());
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/repos/org/acme-web/installation") if mode != Mode::NotInstalled => reply(
            200,
            json!({"id": 4242, "account": {"login": "org"}}).to_string(),
        ),
        ("GET", _) => reply(404, r#"{"message":"Not Found"}"#.into()),
        ("POST", "/app/installations/4242/access_tokens") => {
            let asked: Value = serde_json::from_str(&body).unwrap();
            let mut permissions = asked["permissions"].clone();
            permissions["metadata"] = json!("read");
            let mut repositories = vec![json!({"full_name": "org/acme-web"})];
            let mut selection = "selected";
            let mut token = TOKEN.to_owned();
            match mode {
                Mode::Refuse => {
                    return reply(403, r#"{"message":"Resource not accessible"}"#.into());
                }
                Mode::Garbage => return reply(201, "<html>not json</html>".into()),
                Mode::Huge => {
                    return reply(201, format!(r#"{{"token":"{}"}}"#, "x".repeat(200_000)));
                }
                Mode::ExtraRepository => {
                    repositories.push(json!({"full_name": "org/other-customer"}))
                }
                Mode::OtherRepository => {
                    repositories = vec![json!({"full_name": "org/other-customer"})]
                }
                Mode::AllRepositories => {
                    selection = "all";
                    repositories.clear();
                }
                // The right repository is listed, but the token is not limited to it.
                Mode::SelectionAll => selection = "all",
                Mode::MorePermission => permissions["administration"] = json!("read"),
                Mode::HigherPermission => permissions["contents"] = json!("write"),
                Mode::OddToken => token = "ghs_has \"quote\" and space 0000000000000000".into(),
                _ => {}
            }
            reply(
                201,
                json!({
                    "token": token,
                    "expires_at": "2026-10-11T04:00:00Z",
                    "permissions": permissions,
                    "repository_selection": selection,
                    "repositories": repositories,
                })
                .to_string(),
            )
        }
        _ => reply(404, r#"{"message":"Not Found"}"#.into()),
    }
}

async fn mock(b: &Box, mode: Mode) -> Mock {
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
    let calls: Calls = Arc::default();
    let seen = calls.clone();
    let suspended: Suspended = Arc::new(Mutex::new([4343].into()));
    let state = suspended.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (acceptor, calls, state) = (acceptor.clone(), seen.clone(), state.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service =
                    service_fn(move |req| answer(req, mode, calls.clone(), state.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Mock {
        port,
        calls,
        suspended,
    }
}

/// A set-up Key-Box whose GitHub is the stand-in on `port`, with `key` as the App's key.
async fn key_box(b: &Box, port: u16, key: Option<&str>) -> SocketAddr {
    b.seed_passkeys();
    let secrets_dir = b.dir.join("secrets");
    std::fs::create_dir_all(&secrets_dir).unwrap();
    if let Some(key) = key {
        std::fs::write(secrets_dir.join("github-app"), key).unwrap();
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(b.dir.join(pki::CA_CERT)).unwrap())
        .unwrap();
    let client = HttpsClient::new(roots, Duration::from_millis(1500)).unwrap();
    let secrets: Arc<dyn Secrets> = Arc::new(DirSecrets(secrets_dir));
    let issuer = Issuer {
        secrets,
        github: Github::at(client, "localhost", port),
    };
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), &b.dir, b.core(), TIMEOUT)
        .await
        .unwrap()
        .with_issuer(Arc::new(issuer));
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    addr
}

/// Ask for read access (level 1) and fetch it. Returns the answer to the fetch.
async fn read_code(b: &Box, agents: SocketAddr) -> String {
    let id = id_of(&b.call(agents, "hermes", READ).await.unwrap());
    b.call(
        agents,
        "hermes",
        &format!(r#"{{"op":"fetch","id":"{id}"}}"#),
    )
    .await
    .unwrap()
}

fn nothing_secret_in(text: &str) {
    for secret in [
        TOKEN,
        "BEGIN RSA",
        "PRIVATE KEY",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
        "MIIE",
    ] {
        assert!(!text.contains(secret), "found {secret:?} in: {text}");
    }
}

#[test]
fn a_released_request_becomes_a_token_for_that_repository_only() {
    let b = Box::new("gh-ok");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        let agents = key_box(&b, gh.port, Some(APP_KEY)).await;
        let reply: Value = serde_json::from_str(&read_code(&b, agents).await).unwrap();
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["kind"], "github-token");
        assert_eq!(reply["token"], TOKEN);
        assert_eq!(reply["repository"], "org/acme-web");
        assert_eq!(reply["expires_at"], "2026-10-11T04:00:00Z");

        let calls = gh.calls.lock().unwrap().clone();
        let seen: Vec<_> = calls.iter().map(|c| format!("{} {}", c.0, c.1)).collect();
        assert_eq!(
            seen,
            [
                "GET /repos/org/acme-web/installation",
                "POST /app/installations/4242/access_tokens"
            ]
        );
        // Exactly the repository and the permissions the policy names.
        let asked: Value = serde_json::from_str(&calls[1].3).unwrap();
        assert_eq!(
            asked,
            json!({"repositories": ["acme-web"], "permissions": {"contents": "read"}})
        );
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""kind":"issued""#) && log.contains(r#""what":"github-token""#),
        "{log}"
    );
    nothing_secret_in(&log);
    assert!(keybox_log::verify(&b.log()).is_ok());
}

#[test]
fn a_write_token_needs_the_passkey_first() {
    let b = Box::new("gh-approve");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        // Real passkey flow, so the page runs on the same core as the agent listener.
        let secrets_dir = b.dir.join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        std::fs::write(secrets_dir.join("github-app"), APP_KEY).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(b.dir.join(pki::CA_CERT)).unwrap())
            .unwrap();
        let issuer = Issuer {
            secrets: Arc::new(DirSecrets(secrets_dir)),
            github: Github::at(
                HttpsClient::new(roots, TIMEOUT).unwrap(),
                "localhost",
                gh.port,
            ),
        };
        let core = b.core();
        let web = b.start_web(core.clone(), TIMEOUT).await;
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &b.dir, core, TIMEOUT)
            .await
            .unwrap()
            .with_issuer(Arc::new(issuer));
        let agents = server.local_addr().unwrap();
        tokio::spawn(server.run());
        let (phone, spare) = (Authenticator::new("phone"), Authenticator::new("spare"));
        b.enroll(web, "phone", &phone).await;
        b.enroll(web, "spare", &spare).await;

        let id = id_of(&b.call(agents, "hermes", PUSH).await.unwrap());
        let fetch = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert_eq!(
            b.call(agents, "hermes", &fetch).await.unwrap(),
            r#"{"error":"not-approved","ok":false}"#
        );
        assert!(
            gh.calls.lock().unwrap().is_empty(),
            "GitHub was called before approval"
        );

        assert_eq!(b.sign(web, &phone, "approve", Some(&id)).await.0, 200);
        let reply: Value =
            serde_json::from_str(&b.call(agents, "hermes", &fetch).await.unwrap()).unwrap();
        assert_eq!(reply["token"], TOKEN);
        let asked: Value = serde_json::from_str(&gh.calls.lock().unwrap()[1].3).unwrap();
        assert_eq!(
            asked["permissions"],
            json!({"contents": "write", "pull_requests": "write"})
        );

        // One approval, one token.
        assert_eq!(
            b.call(agents, "hermes", &fetch).await.unwrap(),
            r#"{"error":"closed","ok":false}"#
        );
        assert_eq!(gh.calls.lock().unwrap().len(), 2);
    });
}

#[test]
fn a_token_that_reaches_further_than_asked_is_revoked_not_handed_out() {
    for mode in [
        Mode::ExtraRepository,
        Mode::AllRepositories,
        Mode::SelectionAll,
        Mode::OtherRepository,
        Mode::MorePermission,
        Mode::HigherPermission,
    ] {
        let b = Box::new("gh-broad");
        block_on(async {
            let gh = mock(&b, mode).await;
            let agents = key_box(&b, gh.port, Some(APP_KEY)).await;
            let reply = read_code(&b, agents).await;
            assert_eq!(reply, r#"{"error":"github-token-too-broad","ok":false}"#);
            let calls = gh.calls.lock().unwrap().clone();
            let last = calls.last().unwrap();
            assert_eq!(
                (last.0.as_str(), last.1.as_str(), last.2.as_str()),
                ("DELETE", "/installation/token", TOKEN)
            );
        });
        let log = b.log_text();
        assert!(log.contains(r#""kind":"github-token-too-broad""#), "{log}");
        nothing_secret_in(&log);
    }
}

#[test]
fn when_github_fails_the_agent_gets_a_fixed_word_and_nothing_else() {
    for (mode, want) in [
        (Mode::NotInstalled, "github-not-installed"),
        (Mode::Refuse, "github-refused"),
        (Mode::Garbage, "github-bad-answer"),
        (Mode::Huge, "github-unreachable"),
        (Mode::Slow, "github-unreachable"),
        (Mode::OddToken, "github-bad-answer"),
    ] {
        let b = Box::new("gh-fail");
        block_on(async {
            let gh = mock(&b, mode).await;
            let agents = key_box(&b, gh.port, Some(APP_KEY)).await;
            let reply = read_code(&b, agents).await;
            assert_eq!(reply, format!(r#"{{"error":"{want}","ok":false}}"#));
        });
        let log = b.log_text();
        assert!(log.contains(&format!(r#""kind":"{want}""#)), "{log}");
        nothing_secret_in(&log);
        assert!(
            !log.contains("Resource not accessible") && !log.contains("html"),
            "{log}"
        );
    }
}

#[test]
fn without_the_right_key_or_without_github_nothing_is_issued() {
    // No key in the secret store: GitHub is never contacted.
    let b = Box::new("gh-nokey");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        let agents = key_box(&b, gh.port, None).await;
        assert_eq!(
            read_code(&b, agents).await,
            r#"{"error":"secret-unavailable","ok":false}"#
        );
        assert!(gh.calls.lock().unwrap().is_empty());
    });
    // Something that is not a key.
    let b = Box::new("gh-badkey");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        let agents = key_box(&b, gh.port, Some("ikke en noegle")).await;
        assert_eq!(
            read_code(&b, agents).await,
            r#"{"error":"github-bad-key","ok":false}"#
        );
        assert!(gh.calls.lock().unwrap().is_empty());
    });
    // A real key, but not the App's: GitHub says no.
    let b = Box::new("gh-otherkey");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        let agents = key_box(&b, gh.port, Some(OTHER_KEY)).await;
        assert_eq!(
            read_code(&b, agents).await,
            r#"{"error":"github-refused","ok":false}"#
        );
    });
    // Nothing listening where GitHub should be.
    let b = Box::new("gh-down");
    block_on(async {
        let agents = key_box(&b, 1, Some(APP_KEY)).await;
        assert_eq!(
            read_code(&b, agents).await,
            r#"{"error":"github-unreachable","ok":false}"#
        );
    });
    nothing_secret_in(&b.log_text());
}

#[test]
fn a_server_with_the_wrong_certificate_is_not_github() {
    // The stand-in presents a certificate from another CA than the one Key-Box trusts.
    let b = Box::new("gh-tls");
    let other = Box::new("gh-tls-other");
    block_on(async {
        let gh = mock(&other, Mode::Normal).await;
        let agents = key_box(&b, gh.port, Some(APP_KEY)).await;
        assert_eq!(
            read_code(&b, agents).await,
            r#"{"error":"github-unreachable","ok":false}"#
        );
        // The App's proof of identity was never sent to it.
        assert!(gh.calls.lock().unwrap().is_empty());
    });
}

/// A Key-Box with both listeners, real passkeys and the stand-in as GitHub.
/// `port` is where it believes GitHub is.
async fn with_page(b: &Box, port: u16) -> (SocketAddr, SocketAddr, Authenticator) {
    let secrets_dir = b.dir.join("secrets");
    std::fs::create_dir_all(&secrets_dir).unwrap();
    std::fs::write(secrets_dir.join("github-app"), APP_KEY).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(b.dir.join(pki::CA_CERT)).unwrap())
        .unwrap();
    let issuer = Arc::new(Issuer {
        secrets: Arc::new(DirSecrets(secrets_dir)),
        github: Github::at(
            HttpsClient::new(roots, Duration::from_millis(1500)).unwrap(),
            "localhost",
            port,
        ),
    });
    let core = b.core();
    let (cert, key) = (b.dir.join(pki::SERVER_CERT), b.dir.join(pki::SERVER_KEY));
    let web = keyboxd::web::WebServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert,
        &key,
        core.clone(),
        TIMEOUT,
    )
    .await
    .unwrap()
    .with_issuer(issuer.clone());
    let web_addr = web.local_addr().unwrap();
    tokio::spawn(web.run());
    let agents = Server::bind("127.0.0.1:0".parse().unwrap(), &b.dir, core, TIMEOUT)
        .await
        .unwrap()
        .with_issuer(issuer);
    let agents_addr = agents.local_addr().unwrap();
    tokio::spawn(agents.run());
    let (phone, spare) = (Authenticator::new("phone"), Authenticator::new("spare"));
    b.enroll(web_addr, "phone", &phone).await;
    b.enroll(web_addr, "spare", &spare).await;
    (agents_addr, web_addr, phone)
}

#[test]
fn emergency_stop_suspends_the_app_and_resume_lifts_only_that() {
    let b = Box::new("gh-stop");
    block_on(async {
        let gh = mock(&b, Mode::Normal).await;
        let (agents, web, phone) = with_page(&b, gh.port).await;
        // A token is out there before the stop.
        assert!(read_code(&b, agents).await.contains(TOKEN));
        assert_eq!(*gh.suspended.lock().unwrap(), [4343].into());

        assert_eq!(b.sign(web, &phone, "stop", None).await.0, 200);
        // 4242 is now suspended at GitHub, so that token is dead at once.
        assert_eq!(*gh.suspended.lock().unwrap(), [4242, 4343].into());
        let page = b.get(web, "/").await.2;
        assert!(
            page.contains("NØDSTOP er aktivt") && page.contains("er suspenderet (1 installation)"),
            "{page}"
        );
        assert_eq!(
            read_code_refused(&b, agents).await,
            r#"{"error":"stopped","ok":false}"#
        );

        assert_eq!(b.sign(web, &phone, "resume", None).await.0, 200);
        // Only what the stop suspended is lifted; 4343 was not ours to touch.
        assert_eq!(*gh.suspended.lock().unwrap(), [4343].into());
        let page = b.get(web, "/").await.2;
        assert!(
            page.contains("Key-Box kører.") && !page.contains("suspenderet"),
            "{page}"
        );
        assert!(read_code(&b, agents).await.contains(TOKEN));
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""kind":"github-suspended""#) && log.contains(r#""complete":"yes""#),
        "{log}"
    );
    assert!(log.contains(r#""kind":"github-resumed""#));
    nothing_secret_in(&log);
}

#[test]
fn when_github_cannot_be_reached_the_stop_still_holds_and_says_so() {
    let b = Box::new("gh-stop-down");
    block_on(async {
        // Nothing listens where GitHub should be.
        let (agents, web, phone) = with_page(&b, 1).await;
        assert_eq!(b.sign(web, &phone, "stop", None).await.0, 200);
        // Key-Box itself refuses everything regardless.
        assert_eq!(
            read_code_refused(&b, agents).await,
            r#"{"error":"stopped","ok":false}"#
        );
        let page = b.get(web, "/").await.2;
        assert!(page.contains("NØDSTOP er aktivt"));
        assert!(page.contains("GitHub kunne ikke lukkes helt"), "{page}");
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""kind":"github-suspended""#) && log.contains(r#""complete":"no""#),
        "{log}"
    );
}

/// Ask for read access while Key-Box refuses: returns the refusal.
async fn read_code_refused(b: &Box, agents: SocketAddr) -> String {
    b.call(agents, "hermes", READ).await.unwrap()
}

/// Talks to the real api.github.com, without any credentials, to check that
/// the client's certificate roots and TLS settings work against it.
/// Needs the internet: `cargo test -p keyboxd --test github -- --ignored`.
#[test]
#[ignore = "needs the internet"]
fn the_real_github_answers_over_tls() {
    block_on(async {
        let client = HttpsClient::public(Duration::from_secs(10)).unwrap();
        let (status, body) = client
            .send(
                "api.github.com",
                443,
                hyper::Method::GET,
                "/zen",
                &[("user-agent", "keybox")],
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert!(!body.is_empty() && body.len() < 200);

        // An App JWT signed by a key GitHub does not know is refused, which
        // shows the request reaches the right API and fails closed.
        let key = keyboxd::secrets::Secret::new(APP_KEY.as_bytes().to_vec());
        let github = Github::new(client);
        let permissions = [("contents".to_owned(), keybox_policy::Access::Read)].into();
        let out = github
            .issue(
                keyboxd::now(),
                "Iv23liTESTCLIENTID",
                &key,
                "IT-Hjaelp-Nu/Key-Box",
                &permissions,
            )
            .await;
        assert_eq!(out.err(), Some(keyboxd::github::IssueError::Refused));
    });
}
