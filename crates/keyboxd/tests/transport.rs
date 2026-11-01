//! The agent API over the wire: who gets in, and what gets logged.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Box, READ, RESTART, TIMEOUT, agent, block_on, id_of};
use keybox_log::verify;
use keyboxd::server::Server;
use keyboxd::{Error, client, pki};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A set-up Key-Box (two passkeys on file) with its agent listener running.
async fn start(b: &Box, io_timeout: Duration) -> std::net::SocketAddr {
    b.seed_passkeys();
    b.start_agents(b.core(), io_timeout).await
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn an_agent_with_its_certificate_can_ask_and_is_logged() {
    let b = Box::new("ok");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        let reply = b.call(addr, "hermes", RESTART).await.unwrap();
        assert!(
            reply.contains(r#""ok":true"#) && reply.contains(r#""state":"pending""#),
            "{reply}"
        );
        let status = format!(r#"{{"op":"status","id":"{}"}}"#, id_of(&reply));
        assert!(
            b.call(addr, "hermes", &status)
                .await
                .unwrap()
                .contains("pending")
        );
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""kind":"requested""#) && log.contains(r#""agent":"hermes""#),
        "{log}"
    );
    assert_eq!(verify(&b.log()).unwrap().seq, 1);
}

#[test]
fn the_agent_name_comes_from_the_certificate() {
    let b = Box::new("identity");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        let reply = b.call(addr, "hermes", READ).await.unwrap();
        let id = id_of(&reply);
        // coder holds a valid certificate, but this is not coder's request.
        for op in ["status", "fetch", "withdraw"] {
            let line = format!(r#"{{"op":"{op}","id":"{id}"}}"#);
            let out = b.call(addr, "coder", &line).await.unwrap();
            assert_eq!(out, r#"{"error":"unknown-request","ok":false}"#, "{op}");
        }
        // coder is not listed for restart, whatever it writes in the line.
        let out = b.call(addr, "coder", RESTART).await.unwrap();
        assert_eq!(out, r#"{"error":"policy:agent-not-allowed","ok":false}"#);
        let sneaky = RESTART.replace(r#""reason""#, r#""agent":"hermes","reason""#);
        assert_eq!(
            b.call(addr, "coder", &sneaky).await.unwrap(),
            r#"{"error":"malformed","ok":false}"#
        );
    });
}

#[test]
fn no_certificate_no_answer() {
    let b = Box::new("nocert");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        let out = client::call(addr, "localhost", b.config(None), READ, TIMEOUT).await;
        assert!(out.is_err(), "{out:?}");
    });
    assert_eq!(verify(&b.log()).unwrap().seq, 0);
}

#[test]
fn a_certificate_from_another_ca_is_refused() {
    let b = Box::new("otherca");
    let other = Box::new("otherca-attacker");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        // Trusts the real server, but presents a "hermes" certificate the attacker made.
        let config = client::config(
            &b.dir.join(pki::CA_CERT),
            Some((
                &other.keys.join("hermes.pem"),
                &other.keys.join("hermes.key"),
            )),
        )
        .unwrap();
        let out = client::call(addr, "localhost", config, READ, TIMEOUT).await;
        assert!(out.is_err(), "{out:?}");
    });
    assert!(!b.log_text().contains("requested"));
}

#[test]
fn a_revoked_agent_is_refused_and_the_attempt_is_logged() {
    let b = Box::new("revoked");
    pki::revoke_agent(&b.dir, &agent("coder")).unwrap();
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        // Still signed by the CA, no longer on file.
        assert!(b.call(addr, "coder", READ).await.is_err());
        assert!(b.call(addr, "hermes", READ).await.is_ok());
    });
    let log = b.log_text();
    assert!(log.contains(r#""kind":"unknown-certificate""#), "{log}");
    assert_eq!(log.matches("requested").count(), 1);
}

#[test]
fn the_agent_refuses_a_server_that_is_not_key_box() {
    let b = Box::new("phish");
    let fake = Box::new("phish-fake");
    block_on(async {
        // A look-alike server with its own CA.
        let fake_addr = start(&fake, TIMEOUT).await;
        let out = b.call(fake_addr, "hermes", READ).await;
        assert!(matches!(out, Err(Error::Tls)), "{out:?}");
        // The real server under the wrong name.
        let addr = start(&b, TIMEOUT).await;
        let out = client::call(
            addr,
            "keybox.example",
            b.config(Some("hermes")),
            READ,
            TIMEOUT,
        )
        .await;
        assert!(matches!(out, Err(Error::Tls)), "{out:?}");
    });
    assert!(!fake.log_text().contains("requested"));
}

#[test]
fn malformed_and_oversized_lines_are_refused_and_logged() {
    let b = Box::new("bad");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        let out = b.call(addr, "hermes", r#"{"op":"approve"}"#).await.unwrap();
        assert_eq!(out, r#"{"error":"malformed","ok":false}"#);
        let out = b
            .call(addr, "hermes", &READ.replace("acme", "ghp_Secret"))
            .await
            .unwrap();
        assert_eq!(out, r#"{"error":"invalid customer","ok":false}"#);
        let big = READ.replace("test", &"x".repeat(5000));
        let out = b.call(addr, "hermes", &big).await.unwrap();
        assert_eq!(out, r#"{"error":"too-large","ok":false}"#);
    });
    let log = b.log_text();
    for kind in ["malformed", "invalid", "too-large"] {
        assert!(
            log.contains(&format!(r#""kind":"{kind}""#)),
            "no {kind} in {log}"
        );
    }
    assert!(!log.contains("ghp_") && !log.contains("xxxx"), "{log}");
    assert_eq!(verify(&b.log()).unwrap().seq, 3);
}

#[test]
fn a_silent_client_is_dropped_after_the_timeout() {
    let b = Box::new("slow");
    block_on(async {
        let addr = start(&b, Duration::from_millis(300)).await;
        // Handshake, then send half a line and wait.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(b.config(Some("hermes"))))
            .connect(name, tcp)
            .await
            .unwrap();
        tls.write_all(br#"{"op":"request","#).await.unwrap();
        let started = Instant::now();
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(TIMEOUT, tls.read_to_end(&mut rest))
            .await
            .expect("server never hung up");
        assert!(rest.is_empty());
        assert!(started.elapsed() < Duration::from_secs(3));

        // A TCP connection that never starts TLS is dropped too.
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = tokio::time::timeout(TIMEOUT, tcp.read_to_end(&mut rest))
            .await
            .expect("server never hung up");
        // And the server still answers others.
        assert!(b.call(addr, "hermes", READ).await.is_ok());
    });
}

#[test]
fn fetch_is_logged_before_it_is_answered() {
    let b = Box::new("fetch");
    block_on(async {
        let addr = start(&b, TIMEOUT).await;
        let reply = b.call(addr, "hermes", READ).await.unwrap();
        let fetch = format!(r#"{{"op":"fetch","id":"{}"}}"#, id_of(&reply));
        // No issuer exists yet, so the agent gets no access, and is told so.
        let out = b.call(addr, "hermes", &fetch).await.unwrap();
        assert_eq!(out, r#"{"error":"issuer-unavailable","ok":false}"#);
        assert_eq!(
            b.call(addr, "hermes", &fetch).await.unwrap(),
            r#"{"error":"closed","ok":false}"#
        );
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""kind":"delivered""#) && log.contains(r#""kind":"issuer-unavailable""#)
    );
    assert!(verify(&b.log()).is_ok());
}

#[test]
fn keys_are_private_and_never_overwritten() {
    let b = Box::new("files");
    for key in [
        b.dir.join(pki::CA_KEY),
        b.dir.join(pki::SERVER_KEY),
        b.keys.join("hermes.key"),
    ] {
        assert_eq!(mode(&key), 0o600, "{}", key.display());
        assert!(fs::read_to_string(&key).unwrap().contains("PRIVATE KEY"));
    }
    // Key-Box keeps the agent's certificate, not its private key.
    let on_file: Vec<_> = fs::read_dir(b.dir.join(pki::AGENTS_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(on_file.len(), 2);
    for name in &on_file {
        let text = fs::read_to_string(b.dir.join(pki::AGENTS_DIR).join(name)).unwrap();
        assert!(name.ends_with(".pem") && !text.contains("PRIVATE KEY"));
    }
    let ca_before = fs::read(b.dir.join(pki::CA_KEY)).unwrap();
    assert!(pki::init(&b.dir, &["localhost".to_owned()]).is_err());
    assert!(pki::issue_agent(&b.dir, &agent("hermes"), &b.keys).is_err());
    assert_eq!(fs::read(b.dir.join(pki::CA_KEY)).unwrap(), ca_before);
}

#[test]
fn refuses_to_listen_on_all_interfaces() {
    let b = Box::new("listen");
    block_on(async {
        for addr in ["0.0.0.0:0", "[::]:0"] {
            let out = Server::bind(addr.parse().unwrap(), &b.dir, b.core(), TIMEOUT).await;
            assert!(matches!(out, Err(Error::Usage(_))), "{addr}");
        }
    });
}
