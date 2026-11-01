//! Shared test rig: a Key-Box in a temporary directory, an agent client, a
//! bare HTTPS client and a software passkey.
#![allow(dead_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keybox_core::ident::{AgentId, CredentialId};
use keybox_webauthn::{Site, base64url};
use keyboxd::core::Core;
use keyboxd::passkeys::{Passkey, Passkeys, new_token};
use keyboxd::server::Server;
use keyboxd::web::WebServer;
use keyboxd::{Error, client, pki};
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const POLICY: &str = r#"
[github_apps.github-app]
client_id = "Iv23liTESTCLIENTID"

[customers.acme.systems.github.actions.read-code]
level = 1
agents = ["hermes", "coder"]
targets = ["org/acme-web"]
method = { github_app = { app = "github-app", permissions = { contents = "read" } } }

[customers.acme.systems.github.actions.push]
level = 2
agents = ["hermes"]
targets = ["org/acme-web"]
method = { github_app = { app = "github-app", permissions = { contents = "write", pull_requests = "write" } } }

[customers.acme.systems.web01.actions.restart]
level = 2
agents = ["hermes"]
targets = ["web01.acme.example"]
[customers.acme.systems.web01.actions.restart.method.ssh_cert]
ca = "ssh-ca-acme"
principal = "ops"
source_address = ["100.64.0.10"]
force_command = "/usr/bin/systemctl restart nginx"

[customers.acme.systems.web01.actions.wipe-backup]
level = 3
agents = ["hermes"]
targets = ["web01.acme.example"]
[customers.acme.systems.web01.actions.wipe-backup.method.ssh_cert]
ca = "ssh-ca-acme"
principal = "ops"
source_address = ["100.64.0.10"]
force_command = "/usr/local/bin/wipe-backup"
"#;

pub const READ: &str = r#"{"op":"request","customer":"acme","system":"github","action":"read-code","target":"org/acme-web","reason":"test"}"#;
pub const RESTART: &str = r#"{"op":"request","customer":"acme","system":"web01","action":"restart","target":"web01.acme.example","reason":"test"}"#;
pub const WIPE: &str = r#"{"op":"request","customer":"acme","system":"web01","action":"wipe-backup","target":"web01.acme.example","reason":"test"}"#;
pub const TIMEOUT: Duration = Duration::from_secs(5);
pub const ORIGIN: &str = "https://localhost";

pub fn agent(s: &str) -> AgentId {
    AgentId::new(s).unwrap()
}

pub fn site() -> Site {
    Site {
        origin: ORIGIN.into(),
        rp_id: "localhost".into(),
    }
}

pub fn block_on<T>(f: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

pub fn id_of(reply: &str) -> String {
    let at = reply.find(r#""id":""#).expect("reply has an id") + 6;
    reply[at..at + 32].to_owned()
}

/// A fresh state directory with a CA, a server certificate and two agents.
pub struct Box {
    pub dir: PathBuf,
    pub keys: PathBuf,
}

impl Box {
    pub fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let b = Box {
            dir: root.join("state"),
            keys: root.join("keys"),
        };
        pki::init(&b.dir, &["localhost".to_owned()]).unwrap();
        pki::issue_agent(&b.dir, &agent("hermes"), &b.keys).unwrap();
        pki::issue_agent(&b.dir, &agent("coder"), &b.keys).unwrap();
        b
    }

    pub fn log(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    pub fn log_text(&self) -> String {
        fs::read_to_string(self.log()).unwrap()
    }

    /// Put two passkeys on file without going through the page, for tests
    /// that are about something else.
    pub fn seed_passkeys(&self) {
        let mut passkeys = Passkeys::load(&self.dir).unwrap();
        for name in ["seed-a", "seed-b"] {
            let auth = Authenticator::new(name);
            passkeys
                .add(Passkey {
                    name: CredentialId::new(name).unwrap(),
                    credential_id: auth.id.clone(),
                    public_key: auth.public(),
                    sign_count: 0,
                    synced: false,
                })
                .unwrap();
        }
    }

    /// A core whose policy in force is the test policy, as if Christian
    /// had already approved it.
    pub fn core(&self) -> Arc<Mutex<Core>> {
        let mut core = Core::open(&self.dir, site()).unwrap();
        core.install_policy(
            keyboxd::now(),
            vec![("test.toml".to_owned(), POLICY.to_owned())],
        )
        .unwrap();
        Arc::new(Mutex::new(core))
    }

    pub async fn start_agents(&self, core: Arc<Mutex<Core>>, io_timeout: Duration) -> SocketAddr {
        let server = Server::bind("127.0.0.1:0".parse().unwrap(), &self.dir, core, io_timeout)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());
        addr
    }

    pub async fn start_web(&self, core: Arc<Mutex<Core>>, io_timeout: Duration) -> SocketAddr {
        let (cert, key) = (
            self.dir.join(pki::SERVER_CERT),
            self.dir.join(pki::SERVER_KEY),
        );
        let server = WebServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            &cert,
            &key,
            core,
            io_timeout,
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());
        addr
    }

    pub fn config(&self, who: Option<&str>) -> rustls::ClientConfig {
        let ca = self.dir.join(pki::CA_CERT);
        match who {
            None => client::config(&ca, None).unwrap(),
            Some(who) => {
                let cert = self.keys.join(format!("{who}.pem"));
                let key = self.keys.join(format!("{who}.key"));
                client::config(&ca, Some((&cert, &key))).unwrap()
            }
        }
    }

    /// Call the agent API as `who`.
    pub async fn call(&self, addr: SocketAddr, who: &str, line: &str) -> Result<String, Error> {
        client::call(addr, "localhost", self.config(Some(who)), line, TIMEOUT).await
    }

    /// One raw HTTPS request to the approval page. Returns status, headers, body.
    pub async fn http(&self, addr: SocketAddr, request: &str) -> (u16, String, String) {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(self.config(None)))
            .connect(name, tcp)
            .await
            .unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(TIMEOUT, tls.read_to_end(&mut raw))
            .await
            .expect("no reply");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head.to_lowercase(), body.to_owned())
    }

    pub async fn get(&self, addr: SocketAddr, path: &str) -> (u16, String, String) {
        self.http(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        )
        .await
    }

    /// POST as the real page would.
    pub async fn post(&self, addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (status, _, reply) = self.http(addr, &request).await;
        (status, serde_json::from_str(&reply).unwrap_or(Value::Null))
    }

    /// Register `auth` under `name` with a fresh console token.
    pub async fn enroll(&self, web: SocketAddr, name: &str, auth: &Authenticator) {
        let token = new_token(&self.dir, keyboxd::now()).unwrap();
        let (status, start) = self
            .post(
                web,
                "/api/register/start",
                &json!({"name": name, "token": token}),
            )
            .await;
        assert_eq!(status, 200, "{start}");
        let mut finish = auth.create(start["challenge"].as_str().unwrap());
        finish["challenge_id"] = start["challenge_id"].clone();
        let (status, done) = self.post(web, "/api/register/finish", &finish).await;
        assert_eq!(status, 200, "{done}");
    }

    /// Run one passkey prompt for `purpose` and return the final answer.
    pub async fn sign(
        &self,
        web: SocketAddr,
        auth: &Authenticator,
        purpose: &str,
        request: Option<&str>,
    ) -> (u16, Value) {
        let (status, start) = self
            .post(
                web,
                "/api/assert/start",
                &json!({"purpose": purpose, "request": request}),
            )
            .await;
        if status != 200 {
            return (status, start);
        }
        let mut finish = auth.get(start["challenge"].as_str().unwrap());
        finish["challenge_id"] = start["challenge_id"].clone();
        self.post(web, "/api/assert/finish", &finish).await
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

/// A software passkey. `origin`, `rp_id` and `uv` can be changed to play a
/// phishing site or a device that skips biometrics.
pub struct Authenticator {
    key: EcdsaKeyPair,
    pub id: Vec<u8>,
    pub origin: String,
    pub rp_id: String,
    pub uv: bool,
}

impl Authenticator {
    pub fn new(id: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            key,
            id: format!("credential-{id}").into_bytes(),
            origin: ORIGIN.into(),
            rp_id: "localhost".into(),
            uv: true,
        }
    }

    pub fn public(&self) -> [u8; 65] {
        self.key.public_key().as_ref().try_into().unwrap()
    }

    fn header(&self, attested: bool) -> Vec<u8> {
        let mut flags = 0x01;
        if self.uv {
            flags |= 0x04;
        }
        if attested {
            flags |= 0x40;
        }
        let mut data = sha256(self.rp_id.as_bytes());
        data.push(flags);
        data.extend_from_slice(&[0, 0, 0, 0]);
        data
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    /// The answer to `navigator.credentials.create()`.
    pub fn create(&self, challenge: &str) -> Value {
        let public = self.public();
        let mut auth = self.header(true);
        auth.extend_from_slice(&[0u8; 16]);
        auth.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&self.id);
        auth.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        auth.extend_from_slice(&public[1..33]);
        auth.extend_from_slice(&[0x22, 0x58, 0x20]);
        auth.extend_from_slice(&public[33..]);
        json!({
            "client_data": base64url(&self.client_data("webauthn.create", challenge)),
            "auth_data": base64url(&auth),
        })
    }

    /// The answer to `navigator.credentials.get()`.
    pub fn get(&self, challenge: &str) -> Value {
        let client = self.client_data("webauthn.get", challenge);
        let auth = self.header(false);
        let mut signed = auth.clone();
        signed.extend_from_slice(&sha256(&client));
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        json!({
            "credential_id": base64url(&self.id),
            "client_data": base64url(&client),
            "auth_data": base64url(&auth),
            "signature": base64url(signature.as_ref()),
        })
    }
}
