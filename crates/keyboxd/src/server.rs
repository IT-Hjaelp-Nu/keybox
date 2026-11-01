//! The agent API listener: TLS 1.3 with a client certificate per agent.
//!
//! One connection carries one line in and one line out. The agent's name
//! comes from its certificate and nowhere else.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keybox_api::{MAX_LINE_BYTES, Outcome, dispatch, error_line, parse};
use keybox_core::ident::{AgentId, RequestId, SshPublicKey};
use keybox_log::Record;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::core::Core;
use crate::issuer::{Issuer, Released};
use crate::{Error, pki};
use keybox_core::engine::Delivery;
use keybox_policy::Method;
use zeroize::Zeroizing;

/// Connections served at once. Further ones are dropped.
const MAX_CONNECTIONS: usize = 32;

pub struct Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    agents: Arc<BTreeMap<Vec<u8>, AgentId>>,
    core: Arc<Mutex<Core>>,
    io_timeout: Duration,
    issuer: Option<Arc<Issuer>>,
    /// Addresses that may connect. `None`: any address that can reach the listener.
    allow: Option<Arc<[std::net::IpAddr]>>,
}

impl Server {
    /// Without an issuer, released requests are answered `issuer-unavailable`.
    pub fn with_issuer(mut self, issuer: Arc<Issuer>) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// `listen` must be one specific address (the Tailscale address), never
    /// "all interfaces". `io_timeout` bounds the handshake and each read and write.
    pub async fn bind(
        listen: SocketAddr,
        dir: &Path,
        core: Arc<Mutex<Core>>,
        io_timeout: Duration,
    ) -> Result<Self, Error> {
        if listen.ip().is_unspecified() {
            return Err(Error::Usage("refusing to listen on all interfaces"));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        let ca = CertificateDer::from_pem_file(dir.join(pki::CA_CERT)).map_err(|_| Error::Pki)?;
        roots.add(ca)?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| Error::Tls)?;
        let cert =
            CertificateDer::from_pem_file(dir.join(pki::SERVER_CERT)).map_err(|_| Error::Pki)?;
        let key =
            PrivateKeyDer::from_pem_file(dir.join(pki::SERVER_KEY)).map_err(|_| Error::Pki)?;
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)?;

        let agents = pki::load_agents(dir)?
            .into_iter()
            .map(|(cert, agent)| (cert.as_ref().to_vec(), agent))
            .collect();
        Ok(Self {
            listener: TcpListener::bind(listen).await?,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            agents: Arc::new(agents),
            core,
            io_timeout,
            issuer: None,
            allow: None,
        })
    }

    /// Only these addresses may connect to the agent API. Everything here is still
    /// checked afterwards as if they were strangers.
    pub fn with_allowed(mut self, allow: Vec<std::net::IpAddr>) -> Self {
        self.allow = Some(allow.into());
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve until the audit log cannot be written. Key-Box does not run
    /// without its log, so that is the one error this returns.
    pub async fn run(self) -> Error {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (fatal_tx, mut fatal_rx) = mpsc::channel::<Error>(1);
        let accept = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = self.listener.accept().await else {
                    continue;
                };
                // Dropped before a single byte is read: no TLS, no reply.
                if self.allow.as_ref().is_some_and(|a| !a.contains(&peer.ip())) {
                    continue;
                }
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let conn = Connection {
                    acceptor: self.acceptor.clone(),
                    agents: self.agents.clone(),
                    core: self.core.clone(),
                    io_timeout: self.io_timeout,
                    issuer: self.issuer.clone(),
                };
                let fatal_tx = fatal_tx.clone();
                tokio::spawn(async move {
                    if let Err(e @ Error::Log(_)) = conn.serve(tcp).await {
                        let _ = fatal_tx.send(e).await;
                    }
                    drop(slot);
                });
            }
        });
        let error = fatal_rx.recv().await.unwrap_or(Error::Tls);
        accept.abort();
        error
    }
}

struct Connection {
    acceptor: TlsAcceptor,
    agents: Arc<BTreeMap<Vec<u8>, AgentId>>,
    core: Arc<Mutex<Core>>,
    io_timeout: Duration,
    issuer: Option<Arc<Issuer>>,
}

impl Connection {
    async fn serve(self, tcp: TcpStream) -> Result<(), Error> {
        let mut tls = timeout(self.io_timeout, self.acceptor.accept(tcp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Tls)?;

        // The handshake proved the certificate is signed by our CA. It must
        // also be the exact certificate on file for some agent.
        let agent = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| self.agents.get(leaf.as_ref()))
            .cloned();
        let Some(agent) = agent else {
            self.with_core(|core, now| core.log.append(&Record::new(now, "unknown-certificate")))?;
            return Ok(());
        };

        let line = match timeout(self.io_timeout, read_line(&mut tls)).await {
            Ok(Ok(line)) => line,
            Ok(Err(Error::TooLarge)) => {
                let reply = self.reject(&agent, "too-large")?;
                return self.reply(&mut tls, &reply).await;
            }
            _ => return Ok(()),
        };
        let reply = self.answer(&agent, &line).await?;
        self.reply(&mut tls, &reply).await
    }

    async fn reply<S: AsyncWriteExt + Unpin>(&self, tls: &mut S, reply: &str) -> Result<(), Error> {
        let write = async {
            tls.write_all(reply.as_bytes()).await?;
            tls.write_all(b"\n").await?;
            tls.shutdown().await
        };
        // A client that stops reading only loses its own answer.
        let _ = timeout(self.io_timeout, write).await;
        Ok(())
    }

    fn with_core<T>(
        &self,
        f: impl FnOnce(&mut Core, u64) -> Result<T, keybox_log::LogError>,
    ) -> Result<T, Error> {
        // A poisoned lock means a panic mid-update: stop rather than guess.
        let mut core = self
            .core
            .lock()
            .map_err(|_| Error::Log(keybox_log::LogError::Locked))?;
        let now = crate::now();
        Ok(f(&mut core, now)?)
    }

    /// Log a line that was refused before it reached the engine.
    fn reject(&self, agent: &AgentId, why: &'static str) -> Result<String, Error> {
        self.with_core(|core, now| {
            core.log
                .append(&Record::new(now, why).with("agent", agent))?;
            Ok(error_line(why))
        })
    }

    /// Run one line through the engine. Everything it caused is in the log,
    /// on disk, before the answer is returned.
    async fn answer(&self, agent: &AgentId, line: &[u8]) -> Result<Zeroizing<String>, Error> {
        let call = match parse(line) {
            Ok(call) => call,
            Err(e) => {
                let word = match e {
                    keybox_api::ApiError::Invalid(_) => "invalid",
                    _ => "malformed",
                };
                self.reject(agent, word)?;
                return Ok(Zeroizing::new(error_line(&e.to_string())));
            }
        };
        let new_id = random_id()?;
        let step = self.with_core(|core, now| {
            // No requests until Christian has registered his passkeys.
            if !core.is_set_up() && matches!(call, keybox_api::Call::Request { .. }) {
                core.log
                    .append(&Record::new(now, "not-set-up").with("agent", agent))?;
                return Ok(Step::Reply(error_line("not-set-up")));
            }
            // A certificate needs a key to certify. Say so before the engine
            // spends the approval, so the agent can fetch again with the key.
            // (Only when Key-Box can issue at all; otherwise the answer is
            // "issuer-unavailable" either way.)
            if let (
                Some(_),
                keybox_api::Call::Fetch {
                    id,
                    public_key: None,
                },
            ) = (&self.issuer, &call)
            {
                let wants_ssh = core
                    .engine
                    .spec(agent, id)
                    .and_then(|spec| core.loaded.method(spec))
                    .is_some_and(|method| matches!(method, Method::SshCert(_)));
                if wants_ssh {
                    let record = Record::new(now, "ssh-public-key-required");
                    core.log
                        .append(&record.with("request", id).with("agent", agent))?;
                    return Ok(Step::Reply(error_line("ssh-public-key-required")));
                }
            }
            if matches!(call, keybox_api::Call::List) {
                core.log
                    .append(&Record::new(now, "listed").with("agent", agent))?;
            }
            let outcome = dispatch(&mut core.engine, now, agent, new_id, call);
            core.commit()?;
            Ok(match outcome {
                Outcome::Reply(reply) => Step::Reply(reply),
                // What the policy in force says about this request is read
                // now, under the lock, and travels with it.
                Outcome::Issue {
                    id,
                    delivery,
                    public_key,
                } => {
                    let method = core.loaded.method(&delivery.spec).cloned();
                    let client_id = match &method {
                        Some(Method::GithubApp(app)) => {
                            core.loaded.github_client_id(&app.app).map(str::to_owned)
                        }
                        _ => None,
                    };
                    Step::Issue(Box::new(Release {
                        id,
                        delivery,
                        method,
                        client_id,
                        public_key,
                    }))
                }
            })
        })?;
        let Release {
            id,
            delivery,
            method,
            client_id,
            public_key,
        } = match step {
            Step::Reply(reply) => return Ok(Zeroizing::new(reply)),
            Step::Issue(release) => *release,
        };

        // The engine has released the request and closed it; that is logged.
        // Issuing happens outside the lock. If it fails the agent must ask again.
        let issued = match &self.issuer {
            Some(issuer) => {
                let released = Released {
                    id: &id,
                    agent,
                    delivery: &delivery,
                    method: method.as_ref(),
                    client_id: client_id.as_deref(),
                    public_key: public_key.as_ref(),
                };
                issuer.issue(crate::now(), &released).await
            }
            None => Err("issuer-unavailable"),
        };
        self.with_core(|core, now| {
            let record = match &issued {
                Ok(issued) => Record::new(now, "issued").word("what", issued.kind),
                Err(why) => Record::new(now, why),
            };
            core.log
                .append(&record.with("request", &id).with("agent", agent))
        })?;
        Ok(match issued {
            Ok(issued) => Zeroizing::new(format!(
                r#"{{"ok":true,"id":"{id}",{}}}"#,
                issued.members.as_str()
            )),
            Err(why) => Zeroizing::new(error_line(why)),
        })
    }
}

enum Step {
    Reply(String),
    Issue(Box<Release>),
}

/// A released request and what the policy in force says about issuing it.
struct Release {
    id: RequestId,
    delivery: Delivery,
    method: Option<Method>,
    client_id: Option<String>,
    public_key: Option<SshPublicKey>,
}

/// Read up to the first newline. More than [`MAX_LINE_BYTES`] without one is an error.
async fn read_line<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>, Error> {
    let mut line = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof));
        }
        match chunk[..n].iter().position(|b| *b == b'\n') {
            Some(end) => {
                line.extend_from_slice(&chunk[..end]);
                return if line.len() > MAX_LINE_BYTES {
                    Err(Error::TooLarge)
                } else {
                    Ok(line)
                };
            }
            None => line.extend_from_slice(&chunk[..n]),
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(Error::TooLarge);
        }
    }
}

/// 128 random bits from the operating system.
fn random_id() -> Result<RequestId, Error> {
    let hex: String = crate::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    RequestId::new(&hex).map_err(|_| Error::Pki)
}
