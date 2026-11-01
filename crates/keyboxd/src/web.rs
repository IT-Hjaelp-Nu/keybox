//! The approval page over HTTPS.
//!
//! Reaching this listener proves nothing: it is on the tailnet, and an agent
//! machine is on the tailnet too. So nothing here grants anything by itself.
//! Viewing is open, closing a request is open, and everything else needs a
//! passkey signature that `core` verifies.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use keybox_webauthn::base64url_decode;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::core::{Core, Deny};
use crate::issuer::Issuer;
use crate::push::Subscription;
use crate::{Error, page};

const MAX_CONNECTIONS: usize = 32;
/// Largest request body. A passkey response is about 1 KiB.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   worker-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

pub struct WebServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    core: Arc<Mutex<Core>>,
    io_timeout: Duration,
    /// Sent to browsers that speak plain HTTP to this port.
    redirect: Arc<str>,
    issuer: Option<Arc<Issuer>>,
    /// Addresses that may connect. `None`: any address that can reach the listener.
    allow: Option<Arc<[std::net::IpAddr]>>,
}

type Reply = Response<Full<Bytes>>;

impl WebServer {
    /// `listen` must be one specific address (the Tailscale address).
    pub async fn bind(
        listen: SocketAddr,
        cert: &Path,
        key: &Path,
        core: Arc<Mutex<Core>>,
        io_timeout: Duration,
    ) -> Result<Self, Error> {
        if listen.ip().is_unspecified() {
            return Err(Error::Usage("refusing to listen on all interfaces"));
        }
        let chain: Vec<_> = CertificateDer::pem_file_iter(cert)
            .map_err(|_| Error::Pki)?
            .collect::<Result<_, _>>()
            .map_err(|_| Error::Pki)?;
        let key = PrivateKeyDer::from_pem_file(key).map_err(|_| Error::Pki)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
        let origin = core.lock().map_err(|_| Error::Storage)?.site.origin.clone();
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {origin}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        Ok(Self {
            redirect: redirect.into(),
            issuer: None,
            allow: None,
            listener: TcpListener::bind(listen).await?,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            core,
            io_timeout,
        })
    }

    /// With an issuer, an emergency stop also shuts the issued accesses off
    /// at their source.
    pub fn with_issuer(mut self, issuer: Arc<Issuer>) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Only these addresses may connect to the approval page. Everything here is still
    /// checked afterwards as if they were strangers.
    pub fn with_allowed(mut self, allow: Vec<std::net::IpAddr>) -> Self {
        self.allow = Some(allow.into());
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve until the audit log cannot be written.
    pub async fn run(self) -> Error {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (fatal_tx, mut fatal_rx) = mpsc::channel::<()>(1);
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
                let acceptor = self.acceptor.clone();
                let core = self.core.clone();
                let fatal_tx = fatal_tx.clone();
                let io_timeout = self.io_timeout;
                let redirect = self.redirect.clone();
                let issuer = self.issuer.clone();
                tokio::spawn(async move {
                    let serve = async {
                        let mut tcp = tcp;
                        // A TLS connection starts with byte 0x16. Anything else is a
                        // browser that was given http:// instead of https://. Send it
                        // to the right address; the address is ours, never the caller's.
                        let mut first = [0u8; 1];
                        if tcp.peek(&mut first).await.ok()? == 1 && first[0] != 0x16 {
                            let mut request = [0u8; 2048];
                            let _ = tcp.read(&mut request).await;
                            let _ = tcp.write_all(redirect.as_bytes()).await;
                            let _ = tcp.shutdown().await;
                            return None;
                        }
                        let tls = acceptor.accept(tcp).await.ok()?;
                        let service = service_fn(|req| handle(req, core.clone(), issuer.clone()));
                        http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(io_timeout)
                            .keep_alive(false)
                            .max_buf_size(MAX_BODY_BYTES)
                            .serve_connection(TokioIo::new(tls), service)
                            .await
                            .ok()
                    };
                    // One request per connection, and a hard limit on its whole life.
                    let _ = timeout(io_timeout * 3, serve).await;
                    if core.lock().map_or(true, |c| c.log_failed) {
                        let _ = fatal_tx.send(()).await;
                    }
                    drop(slot);
                });
            }
        });
        let _ = fatal_rx.recv().await;
        accept.abort();
        Error::Log(keybox_log::LogError::Io(std::io::ErrorKind::Other))
    }
}

fn reply(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> Reply {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    let mut set = |name, value: &'static str| headers.insert(name, HeaderValue::from_static(value));
    set(header::CONTENT_TYPE, content_type);
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(header::CACHE_CONTROL, "no-store");
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "no-referrer");
    set(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    response
}

fn json_reply(status: u16, body: &Value) -> Reply {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    reply(status, "application/json", body.to_string())
}

fn deny(status: u16, word: &'static str) -> Reply {
    json_reply(status, &json!({ "ok": false, "error": word }))
}

fn header_is(req: &Request<Incoming>, name: header::HeaderName, want: &str) -> bool {
    req.headers().get(name).and_then(|v| v.to_str().ok()) == Some(want)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterStart {
    name: String,
    token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    challenge_id: String,
    client_data: String,
    auth_data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertStart {
    purpose: String,
    request: Option<String>,
    subscription: Option<NewSubscription>,
}

/// A browser's push subscription, as the browser states it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSubscription {
    endpoint: String,
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotifyOff {
    endpoint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertFinish {
    challenge_id: String,
    credential_id: String,
    client_data: String,
    auth_data: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    request: String,
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Deny> {
    serde_json::from_slice(body).map_err(|_| Deny(400, "malformed"))
}

fn bytes(text: &str) -> Result<Vec<u8>, Deny> {
    base64url_decode(text).ok_or(Deny(400, "malformed"))
}

/// The POST endpoints. Each parses its own exact shape and calls `core`.
fn api(core: &mut Core, now: u64, path: &str, body: &[u8]) -> Result<Value, Deny> {
    match path {
        "/api/register/start" => {
            let r: RegisterStart = parse(body)?;
            core.register_start(now, &r.name, r.token.as_deref())
        }
        "/api/register/finish" => {
            let r: RegisterFinish = parse(body)?;
            core.register_finish(
                now,
                &r.challenge_id,
                &bytes(&r.client_data)?,
                &bytes(&r.auth_data)?,
            )
        }
        "/api/assert/start" => {
            let r: AssertStart = parse(body)?;
            let subscription = match &r.subscription {
                Some(s) => Some(
                    Subscription::new(
                        &core.push_origins,
                        &s.endpoint,
                        &bytes(&s.p256dh)?,
                        &bytes(&s.auth)?,
                    )
                    .map_err(|word| Deny(400, word))?,
                ),
                None => None,
            };
            core.assert_start(now, &r.purpose, r.request.as_deref(), subscription)
        }
        "/api/assert/finish" => {
            let r: AssertFinish = parse(body)?;
            core.assert_finish(
                now,
                &r.challenge_id,
                &bytes(&r.credential_id)?,
                &bytes(&r.client_data)?,
                &bytes(&r.auth_data)?,
                &bytes(&r.signature)?,
            )
        }
        "/api/notify/off" => {
            let r: NotifyOff = parse(body)?;
            core.notify_off(now, &r.endpoint)
        }
        "/api/cancel" => {
            let r: Cancel = parse(body)?;
            core.cancel(now, &r.request)
        }
        _ => Err(Deny(404, "not-found")),
    }
}

async fn handle(
    req: Request<Incoming>,
    core: Arc<Mutex<Core>>,
    issuer: Option<Arc<Issuer>>,
) -> Result<Reply, Infallible> {
    Ok(respond(req, &core, issuer.as_deref()).await)
}

/// After an emergency stop is in force: suspend the GitHub App, so tokens
/// already handed out stop working now instead of within the hour.
async fn after_stop(core: &Mutex<Core>, issuer: &Issuer) {
    let Ok(apps) = core.lock().map(|c| c.github_apps()) else {
        return;
    };
    let (done, failed) = issuer.suspend_all(crate::now(), &apps).await;
    if let Ok(mut core) = core.lock() {
        core.github_stopped(crate::now(), &done, failed);
    }
}

/// After Key-Box is switched back on: lift the suspensions that stop made.
async fn after_resume(core: &Mutex<Core>, issuer: &Issuer) {
    let Ok(suspended) = core.lock().map(|c| c.github_suspended()) else {
        return;
    };
    let Ok(apps) = core.lock().map(|c| c.github_apps()) else {
        return;
    };
    let left = issuer.resume(crate::now(), &apps, &suspended).await;
    if let Ok(mut core) = core.lock() {
        core.github_resumed(crate::now(), suspended.len() - left.len(), &left);
    }
}

async fn respond(req: Request<Incoming>, core: &Mutex<Core>, issuer: Option<&Issuer>) -> Reply {
    let (origin, host) = {
        let Ok(core) = core.lock() else {
            return deny(500, "log");
        };
        let origin = core.site.origin.clone();
        let host = origin.split_once("://").map_or("", |(_, h)| h).to_owned();
        (origin, host)
    };
    // A request for another name is someone pointing their own domain at us.
    if !header_is(&req, header::HOST, &host) {
        return deny(421, "wrong-host");
    }
    let path = req.uri().path().to_owned();
    match *req.method() {
        Method::GET => match path.as_str() {
            "/" => match core.lock() {
                Ok(mut core) => {
                    let html = page::render(&mut core, crate::now());
                    reply(StatusCode::OK, "text/html; charset=utf-8", html)
                }
                Err(_) => deny(500, "log"),
            },
            // A mark of what the page would show now. The open page asks for
            // it and reloads itself when it differs from the one it carries.
            "/state" => match core.lock() {
                Ok(mut core) => {
                    json_reply(200, &json!({ "v": page::version(&mut core, crate::now()) }))
                }
                Err(_) => deny(500, "log"),
            },
            "/app.js" => reply(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                page::SCRIPT,
            ),
            // The service worker that shows notifications. It handles no
            // page loads, so it can neither cache nor alter the page.
            "/sw.js" => reply(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                page::WORKER,
            ),
            "/style.css" => reply(StatusCode::OK, "text/css; charset=utf-8", page::STYLE),
            _ => deny(404, "not-found"),
        },
        Method::POST => {
            // Another site open in the same browser can send a POST here, but
            // the browser then states that site's origin. Only our own page may post.
            if !header_is(&req, header::ORIGIN, &origin) {
                return deny(403, "wrong-origin");
            }
            if !header_is(&req, header::CONTENT_TYPE, "application/json") {
                return deny(415, "json-only");
            }
            let body = match Limited::new(req.into_body(), MAX_BODY_BYTES)
                .collect()
                .await
            {
                Ok(body) => body.to_bytes(),
                Err(_) => return deny(413, "too-large"),
            };
            // The lock is released before anything that waits on the network.
            let result = match core.lock() {
                Ok(mut core) => api(&mut core, crate::now(), &path, &body),
                Err(_) => return deny(500, "log"),
            };
            match result {
                Ok(value) => {
                    if let Some(issuer) = issuer {
                        match value["done"].as_str() {
                            Some("stop") => after_stop(core, issuer).await,
                            Some("resume") => after_resume(core, issuer).await,
                            _ => {}
                        }
                    }
                    json_reply(200, &value)
                }
                Err(Deny(status, word)) => deny(status, word),
            }
        }
        _ => deny(405, "method"),
    }
}
