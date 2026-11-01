//! A small HTTPS client for the few calls Key-Box makes itself: one request
//! per connection, TLS 1.3 or 1.2 as the other side offers, a time limit on
//! the whole exchange and a size limit on the answer.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::Error;

/// Largest response body accepted.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct HttpsClient {
    config: Arc<ClientConfig>,
    /// Limit for one whole request, connect to last byte.
    pub timeout: Duration,
}

impl HttpsClient {
    pub fn new(roots: RootCertStore, timeout: Duration) -> Result<Self, Error> {
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
            timeout,
        })
    }

    /// Trusting the public web's certificate authorities.
    pub fn public(timeout: Duration) -> Result<Self, Error> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::new(roots, timeout)
    }

    /// Send one request to `host:port` and return status and body. The
    /// certificate must be valid for `host`.
    pub async fn send(
        &self,
        host: &str,
        port: u16,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), Error> {
        let exchange = async {
            let name = ServerName::try_from(host.to_owned()).map_err(|_| Error::Tls)?;
            let tcp = TcpStream::connect((host, port)).await?;
            let tls = TlsConnector::from(self.config.clone())
                .connect(name, tcp)
                .await
                .map_err(|_| Error::Tls)?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|_| Error::Tls)?;
            let driver = tokio::spawn(connection);

            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("host", host);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let request = request
                .body(Full::new(Bytes::from(body)))
                .map_err(|_| Error::Usage("bad request"))?;
            let response = sender.send_request(request).await.map_err(|_| Error::Tls)?;
            let status = response.status().as_u16();
            let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| Error::TooLarge)?
                .to_bytes()
                .to_vec();
            driver.abort();
            Ok((status, body))
        };
        timeout(self.timeout, exchange)
            .await
            .map_err(|_| Error::Timeout)?
    }
}
