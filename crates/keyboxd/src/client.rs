//! What an agent uses to talk to Key-Box: one line out, one line back.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::Error;

/// Longest reply accepted. A reply may carry an SSH certificate or a token.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// A client that trusts only Key-Box' own CA and, if given, presents the
/// agent's certificate.
pub fn config(ca: &Path, identity: Option<(&Path, &Path)>) -> Result<ClientConfig, Error> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(ca).map_err(|_| Error::Pki)?)?;
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots);
    Ok(match identity {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder.with_client_auth_cert(
            vec![CertificateDer::from_pem_file(cert).map_err(|_| Error::Pki)?],
            PrivateKeyDer::from_pem_file(key).map_err(|_| Error::Pki)?,
        )?,
    })
}

/// Send one line and return the one-line reply. `server_name` must match the
/// name in Key-Box' certificate.
pub async fn call(
    addr: SocketAddr,
    server_name: &str,
    config: ClientConfig,
    line: &str,
    io_timeout: Duration,
) -> Result<String, Error> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::Usage("server name is not a DNS name or IP address"))?;
    let exchange = async {
        let tcp = TcpStream::connect(addr).await?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|_| Error::Tls)?;
        tls.write_all(line.as_bytes()).await?;
        tls.write_all(b"\n").await?;
        let mut reply = Vec::new();
        (&mut tls)
            .take(MAX_REPLY_BYTES as u64 + 1)
            .read_to_end(&mut reply)
            .await?;
        if reply.len() > MAX_REPLY_BYTES {
            return Err(Error::TooLarge);
        }
        match reply
            .strip_suffix(b"\n")
            .map(|r| String::from_utf8(r.to_vec()))
        {
            Some(Ok(reply)) => Ok(reply),
            // Closed without a full line: Key-Box did not accept this client.
            _ => Err(Error::Tls),
        }
    };
    timeout(io_timeout, exchange)
        .await
        .map_err(|_| Error::Timeout)?
}
