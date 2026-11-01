//! The Key-Box daemon: the agent API over mutual TLS.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;

pub mod client;
pub mod core;
pub mod github;
pub mod https;
pub mod issuer;
pub mod page;
pub mod passkeys;
pub mod pki;
pub mod policy;
pub mod push;
pub mod secrets;
pub mod server;
pub mod ssh;
pub mod store;
pub mod web;

/// Errors carry a fixed description only: no paths' contents, no key
/// material, nothing an agent sent.
#[derive(Debug)]
pub enum Error {
    Usage(&'static str),
    Io(io::ErrorKind),
    /// A key or certificate could not be made or read.
    Pki,
    Tls,
    Policy(keybox_policy::PolicyError),
    Log(keybox_log::LogError),
    Timeout,
    /// The other side sent more than allowed.
    TooLarge,
    /// A state file could not be read or written.
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(what) => f.write_str(what),
            Error::Io(kind) => write!(f, "i/o: {kind}"),
            Error::Pki => f.write_str("key or certificate could not be made or read"),
            Error::Tls => f.write_str("TLS failed"),
            Error::Policy(e) => e.fmt(f),
            Error::Log(e) => e.fmt(f),
            Error::Timeout => f.write_str("timed out"),
            Error::TooLarge => f.write_str("message too large"),
            Error::Storage => f.write_str("state file could not be read or written"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.kind())
    }
}

impl From<rustls::Error> for Error {
    fn from(_: rustls::Error) -> Self {
        Error::Tls
    }
}

impl From<keybox_log::LogError> for Error {
    fn from(e: keybox_log::LogError) -> Self {
        Error::Log(e)
    }
}

impl From<keybox_policy::PolicyError> for Error {
    fn from(e: keybox_policy::PolicyError) -> Self {
        Error::Policy(e)
    }
}

/// A comma-separated list of the addresses that may connect to a listener.
/// Empty, or anything that is not an address, is an error: there is no way
/// to write "everyone".
pub fn allow_list(text: &str) -> Result<Vec<std::net::IpAddr>, Error> {
    let bad = Error::Usage("allow list must be IP addresses separated by commas");
    let list: Result<Vec<_>, _> = text.split(',').map(|a| a.trim().parse()).collect();
    match list {
        Ok(list) if !list.is_empty() => Ok(list),
        _ => Err(bad),
    }
}

/// Random bytes from the operating system.
pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Pki)?;
    Ok(bytes)
}

/// Seconds since 1970.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
