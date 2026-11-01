//! Short-lived SSH certificates.
//!
//! Each customer has its own certificate authority; its private key is a
//! fixed key and never leaves Key-Box. The agent sends the public half of a
//! key pair it made itself, and gets back a certificate for it that is good
//! for one user name, from the agent machine's address only, for a short
//! time, and, where the policy says so, for one command only.
//!
//! A certificate cannot be withdrawn once issued. It is short and narrow so
//! that it does not need to be.

use keybox_core::ident::{Pin, SshPublicKey};
use keybox_policy::SshCert;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, PrivateKey, PublicKey};

use crate::secrets::Secret;

/// How far a certificate is backdated, for a server whose clock is behind.
const BACKDATE_SECS: u64 = 60;

/// What is handed to the agent.
pub struct Certificate {
    /// One line in OpenSSH format, to be saved next to the private key as
    /// `<key>-cert.pub`.
    pub line: String,
    pub valid_before: u64,
}

/// Sign a certificate for `public_key`. `key_id` is what the server's log
/// will show for each login; `nonce` and `serial` are fresh random values.
#[allow(clippy::too_many_arguments)]
pub fn certify(
    now: u64,
    ca_key: &Secret,
    public_key: &SshPublicKey,
    rule: &SshCert,
    pin: Option<&Pin>,
    key_id: &str,
    nonce: [u8; 32],
    serial: u64,
) -> Result<Certificate, &'static str> {
    let ca = PrivateKey::from_openssh(ca_key.expose()).map_err(|_| "ssh-bad-ca")?;
    if ca.is_encrypted() || ca.algorithm() != Algorithm::Ed25519 {
        return Err("ssh-bad-ca");
    }
    let subject = PublicKey::from_openssh(public_key.as_str()).map_err(|_| "ssh-bad-public-key")?;
    if subject.algorithm() != Algorithm::Ed25519 {
        return Err("ssh-bad-public-key");
    }

    let valid_before = now + rule.ttl_secs;
    let failed = |_| "ssh-sign-failed";
    let mut builder = Builder::new(
        nonce,
        subject.key_data().clone(),
        now.saturating_sub(BACKDATE_SECS),
        valid_before,
    )
    .map_err(failed)?;
    builder.serial(serial).map_err(failed)?;
    builder.cert_type(CertType::User).map_err(failed)?;
    builder.key_id(key_id).map_err(failed)?;
    // Exactly one user name. Never "all principals".
    builder
        .valid_principal(rule.principal.as_str())
        .map_err(failed)?;
    builder
        .critical_option("source-address", rule.source_address.join(","))
        .map_err(failed)?;
    match rule.force_command_for(pin) {
        // Locked to one command: nothing else is granted, not even a terminal.
        Some(command) => {
            builder
                .critical_option("force-command", command)
                .map_err(failed)?;
        }
        // A shell needs a terminal. Forwarding of ports, agents and X11 stays off.
        None => {
            builder.extension("permit-pty", "").map_err(failed)?;
        }
    }
    let certificate = builder.sign(&ca).map_err(failed)?;
    Ok(Certificate {
        line: certificate.to_openssh().map_err(failed)?,
        valid_before,
    })
}
