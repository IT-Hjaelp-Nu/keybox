//! Key-Box' own small certificate authority for the agent API.
//!
//! It signs one server certificate (so agents know they talk to Key-Box) and
//! one client certificate per agent. Being signed by the CA is not enough to
//! be let in: the daemon also requires the exact certificate to be on file in
//! `agents/`. Removing that file revokes the agent.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

use keybox_core::ident::AgentId;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use zeroize::Zeroizing;

use crate::Error;

pub const CA_KEY: &str = "agent-ca.key";
pub const CA_CERT: &str = "agent-ca.pem";
pub const SERVER_KEY: &str = "server.key";
pub const SERVER_CERT: &str = "server.pem";
pub const AGENTS_DIR: &str = "agents";

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const CA_DAYS: u32 = 3650;
const LEAF_DAYS: u32 = 365;

fn ca_params() -> Result<CertificateParams, Error> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::Pki)?;
    params.distinguished_name = name("Key-Box agent CA");
    // May sign leaf certificates only, never another CA.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    valid_for(&mut params, CA_DAYS);
    Ok(params)
}

fn name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn valid_for(params: &mut CertificateParams, days: u32) {
    let now = SystemTime::now();
    // Backdated a day so a slightly slow clock on the other side still accepts it.
    params.not_before = (now - DAY).into();
    params.not_after = (now + DAY * days).into();
}

/// Write a new file readable only by its owner. Fails if it already exists.
fn write_new(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn make_dir(path: &Path) -> Result<(), Error> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e.into()),
        _ => Ok(()),
    }
}

/// Create the CA and the server certificate. `server_names` are the DNS names
/// or IP addresses agents will connect to. Refuses to overwrite an existing CA.
pub fn init(dir: &Path, server_names: &[String]) -> Result<(), Error> {
    if server_names.is_empty() {
        return Err(Error::Usage("at least one server name is required"));
    }
    make_dir(dir)?;
    make_dir(&dir.join(AGENTS_DIR))?;

    let ca_key = KeyPair::generate().map_err(|_| Error::Pki)?;
    let ca_params = ca_params()?;
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|_| Error::Pki)?;
    write_new(
        &dir.join(CA_KEY),
        Zeroizing::new(ca_key.serialize_pem()).as_bytes(),
    )?;
    write_new(&dir.join(CA_CERT), ca_cert.pem().as_bytes())?;

    let server_key = KeyPair::generate().map_err(|_| Error::Pki)?;
    let mut params = CertificateParams::new(server_names.to_vec())
        .map_err(|_| Error::Usage("server name is not a DNS name or IP address"))?;
    params.distinguished_name = name("Key-Box");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    valid_for(&mut params, LEAF_DAYS);
    let issuer = Issuer::new(ca_params, ca_key);
    let cert = params
        .signed_by(&server_key, &issuer)
        .map_err(|_| Error::Pki)?;
    write_new(
        &dir.join(SERVER_KEY),
        Zeroizing::new(server_key.serialize_pem()).as_bytes(),
    )?;
    write_new(&dir.join(SERVER_CERT), cert.pem().as_bytes())?;
    Ok(())
}

/// Create a key and certificate for `agent` in `out_dir`, to be moved to the
/// agent's machine, and put the certificate on file so the daemon lets it in.
/// Key-Box keeps no copy of the agent's private key.
pub fn issue_agent(dir: &Path, agent: &AgentId, out_dir: &Path) -> Result<(), Error> {
    let on_file = dir.join(AGENTS_DIR).join(format!("{agent}.pem"));
    if on_file.exists() {
        return Err(Error::Usage(
            "agent already has a certificate; revoke it first",
        ));
    }
    let ca_pem = Zeroizing::new(fs::read_to_string(dir.join(CA_KEY))?);
    let ca_key = KeyPair::from_pem(&ca_pem).map_err(|_| Error::Pki)?;
    let issuer = Issuer::new(ca_params()?, ca_key);

    let key = KeyPair::generate().map_err(|_| Error::Pki)?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::Pki)?;
    params.distinguished_name = name(agent.as_str());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.use_authority_key_identifier_extension = true;
    valid_for(&mut params, LEAF_DAYS);
    let cert = params.signed_by(&key, &issuer).map_err(|_| Error::Pki)?;

    make_dir(out_dir)?;
    write_new(
        &out_dir.join(format!("{agent}.key")),
        Zeroizing::new(key.serialize_pem()).as_bytes(),
    )?;
    write_new(&out_dir.join(format!("{agent}.pem")), cert.pem().as_bytes())?;
    write_new(&on_file, cert.pem().as_bytes())?;
    Ok(())
}

/// Take an agent's certificate off file. Takes effect when the daemon restarts.
pub fn revoke_agent(dir: &Path, agent: &AgentId) -> Result<(), Error> {
    fs::remove_file(dir.join(AGENTS_DIR).join(format!("{agent}.pem")))?;
    Ok(())
}

/// The certificates on file, each with the agent it identifies. The agent's
/// name is the file name, which only Key-Box' administrator can write.
pub fn load_agents(dir: &Path) -> Result<Vec<(CertificateDer<'static>, AgentId)>, Error> {
    let mut agents = Vec::new();
    for entry in fs::read_dir(dir.join(AGENTS_DIR))? {
        let path = entry?.path();
        let stem = path.file_stem().and_then(|s| s.to_str());
        let agent = match (stem, path.extension().and_then(|e| e.to_str())) {
            (Some(stem), Some("pem")) => AgentId::new(stem).map_err(|_| Error::Pki)?,
            _ => return Err(Error::Pki),
        };
        let cert = CertificateDer::from_pem_file(&path).map_err(|_| Error::Pki)?;
        agents.push((cert, agent));
    }
    Ok(agents)
}
