//! Registered passkeys, and the one-time console token that lets the first
//! ones be registered.
//!
//! A passkey record holds a public key only. It is kept in a small file that
//! is rewritten whole and swapped in, so it is never half written.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use keybox_core::ident::CredentialId;
use keybox_webauthn::{PUBLIC_KEY_BYTES, base64url, base64url_decode};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::{Error, random};

pub const PASSKEYS_FILE: &str = "passkeys.json";
pub const TOKEN_FILE: &str = "enroll.token";
/// How long a console token can be used.
pub const TOKEN_TTL_SECS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    /// The name Christian gave it, e.g. `phone`. Used in the log.
    pub name: CredentialId,
    pub credential_id: Vec<u8>,
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub sign_count: u32,
    /// The provider can sync it to other devices.
    pub synced: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    name: String,
    credential_id: String,
    public_key: String,
    sign_count: u32,
    synced: bool,
}

pub struct Passkeys {
    path: PathBuf,
    list: Vec<Passkey>,
}

impl Passkeys {
    /// Load the file, or start empty if there is none. A file that does not
    /// parse is an error: Key-Box must not quietly forget who may approve.
    pub fn load(dir: &Path) -> Result<Self, Error> {
        let path = dir.join(PASSKEYS_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    list: Vec::new(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        let stored: Vec<Stored> = serde_json::from_str(&text).map_err(|_| Error::Storage)?;
        let mut list = Vec::new();
        for s in stored {
            let key = base64url_decode(&s.public_key).ok_or(Error::Storage)?;
            list.push(Passkey {
                name: CredentialId::new(&s.name).map_err(|_| Error::Storage)?,
                credential_id: base64url_decode(&s.credential_id).ok_or(Error::Storage)?,
                public_key: key.try_into().map_err(|_| Error::Storage)?,
                sign_count: s.sign_count,
                synced: s.synced,
            });
        }
        Ok(Self { path, list })
    }

    pub fn list(&self) -> &[Passkey] {
        &self.list
    }

    pub fn by_credential(&self, credential_id: &[u8]) -> Option<&Passkey> {
        self.list.iter().find(|p| p.credential_id == credential_id)
    }

    pub fn has_name(&self, name: &CredentialId) -> bool {
        self.list.iter().any(|p| &p.name == name)
    }

    pub fn add(&mut self, passkey: Passkey) -> Result<(), Error> {
        self.list.push(passkey);
        self.save().inspect_err(|_| {
            self.list.pop();
        })
    }

    /// Take a passkey off file. False if there is none by that name.
    pub fn remove(&mut self, name: &CredentialId) -> Result<bool, Error> {
        let before = self.list.len();
        self.list.retain(|p| &p.name != name);
        if self.list.len() == before {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    pub fn set_sign_count(&mut self, name: &CredentialId, sign_count: u32) -> Result<(), Error> {
        if let Some(p) = self.list.iter_mut().find(|p| &p.name == name) {
            p.sign_count = sign_count;
        }
        self.save()
    }

    fn save(&self) -> Result<(), Error> {
        let stored: Vec<Stored> = self
            .list
            .iter()
            .map(|p| Stored {
                name: p.name.as_str().to_owned(),
                credential_id: base64url(&p.credential_id),
                public_key: base64url(&p.public_key),
                sign_count: p.sign_count,
                synced: p.synced,
            })
            .collect();
        let text = serde_json::to_string_pretty(&stored).map_err(|_| Error::Storage)?;
        let tmp = self.path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Make a new console token, replacing any earlier one. The caller prints it;
/// only its hash is stored, so reading the file does not reveal the token.
pub fn new_token(dir: &Path, now: u64) -> Result<String, Error> {
    let token = base64url(&random::<32>()?);
    let line = format!("{} {}\n", now + TOKEN_TTL_SECS, base64url(&hash(&token)));
    let path = dir.join(TOKEN_FILE);
    let _ = fs::remove_file(&path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(line.as_bytes())?;
    file.sync_all()?;
    Ok(token)
}

/// True if `presented` is the current, unexpired token. A correct token is
/// used up; an expired one is removed.
pub fn use_token(dir: &Path, presented: &str, now: u64) -> bool {
    let path = dir.join(TOKEN_FILE);
    let Ok(line) = fs::read_to_string(&path) else {
        return false;
    };
    let Some((expires, stored)) = line.trim_end().split_once(' ') else {
        return false;
    };
    if expires.parse::<u64>().map_or(true, |at| now >= at) {
        let _ = fs::remove_file(&path);
        return false;
    }
    // Comparing hashes, so timing says nothing about the token itself.
    if base64url(&hash(presented)) != stored {
        return false;
    }
    fs::remove_file(&path).is_ok()
}

fn hash(token: &str) -> Vec<u8> {
    digest(&SHA256, token.as_bytes()).as_ref().to_vec()
}
