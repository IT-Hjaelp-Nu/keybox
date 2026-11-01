//! The policy as files on disk, one per customer, and the step between a
//! changed file and a changed Key-Box: Christian's passkey.
//!
//! Key-Box always runs on the policy that was last approved, which it keeps
//! in its own state. Files on disk are only a proposal. This module reads the
//! proposal, gives it a hash to approve, and says in words what would change.

use std::collections::BTreeMap;
use std::path::Path;

use keybox_core::ident::PinKind;
use keybox_core::policy::Level;
use keybox_core::request::RequestSpec;
use keybox_policy::{Access, Loaded, MAX_POLICY_BYTES, MAX_POLICY_FILES, Method, is_file_name};
use ring::digest::{Context, SHA256};

use crate::Error;

/// File name and text, sorted by name.
pub type Files = Vec<(String, String)>;

/// Read every `*.toml` directly in `dir`. Other files and all sub-directories
/// (a README, `.git`) are left alone; a `.toml` file with a name outside the
/// allowed grammar is an error rather than something to skip.
pub fn read_dir(dir: &Path) -> Result<Files, Error> {
    let mut files = Files::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(Error::Usage("a policy file has a name that is not allowed"));
        };
        if !name.ends_with(".toml") || !entry.file_type()?.is_file() {
            continue;
        }
        if !is_file_name(&name) || files.len() >= MAX_POLICY_FILES {
            return Err(Error::Usage(
                "a policy file has a name that is not allowed, or there are too many",
            ));
        }
        if entry.metadata()?.len() > MAX_POLICY_BYTES as u64 {
            return Err(Error::TooLarge);
        }
        files.push((name, std::fs::read_to_string(entry.path())?));
    }
    files.sort();
    Ok(files)
}

/// What an approval of a policy covers: every file name and every byte, each
/// length prefixed so that no two different sets of files hash alike.
pub fn hash(files: &Files) -> [u8; 32] {
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort();
    let mut context = Context::new(&SHA256);
    context.update(b"keybox-policy-v1\0");
    for (name, text) in sorted {
        for part in [name, text] {
            context.update(&(part.len() as u64).to_be_bytes());
            context.update(part.as_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

fn level(level: Level) -> u8 {
    match level {
        Level::One => 1,
        Level::Two => 2,
        Level::Three => 3,
    }
}

fn list<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every rule in words, keyed by what it is about. Shown to Christian, so it
/// names everything that decides what an agent can get.
pub fn describe(loaded: &Loaded) -> BTreeMap<String, (String, u8)> {
    let mut out = BTreeMap::new();
    for (name, client_id) in loaded.github_apps() {
        out.insert(
            format!("GitHub App {name}"),
            (format!("client id {client_id}"), 0),
        );
    }
    for (customer, system, action, rule, method) in loaded.actions() {
        let pin = match rule.pin {
            Some(PinKind::Commit) => "; kræver commit",
            Some(PinKind::Digest) => "; kræver digest",
            None => "",
        };
        let how = match method {
            Method::GithubApp(gh) => {
                let permissions = gh.permissions.iter().map(|(k, v)| {
                    format!("{k}={}", if *v == Access::Write { "skriv" } else { "læs" })
                });
                format!("GitHub-token ({}): {}", gh.app, list(permissions))
            }
            Method::SshCert(ssh) => format!(
                "SSH-certifikat: bruger {}, fra {}, kommando «{}», {} min, CA {}",
                ssh.principal,
                list(&ssh.source_address),
                ssh.force_command_template().unwrap_or("fri shell"),
                ssh.ttl_secs / 60,
                ssh.ca
            ),
        };
        let text = format!(
            "niveau {}; agenter: {}; mål: {}{pin}; {how}",
            level(rule.level),
            list(&rule.agents),
            list(&rule.targets)
        );
        out.insert(
            format!("{customer} · {system} · {action}"),
            (text, level(rule.level)),
        );
    }
    out
}

/// What one request hands the agent once it is approved, in words. Shown
/// next to the request, so Christian reads the consequence and not only names.
pub fn grants(method: &Method, spec: &RequestSpec) -> String {
    match method {
        Method::GithubApp(gh) => {
            let permissions = gh
                .permissions
                .iter()
                .map(|(k, v)| format!("{k}={}", if *v == Access::Write { "skriv" } else { "læs" }));
            format!(
                "GitHub-token til {} i 1 time: {}",
                spec.target,
                list(permissions)
            )
        }
        Method::SshCert(ssh) => {
            let what = match ssh.force_command_for(spec.pin.as_ref()) {
                Some(command) => format!("Kun kommandoen «{command}»"),
                None => "Fri shell".to_owned(),
            };
            format!(
                "{what} som {} på {}, i {} min",
                ssh.principal,
                spec.target,
                ssh.ttl_secs / 60
            )
        }
    }
}

/// One difference between the approved policy and the proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub what: String,
    pub before: Option<String>,
    pub after: Option<String>,
    /// The action would need less approval than it does now.
    pub lower_level: bool,
}

pub fn diff(old: &Loaded, new: &Loaded) -> Vec<Change> {
    let (old, new) = (describe(old), describe(new));
    let mut changes = Vec::new();
    for (what, (before, old_level)) in &old {
        match new.get(what) {
            None => changes.push(Change {
                what: what.clone(),
                before: Some(before.clone()),
                after: None,
                lower_level: false,
            }),
            Some((after, new_level)) if after != before => changes.push(Change {
                what: what.clone(),
                before: Some(before.clone()),
                after: Some(after.clone()),
                lower_level: new_level < old_level,
            }),
            Some(_) => {}
        }
    }
    for (what, (after, _)) in &new {
        if !old.contains_key(what) {
            changes.push(Change {
                what: what.clone(),
                before: None,
                after: Some(after.clone()),
                lower_level: false,
            });
        }
    }
    changes.sort_by(|a, b| a.what.cmp(&b.what));
    changes
}

/// The files on disk, compared with what is approved.
pub enum Proposal {
    /// Nothing to approve.
    Same,
    /// A valid policy that differs from the approved one.
    Pending {
        hash: [u8; 32],
        files: Files,
        changes: Vec<Change>,
    },
    /// The files do not make a valid policy. The text says where.
    Invalid(String),
    /// The directory could not be read.
    Unreadable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(list: &[(&str, &str)]) -> Files {
        list.iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
            .collect()
    }

    #[test]
    fn the_hash_covers_names_text_and_where_one_ends() {
        let base = hash(&files(&[("a.toml", "x = 1"), ("b.toml", "y = 2")]));
        // Order on disk does not matter.
        assert_eq!(
            base,
            hash(&files(&[("b.toml", "y = 2"), ("a.toml", "x = 1")]))
        );
        // Any change does.
        assert_ne!(
            base,
            hash(&files(&[("a.toml", "x = 1"), ("b.toml", "y = 3")]))
        );
        assert_ne!(
            base,
            hash(&files(&[("a.toml", "x = 1"), ("c.toml", "y = 2")]))
        );
        assert_ne!(base, hash(&files(&[("a.toml", "x = 1")])));
        assert_ne!(base, hash(&files(&[])));
        // Text cannot be moved between a name and its content, or between files.
        assert_ne!(
            hash(&files(&[("a.toml", "bc")])),
            hash(&files(&[("a.tomlb", "c")]))
        );
        assert_ne!(
            hash(&files(&[("a.toml", "x"), ("b.toml", "")])),
            hash(&files(&[("a.toml", ""), ("b.toml", "x")]))
        );
        assert_ne!(
            hash(&files(&[("a.toml", "xb.toml")])),
            hash(&files(&[("a.toml", "x"), ("b.toml", "")]))
        );
    }
}
