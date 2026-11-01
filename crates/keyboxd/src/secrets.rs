//! Where Key-Box gets the fixed keys it issues from.
//!
//! A secret is looked up by name each time it is needed and is not kept. The
//! value lives in memory that is wiped on drop and has no `Debug` output.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use keybox_core::ident::SecretName;
use zeroize::Zeroizing;

/// Largest secret accepted. A 4096-bit RSA key in PEM is about 3.3 KiB.
pub const MAX_SECRET_BYTES: usize = 16 * 1024;

/// A secret value. Deliberately has no `Debug`, `Display` or `Clone`.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Says only that a secret could not be had, never why in terms of its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secret unavailable")
    }
}

pub trait Secrets: Send + Sync {
    fn get(&self, name: &SecretName) -> Result<Secret, Unavailable>;
}

/// One file per secret in a directory, named after the secret. Meant for a
/// directory only Key-Box can read, such as systemd's credentials directory.
pub struct DirSecrets(pub PathBuf);

impl Secrets for DirSecrets {
    fn get(&self, name: &SecretName) -> Result<Secret, Unavailable> {
        // A SecretName is a-z, 0-9 and '-', so it cannot leave the directory.
        let path = self.0.join(name.as_str());
        let size = std::fs::metadata(&path).map_err(|_| Unavailable)?.len();
        if size == 0 || size > MAX_SECRET_BYTES as u64 {
            return Err(Unavailable);
        }
        std::fs::read(&path)
            .map(Secret::new)
            .map_err(|_| Unavailable)
    }
}

/// No secrets at all: every issue fails closed.
pub struct NoSecrets;

impl Secrets for NoSecrets {
    fn get(&self, _: &SecretName) -> Result<Secret, Unavailable> {
        Err(Unavailable)
    }
}

/// Secrets fetched from Vaultwarden through `rbw`, each time one is needed.
///
/// The secret is the *notes* field of the vault item with the secret's name.
/// `rbw` keeps the vault unlocked in its own agent process; Key-Box holds a
/// secret only for the moment it is used.
pub struct RbwSecrets {
    /// Path to the `rbw` program.
    pub program: PathBuf,
    /// Limit for each run of `rbw`.
    pub timeout: Duration,
}

impl RbwSecrets {
    /// Run `rbw` with `args`, returning its output if it exits cleanly in time.
    fn run(&self, args: &[&str]) -> Result<Secret, Unavailable> {
        let mut child = Command::new(&self.program)
            .args(args)
            // Only what rbw needs to find its own files and its password prompt.
            .env_clear()
            .envs(
                ["HOME", "XDG_RUNTIME_DIR", "CREDENTIALS_DIRECTORY", "PATH"]
                    .iter()
                    .filter_map(|k| std::env::var_os(k).map(|v| (*k, v))),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // rbw's error text may quote what it was working on.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Unavailable)?;
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Unavailable);
                }
            }
        };
        // A secret fits in the pipe's buffer, so the program can exit before
        // this reads. One byte over the limit is read to notice an oversized answer.
        let mut out = Secret::new(Vec::new());
        let stdout = child.stdout.take().ok_or(Unavailable)?;
        stdout
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut out.0)
            .map_err(|_| Unavailable)?;
        if !status.success() || out.0.is_empty() || out.0.len() > MAX_SECRET_BYTES {
            return Err(Unavailable);
        }
        Ok(out)
    }
}

impl Secrets for RbwSecrets {
    fn get(&self, name: &SecretName) -> Result<Secret, Unavailable> {
        // Pick up changes made in Vaultwarden. If the server cannot be
        // reached, what rbw already has is still used.
        let _ = self.run(&["sync"]);
        // A SecretName is a-z, 0-9 and '-' and cannot start with '-', so it
        // cannot be taken for an option.
        self.run(&["get", "--field", "notes", name.as_str()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Writing a script and running it straight away fails with "text file
    /// busy" if another thread starts a process in between, so the tests that
    /// do it take turns.
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A stand-in for `rbw`: a shell script in a fresh directory.
    fn fake_rbw(tag: &str, script: &str) -> RbwSecrets {
        let dir = std::env::temp_dir().join(format!("keybox-rbw-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("rbw");
        std::fs::write(&program, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        RbwSecrets {
            program,
            timeout: Duration::from_millis(1500),
        }
    }

    fn name(s: &str) -> SecretName {
        SecretName::new(s).unwrap()
    }

    #[test]
    fn fetches_the_notes_field_of_the_named_item() {
        let _turn = turn();
        let rbw = fake_rbw(
            "ok",
            r#"[ "$1" = sync ] && exit 0
[ "$1 $2 $3 $4" = "get --field notes github-app" ] && printf 'LINE ONE\nLINE TWO\n' && exit 0
exit 1"#,
        );
        assert_eq!(
            rbw.get(&name("github-app")).unwrap().expose(),
            b"LINE ONE\nLINE TWO\n"
        );
        assert!(rbw.get(&name("something-else")).is_err());
    }

    #[test]
    fn a_failed_sync_does_not_stop_a_cached_secret_from_being_used() {
        let _turn = turn();
        let rbw = fake_rbw("nosync", r#"[ "$1" = sync ] && exit 1; printf cached"#);
        assert_eq!(rbw.get(&name("github-app")).unwrap().expose(), b"cached");
    }

    #[test]
    fn failure_empty_output_oversized_output_and_hanging_are_all_unavailable() {
        let _turn = turn();
        for (tag, script) in [
            (
                "fail",
                r#"[ "$1" = sync ] && exit 0; echo "error: no entry found" ; exit 1"#,
            ),
            ("empty", r#"exit 0"#),
            (
                "huge",
                r#"[ "$1" = sync ] && exit 0; head -c 20000 /dev/zero"#,
            ),
            ("hang", r#"[ "$1" = sync ] && exit 0; sleep 30"#),
        ] {
            let started = Instant::now();
            assert!(
                fake_rbw(tag, script).get(&name("github-app")).is_err(),
                "{tag}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{tag} was not cut off"
            );
        }
        let missing = RbwSecrets {
            program: "/nonexistent/rbw".into(),
            timeout: Duration::from_secs(1),
        };
        assert!(missing.get(&name("github-app")).is_err());
    }

    #[test]
    fn the_program_does_not_inherit_the_environment() {
        let _turn = turn();
        // The test process has CARGO_* and more in its environment; none of it
        // may reach the program.
        let rbw = fake_rbw(
            "env",
            r#"[ "$1" = sync ] && exit 0; env | grep -c -E '^(CARGO|RUST|SSH_|LANG)' ; exit 0"#,
        );
        let out = rbw.get(&name("github-app")).unwrap();
        assert_eq!(String::from_utf8_lossy(out.expose()).trim(), "0");
    }
}
