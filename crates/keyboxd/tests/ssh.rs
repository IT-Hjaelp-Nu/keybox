//! SSH certificates, checked by OpenSSH itself: `ssh-keygen -L` reads what
//! Key-Box signed, and a real `sshd` decides who gets in.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::{Box, RESTART, TIMEOUT, agent, block_on, id_of};
use keybox_core::ident::{CredentialId, Pin, SshPublicKey};
use keybox_policy::{Method, SshCert};
use keyboxd::github::Github;
use keyboxd::https::HttpsClient;
use keyboxd::issuer::Issuer;
use keyboxd::secrets::{DirSecrets, Secret};
use keyboxd::server::Server;
use keyboxd::ssh::certify;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// A new Ed25519 key pair made by OpenSSH. Returns the private key's path.
fn keygen(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let (ok, text) = run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            path.to_str().unwrap(),
        ],
    );
    assert!(ok, "{text}");
    path
}

fn public_key(private: &Path) -> SshPublicKey {
    let line = std::fs::read_to_string(private.with_extension("pub")).unwrap();
    let mut parts = line.split_whitespace();
    SshPublicKey::new(&format!(
        "{} {}",
        parts.next().unwrap(),
        parts.next().unwrap()
    ))
    .unwrap()
}

fn secret(path: &Path) -> Secret {
    Secret::new(std::fs::read(path).unwrap())
}

/// An `ssh_cert` rule as the policy would hold it.
fn rule(principal: &str, source: &str, command: Option<&str>, pin: bool) -> SshCert {
    let text = format!(
        "[customers.acme.systems.web01.actions.x]\nlevel = 2\nagents = [\"hermes\"]\ntargets = [\"web01.acme.example\"]\n{}\
         [customers.acme.systems.web01.actions.x.method.ssh_cert]\nca = \"ssh-ca-acme\"\nprincipal = \"{principal}\"\n\
         source_address = [\"{source}\"]\nttl_secs = 600\n{}",
        if pin { "pin = \"commit\"\n" } else { "" },
        command
            .map(|c| format!("force_command = \"{c}\"\n"))
            .unwrap_or_default(),
    );
    let loaded = keybox_policy::load(&text).unwrap();
    let (.., method) = loaded.actions().next().unwrap();
    let Method::SshCert(rule) = method else {
        panic!("not ssh")
    };
    rule.clone()
}

/// Sign and save the certificate where OpenSSH looks for it. Returns `ssh-keygen -L`.
fn issue(now: u64, ca: &Path, key: &Path, rule: &SshCert, pin: Option<&Pin>) -> String {
    let cert = certify(
        now,
        &secret(ca),
        &public_key(key),
        rule,
        pin,
        "keybox:hermes:test",
        [7; 32],
        42,
    )
    .unwrap();
    let cert_path = PathBuf::from(format!("{}-cert.pub", key.display()));
    std::fs::write(&cert_path, format!("{}\n", cert.line)).unwrap();
    let (ok, text) = run("ssh-keygen", &["-L", "-f", cert_path.to_str().unwrap()]);
    assert!(ok, "ssh-keygen could not read the certificate: {text}");
    text
}

fn fingerprint(public: &Path) -> String {
    let (_, text) = run("ssh-keygen", &["-l", "-f", public.to_str().unwrap()]);
    text.split_whitespace().nth(1).unwrap().to_owned()
}

#[test]
fn openssh_reads_exactly_what_the_policy_says() {
    let b = Box::new("ssh-read");
    let (ca, key) = (keygen(&b.dir, "ca"), keygen(&b.dir, "agent"));
    let pin = Pin::commit(SHA).unwrap();
    let now = keyboxd::now();
    let text = issue(
        now,
        &ca,
        &key,
        &rule(
            "deploy",
            "100.64.0.10",
            Some("/usr/local/bin/deploy {commit}"),
            true,
        ),
        Some(&pin),
    );

    for want in [
        "Type: ssh-ed25519-cert-v01@openssh.com user certificate",
        "Key ID: \"keybox:hermes:test\"",
        "Serial: 42",
        &format!(
            "Signing CA: ED25519 {}",
            fingerprint(&ca.with_extension("pub"))
        ),
        &format!(
            "Public key: ED25519-CERT {}",
            fingerprint(&key.with_extension("pub"))
        ),
        &format!("force-command /usr/local/bin/deploy {SHA}"),
        "source-address 100.64.0.10",
    ] {
        assert!(text.contains(want), "missing {want:?} in:\n{text}");
    }
    // One user name and nothing else; locked to a command, so no extensions at all.
    let section = |name: &str| -> Vec<String> {
        text.lines()
            .skip_while(|l| !l.trim_start().starts_with(name))
            .skip(1)
            .take_while(|l| l.starts_with("                "))
            .map(|l| l.trim().to_owned())
            .collect()
    };
    assert_eq!(section("Principals:"), ["deploy"]);
    assert_eq!(section("Critical Options:").len(), 2);
    assert!(text.contains("Extensions: (none)"), "{text}");
    assert!(!text.contains("permit-port-forwarding") && !text.contains("permit-agent-forwarding"));

    // A shell (no forced command) gets a terminal and still no forwarding.
    let text = issue(
        now,
        &ca,
        &key,
        &rule("ops", "100.64.0.0/24", None, false),
        None,
    );
    assert_eq!(section_of(&text, "Extensions:"), ["permit-pty"]);
    assert!(text.contains("source-address 100.64.0.0/24") && !text.contains("force-command"));
}

fn section_of(text: &str, name: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| !l.trim_start().starts_with(name))
        .skip(1)
        .take_while(|l| l.starts_with("                "))
        .map(|l| l.trim().to_owned())
        .collect()
}

#[test]
fn only_an_unencrypted_ed25519_ca_and_an_ed25519_key_are_accepted() {
    let b = Box::new("ssh-keys");
    let (ca, key) = (keygen(&b.dir, "ca"), keygen(&b.dir, "agent"));
    let r = rule("ops", "100.64.0.10", None, false);
    let sign = |ca: Secret, key: &SshPublicKey| {
        certify(keyboxd::now(), &ca, key, &r, None, "id", [1; 32], 1).err()
    };
    assert_eq!(sign(secret(&ca), &public_key(&key)), None);

    assert_eq!(
        sign(Secret::new(b"ikke en noegle".to_vec()), &public_key(&key)),
        Some("ssh-bad-ca")
    );
    // The CA's public half is not a signing key.
    assert_eq!(
        sign(secret(&ca.with_extension("pub")), &public_key(&key)),
        Some("ssh-bad-ca")
    );
    // An RSA CA, and a CA key protected by a passphrase.
    let rsa = b.dir.join("rsa");
    run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-f",
            rsa.to_str().unwrap(),
        ],
    );
    assert_eq!(sign(secret(&rsa), &public_key(&key)), Some("ssh-bad-ca"));
    let locked = b.dir.join("locked");
    run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "hemmelig",
            "-f",
            locked.to_str().unwrap(),
        ],
    );
    assert_eq!(sign(secret(&locked), &public_key(&key)), Some("ssh-bad-ca"));

    // Right shape, but not a key.
    let junk = SshPublicKey::new(&format!("ssh-ed25519 {}", "A".repeat(68))).unwrap();
    assert_eq!(sign(secret(&ca), &junk), Some("ssh-bad-public-key"));
}

/// A real sshd on a local port, running as the current user and trusting one CA.
struct Sshd {
    child: Child,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sshd(dir: &Path, ca_pub: &Path) -> Option<Sshd> {
    let binary = ["/usr/bin/sshd", "/usr/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())?;
    let host = keygen(dir, "host");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nTrustedUserCAKeys {}\n\
             AuthorizedKeysFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             UsePAM no\nStrictModes no\nLogLevel VERBOSE\nPerSourcePenalties no\nMaxStartups 100\n",
            host.display(),
            dir.join("sshd.pid").display(),
            ca_pub.display()
        ),
    )
    .unwrap();
    let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
    let child = Command::new(binary)
        .args(["-D", "-e", "-f", config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .ok()?;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Sshd { child, port });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Log in with `key` and its certificate and ask to run `echo requested`.
fn login(port: u16, key: &Path, with_certificate: bool) -> (bool, String) {
    let user = std::env::var("USER").unwrap();
    let cert = format!("CertificateFile={}-cert.pub", key.display());
    let port = port.to_string();
    let target = format!("{user}@127.0.0.1");
    let mut args = vec![
        "-p",
        &port,
        "-i",
        key.to_str().unwrap(),
        "-F",
        "none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "LogLevel=ERROR",
    ];
    if with_certificate {
        args.extend(["-o", &cert]);
    } else {
        args.extend(["-o", "CertificateFile=none"]);
    }
    args.extend([target.as_str(), "echo requested"]);
    run("ssh", &args)
}

#[test]
fn a_real_sshd_lets_the_certificate_in_only_as_the_policy_allows() {
    let b = Box::new("ssh-sshd");
    let (ca, key) = (keygen(&b.dir, "ca"), keygen(&b.dir, "agent"));
    let Some(server) = sshd(&b.dir, &ca.with_extension("pub")) else {
        eprintln!("no sshd on this machine: skipping");
        return;
    };
    let user = std::env::var("USER").unwrap();
    let pin = Pin::commit(SHA).unwrap();
    let now = keyboxd::now();
    let cert_file = PathBuf::from(format!("{}-cert.pub", key.display()));

    // Locked to one command with the approved commit: that runs, whatever was asked for.
    issue(
        now,
        &ca,
        &key,
        &rule(&user, "127.0.0.1", Some("/bin/echo forced {commit}"), true),
        Some(&pin),
    );
    let (ok, out) = login(server.port, &key, true);
    assert!(ok && out.trim() == format!("forced {SHA}"), "{out}");

    // A shell certificate runs what the agent asks.
    issue(now, &ca, &key, &rule(&user, "127.0.0.1", None, false), None);
    let (ok, out) = login(server.port, &key, true);
    assert!(ok && out.trim() == "requested", "{out}");

    // The same key without its certificate is nobody.
    assert!(!login(server.port, &key, false).0);

    // From an address the certificate does not name.
    issue(now, &ca, &key, &rule(&user, "10.9.9.9", None, false), None);
    assert!(
        !login(server.port, &key, true).0,
        "source-address was not enforced"
    );

    // For another user name.
    issue(
        now,
        &ca,
        &key,
        &rule("someone-else", "127.0.0.1", None, false),
        None,
    );
    assert!(
        !login(server.port, &key, true).0,
        "principal was not enforced"
    );

    // After it has run out (600 seconds of life, signed long ago).
    issue(
        now - 10_000,
        &ca,
        &key,
        &rule(&user, "127.0.0.1", None, false),
        None,
    );
    assert!(!login(server.port, &key, true).0, "expiry was not enforced");

    // Signed by a CA the server does not trust.
    let other_ca = keygen(&b.dir, "other-ca");
    issue(
        now,
        &other_ca,
        &key,
        &rule(&user, "127.0.0.1", None, false),
        None,
    );
    assert!(
        !login(server.port, &key, true).0,
        "an unknown CA was trusted"
    );

    // And a good one still works at the end, so the refusals were real.
    issue(now, &ca, &key, &rule(&user, "127.0.0.1", None, false), None);
    assert!(login(server.port, &key, true).0);
    assert!(cert_file.exists());
}

#[test]
fn an_approved_request_becomes_a_certificate_for_the_agents_own_key() {
    let b = Box::new("ssh-stack");
    let (ca, key) = (keygen(&b.dir, "ca"), keygen(&b.dir, "agent"));
    let secrets = b.dir.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::copy(&ca, secrets.join("ssh-ca-acme")).unwrap();
    b.seed_passkeys();
    block_on(async {
        let core = b.core();
        let issuer = Issuer {
            secrets: Arc::new(DirSecrets(secrets)),
            github: Github::at(
                HttpsClient::public(Duration::from_secs(1)).unwrap(),
                "localhost",
                1,
            ),
        };
        let server = Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            &b.dir,
            core.clone(),
            TIMEOUT,
        )
        .await
        .unwrap()
        .with_issuer(Arc::new(issuer));
        let agents = server.local_addr().unwrap();
        tokio::spawn(server.run());

        let id = id_of(&b.call(agents, "hermes", RESTART).await.unwrap());
        {
            let mut core = core.lock().unwrap();
            let request = keybox_core::ident::RequestId::new(&id).unwrap();
            let binding = core.engine.binding(&request).unwrap().to_vec();
            let phone = CredentialId::new("seed-a").unwrap();
            core.engine
                .approve(keyboxd::now(), &request, &binding, &phone)
                .unwrap();
            core.commit().unwrap();
        }
        let _ = agent("hermes");

        // Without a key there is nothing to certify, and the approval is not spent.
        let bare = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert_eq!(
            b.call(agents, "hermes", &bare).await.unwrap(),
            r#"{"error":"ssh-public-key-required","ok":false}"#
        );

        let with_key = format!(
            r#"{{"op":"fetch","id":"{id}","public_key":"{}"}}"#,
            public_key(&key).as_str()
        );
        let reply: serde_json::Value =
            serde_json::from_str(&b.call(agents, "hermes", &with_key).await.unwrap()).unwrap();
        assert_eq!(reply["kind"], "ssh-certificate");
        assert_eq!(reply["host"], "web01.acme.example");
        assert_eq!(reply["principal"], "ops");

        let cert_path = b.dir.join("agent-cert.pub");
        std::fs::write(
            &cert_path,
            format!("{}\n", reply["certificate"].as_str().unwrap()),
        )
        .unwrap();
        let (ok, text) = run("ssh-keygen", &["-L", "-f", cert_path.to_str().unwrap()]);
        assert!(ok, "{text}");
        assert!(
            text.contains(&format!("Key ID: \"keybox:hermes:{id}\"")),
            "{text}"
        );
        assert!(text.contains("force-command /usr/bin/systemctl restart nginx"));
        assert!(text.contains(&format!(
            "Signing CA: ED25519 {}",
            fingerprint(&ca.with_extension("pub"))
        )));

        // One approval, one certificate.
        assert_eq!(
            b.call(agents, "hermes", &with_key).await.unwrap(),
            r#"{"error":"closed","ok":false}"#
        );
    });
    let log = b.log_text();
    assert!(
        log.contains(r#""what":"ssh-certificate""#)
            && log.contains(r#""kind":"ssh-public-key-required""#),
        "{log}"
    );
    assert!(
        !log.contains("PRIVATE KEY") && !log.contains("ssh-ed25519-cert"),
        "{log}"
    );
}
