//! `keyboxd`: set up certificates and passkeys, run the daemon, check the log.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keybox_core::ident::{AgentId, CredentialId};
use keybox_log::{AuditLog, Record};
use keybox_webauthn::Site;
use keyboxd::core::Core;
use keyboxd::github::Github;
use keyboxd::https::HttpsClient;
use keyboxd::issuer::Issuer;
use keyboxd::secrets::{DirSecrets, RbwSecrets, Secrets};
use keyboxd::server::Server;
use keyboxd::web::WebServer;
use keyboxd::{Error, client, passkeys, pki};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the policy files are looked at, to announce a new proposal.
const POLICY_WATCH: Duration = Duration::from_secs(30);
/// For each call Key-Box itself makes to an issuer such as GitHub.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(8);
/// For each run of rbw. Unlocking the vault takes a moment the first time.
const SECRET_TIMEOUT: Duration = Duration::from_secs(15);

const USAGE: &str = "\
usage:
  keyboxd init-pki     --dir DIR --name NAME [--name NAME ...]
  keyboxd issue-agent  --dir DIR --out DIR AGENT
  keyboxd revoke-agent --dir DIR AGENT
  keyboxd enroll-token --dir DIR
  keyboxd remove-passkey --dir DIR NAME      (stop the service first)
  keyboxd check-policy DIR
  keyboxd serve        --dir DIR --policy-dir DIR --listen ADDR:PORT
                       --web-listen ADDR:PORT --origin https://NAME
                       --web-cert FILE --web-key FILE [--min-passkeys N]
                       [--rbw PROGRAM | --secrets-dir DIR]
                       [--agent-allow IP,IP] [--web-allow IP,IP]
  keyboxd call         --addr ADDR:PORT --name NAME --ca FILE --cert FILE --key FILE JSON
  keyboxd verify-log   FILE";

/// `--flag value` pairs and the remaining words, in order.
struct Args {
    flags: Vec<(String, String)>,
    rest: Vec<String>,
}

impl Args {
    fn parse(words: impl Iterator<Item = String>) -> Result<Self, Error> {
        let mut args = Args {
            flags: Vec::new(),
            rest: Vec::new(),
        };
        let mut words = words;
        while let Some(word) = words.next() {
            match word.strip_prefix("--") {
                Some(flag) => {
                    let value = words.next().ok_or(Error::Usage(USAGE))?;
                    args.flags.push((flag.to_owned(), value));
                }
                None => args.rest.push(word),
            }
        }
        Ok(args)
    }

    fn all(&self, flag: &str) -> Vec<String> {
        self.flags
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn one(&self, flag: &str) -> Result<String, Error> {
        match self.all(flag).as_slice() {
            [value] => Ok(value.clone()),
            _ => Err(Error::Usage(USAGE)),
        }
    }

    fn path(&self, flag: &str) -> Result<PathBuf, Error> {
        self.one(flag).map(PathBuf::from)
    }

    fn addr(&self, flag: &str) -> Result<SocketAddr, Error> {
        self.one(flag)?
            .parse()
            .map_err(|_| Error::Usage("address must be IP:PORT"))
    }

    fn only(&self) -> Result<&str, Error> {
        match self.rest.as_slice() {
            [word] => Ok(word),
            _ => Err(Error::Usage(USAGE)),
        }
    }

    fn agent(&self) -> Result<AgentId, Error> {
        AgentId::new(self.only()?).map_err(|_| Error::Usage("agent name must be a-z, 0-9 and -"))
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// The page's origin and the domain passkeys are bound to. HTTPS only.
fn site(origin: &str) -> Result<Site, Error> {
    const BAD: Error = Error::Usage("origin must look like https://name or https://name:port");
    let host = origin.strip_prefix("https://").ok_or(BAD)?;
    let rp_id = host.split(':').next().unwrap_or(host);
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-';
    if rp_id.is_empty() || !rp_id.chars().all(plain) || host.contains('/') {
        return Err(BAD);
    }
    Ok(Site {
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
    })
}

fn serve(args: &Args) -> Result<(), Error> {
    let dir = args.path("dir")?;
    // Key-Box runs on the policy that was last approved with a passkey. The
    // files in --policy-dir are only a proposal, shown on the approval page.
    let mut core = Core::open(&dir, site(&args.one("origin")?)?)?;
    core.policy_dir = Some(args.path("policy-dir")?);
    // One passkey is allowed, as an explicit choice. Zero never is.
    if let [n] = args.all("min-passkeys").as_slice() {
        core.min_passkeys = match n.parse() {
            Ok(n @ 1..=8) => n,
            _ => return Err(Error::Usage("--min-passkeys must be between 1 and 8")),
        };
    }
    let (notices, queue) = tokio::sync::mpsc::channel(keyboxd::push::QUEUE);
    core.notices = Some(notices);
    let core = Arc::new(Mutex::new(core));
    let (listen, web_listen) = (args.addr("listen")?, args.addr("web-listen")?);
    let (cert, key) = (args.path("web-cert")?, args.path("web-key")?);
    runtime()?.block_on(async {
        let mut agents = Server::bind(listen, &dir, core.clone(), IO_TIMEOUT).await?;
        // Without a place to get secrets from nothing can be issued;
        // requests can still be made and approved.
        let secrets: Option<Arc<dyn Secrets>> = match (
            args.all("rbw").as_slice(),
            args.all("secrets-dir").as_slice(),
        ) {
            ([rbw], []) => Some(Arc::new(RbwSecrets {
                program: PathBuf::from(rbw),
                timeout: SECRET_TIMEOUT,
            })),
            ([], [dir]) => Some(Arc::new(DirSecrets(PathBuf::from(dir)))),
            ([], []) => None,
            _ => return Err(Error::Usage("give either --rbw or --secrets-dir, once")),
        };
        // Notifications to the phone, and a look at the policy files now and then.
        let push = HttpsClient::public(ISSUE_TIMEOUT)?;
        tokio::spawn(keyboxd::push::run(
            queue,
            core.clone(),
            push,
            keyboxd::push::GAP,
        ));
        tokio::spawn(keyboxd::push::watch_policy(core.clone(), POLICY_WATCH));
        let mut web = WebServer::bind(web_listen, &cert, &key, core, IO_TIMEOUT).await?;
        if let Some(secrets) = secrets {
            let issuer = Arc::new(Issuer {
                secrets,
                github: Github::new(HttpsClient::public(ISSUE_TIMEOUT)?),
            });
            agents = agents.with_issuer(issuer.clone());
            web = web.with_issuer(issuer);
        }
        // Who may connect at all. Given as a flag, it must name at least one address.
        if let [list] = args.all("agent-allow").as_slice() {
            agents = agents.with_allowed(keyboxd::allow_list(list)?);
        }
        if let [list] = args.all("web-allow").as_slice() {
            web = web.with_allowed(keyboxd::allow_list(list)?);
        }
        // Either listener ends only when the audit log cannot be written.
        let web = tokio::spawn(web.run());
        let error = agents.run().await;
        web.abort();
        Err(error)
    })
}

/// Take a passkey off file, for a lost or stolen device. Opens the audit log,
/// so it only works while the service is stopped, and the removal is logged.
fn remove_passkey(args: &Args) -> Result<(), Error> {
    let dir = args.path("dir")?;
    let name = CredentialId::new(args.only()?)
        .map_err(|_| Error::Usage("passkey name must be a-z, 0-9 and -"))?;
    let mut log = AuditLog::open(&dir.join(keyboxd::core::LOG_FILE))?;
    let mut passkeys = passkeys::Passkeys::load(&dir)?;
    if !passkeys.remove(&name)? {
        return Err(Error::Usage("no passkey by that name"));
    }
    log.append(&Record::new(keyboxd::now(), "passkey-removed").with("credential", &name))?;
    println!(
        "Passkey {name} er fjernet. {} tilbage.",
        passkeys.list().len()
    );
    Ok(())
}

fn run() -> Result<(), Error> {
    let mut words = std::env::args().skip(1);
    let command = words.next().ok_or(Error::Usage(USAGE))?;
    let args = Args::parse(words)?;
    match command.as_str() {
        "init-pki" => pki::init(&args.path("dir")?, &args.all("name")),
        "issue-agent" => pki::issue_agent(&args.path("dir")?, &args.agent()?, &args.path("out")?),
        "revoke-agent" => pki::revoke_agent(&args.path("dir")?, &args.agent()?),
        "enroll-token" => {
            let token = passkeys::new_token(&args.path("dir")?, keyboxd::now())?;
            println!("Engangs-token (gælder i 10 minutter, kan bruges én gang):\n{token}");
            Ok(())
        }
        "remove-passkey" => remove_passkey(&args),
        "check-policy" => {
            let files = keyboxd::policy::read_dir(Path::new(args.only()?))?;
            let loaded = keybox_policy::load_files(&files)?;
            println!(
                "ok: {} filer, {} handlinger",
                files.len(),
                loaded.actions().count()
            );
            for (what, (text, _)) in keyboxd::policy::describe(&loaded) {
                println!("  {what}: {text}");
            }
            Ok(())
        }
        "serve" => serve(&args),
        "call" => {
            let (cert, key) = (args.path("cert")?, args.path("key")?);
            let config = client::config(&args.path("ca")?, Some((&cert, &key)))?;
            let name = args.one("name")?;
            // Longer than Key-Box' own calls to an issuer can take.
            let wait = ISSUE_TIMEOUT * 4 + SECRET_TIMEOUT * 2;
            let call = client::call(args.addr("addr")?, &name, config, args.only()?, wait);
            println!("{}", runtime()?.block_on(call)?);
            Ok(())
        }
        "verify-log" => {
            let head = keybox_log::verify(Path::new(args.only()?))?;
            println!("ok: {} lines, head {}", head.seq, head.hash);
            Ok(())
        }
        _ => Err(Error::Usage(USAGE)),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keyboxd: {e}");
            ExitCode::FAILURE
        }
    }
}
