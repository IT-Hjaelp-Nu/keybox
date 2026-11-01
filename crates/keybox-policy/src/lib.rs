//! The policy file: customer → system → action → level and method.
//!
//! Loading is all-or-nothing. A file with one bad rule loads nothing, so a
//! typo can never widen what is allowed.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use keybox_core::ident::{
    ActionId, AgentId, CustomerId, InvalidIdent, Pin, PinKind, SecretName, SystemId, Target,
};
use keybox_core::policy::{ActionRule, Level, Policy};
use keybox_core::request::RequestSpec;
use serde::Deserialize;

pub const MAX_POLICY_BYTES: usize = 1 << 20;
/// GitHub fixes the lifetime of an installation token.
pub const GITHUB_TOKEN_TTL_SECS: u64 = 3600;
pub const SSH_CERT_MAX_TTL_SECS: u64 = 1800;
const SSH_CERT_MIN_TTL_SECS: u64 = 60;

/// Repository permissions a GitHub App token may be given.
const GITHUB_PERMISSIONS: [&str; 7] = [
    "actions",
    "checks",
    "contents",
    "deployments",
    "issues",
    "pull_requests",
    "statuses",
];

/// Where in the file the problem is, and what it is. The policy file holds no
/// secrets, so this may be shown and logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub at: String,
    pub problem: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.at.is_empty() {
            write!(f, "policy: {}", self.problem)
        } else {
            write!(f, "policy: {}: {}", self.at, self.problem)
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// A GitHub App installation token for the one repo named by the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubApp {
    /// Vault item holding the App's private key.
    pub app: SecretName,
    pub permissions: BTreeMap<String, Access>,
}

/// An SSH certificate for the one host named by the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCert {
    /// Vault item holding the CA's private key.
    pub ca: SecretName,
    pub principal: String,
    /// Addresses the certificate is valid from. Never empty.
    pub source_address: Vec<String>,
    force_command: Option<String>,
    pub ttl_secs: u64,
}

impl SshCert {
    /// The command as written in the policy, placeholders and all.
    pub fn force_command_template(&self) -> Option<&str> {
        self.force_command.as_deref()
    }

    /// The command the certificate is locked to, with the approved commit or
    /// digest filled in. A pin is hex only, so it cannot add shell syntax.
    pub fn force_command_for(&self, pin: Option<&Pin>) -> Option<String> {
        let template = self.force_command.as_deref()?;
        Some(match pin {
            Some(pin) => template.replace(placeholder(pin.kind()), pin.as_str()),
            None => template.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    GithubApp(GithubApp),
    SshCert(SshCert),
}

#[derive(Debug, Clone)]
pub struct Loaded {
    pub policy: Policy,
    methods: BTreeMap<(CustomerId, SystemId, ActionId), Method>,
    github_apps: BTreeMap<SecretName, String>,
}

impl Loaded {
    /// How the access for `spec` is issued. `None` if the action is not in the policy.
    pub fn method(&self, spec: &RequestSpec) -> Option<&Method> {
        self.methods.get(&(
            spec.customer.clone(),
            spec.system.clone(),
            spec.action.clone(),
        ))
    }

    /// Every action with its rule and how its access is issued, in a fixed order.
    pub fn actions(
        &self,
    ) -> impl Iterator<Item = (&CustomerId, &SystemId, &ActionId, &ActionRule, &Method)> {
        self.policy.rules().filter_map(|(c, s, a, rule)| {
            let method = self.methods.get(&(c.clone(), s.clone(), a.clone()))?;
            Some((c, s, a, rule, method))
        })
    }

    /// Every GitHub App in the policy: its name and public client id.
    pub fn github_apps(&self) -> impl Iterator<Item = (&SecretName, &str)> {
        self.github_apps
            .iter()
            .map(|(name, id)| (name, id.as_str()))
    }

    /// The public client id of a GitHub App named in the policy.
    pub fn github_client_id(&self, app: &SecretName) -> Option<&str> {
        self.github_apps.get(app).map(String::as_str)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    github_apps: BTreeMap<String, RawGithubApp>,
    #[serde(default)]
    customers: BTreeMap<String, RawCustomer>,
}

/// A GitHub App. Its name is also the name of the vault item holding its
/// private key; the client id is public.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithubApp {
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCustomer {
    #[serde(default)]
    systems: BTreeMap<String, RawSystem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSystem {
    #[serde(default)]
    actions: BTreeMap<String, RawAction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAction {
    level: u8,
    agents: Vec<String>,
    targets: Vec<String>,
    pin: Option<RawPin>,
    method: RawMethod,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum RawPin {
    Commit,
    Digest,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum RawAccess {
    Read,
    Write,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RawMethod {
    GithubApp {
        app: String,
        permissions: BTreeMap<String, RawAccess>,
    },
    SshCert {
        ca: String,
        principal: String,
        source_address: Vec<String>,
        force_command: Option<String>,
        ttl_secs: Option<u64>,
    },
}

/// Most files a policy may be spread over.
pub const MAX_POLICY_FILES: usize = 500;

fn parse(text: &str) -> Result<RawFile, PolicyError> {
    if text.len() > MAX_POLICY_BYTES {
        return Err(err("", "file is too large"));
    }
    toml::from_str(text).map_err(|e| err("", e.message()))
}

/// Parse and validate a policy file.
pub fn load(text: &str) -> Result<Loaded, PolicyError> {
    build(parse(text)?)
}

/// 1-100 characters of `a-z 0-9 . _ -`, ending in `.toml`, not starting with a dot.
pub fn is_file_name(name: &str) -> bool {
    (6..=100).contains(&name.len())
        && name.ends_with(".toml")
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// Parse and validate a policy kept as several files, typically one per
/// customer. Each customer and each GitHub App must be defined in exactly one
/// file, so two files can never quietly add up to more than either says.
/// Like [`load`], it is all or nothing.
pub fn load_files(files: &[(String, String)]) -> Result<Loaded, PolicyError> {
    if files.len() > MAX_POLICY_FILES {
        return Err(err("", "too many policy files"));
    }
    let mut merged = RawFile {
        github_apps: BTreeMap::new(),
        customers: BTreeMap::new(),
    };
    let mut home: BTreeMap<String, &str> = BTreeMap::new();
    for (name, text) in files {
        if !is_file_name(name) {
            return Err(err("", "a policy file has a name that is not allowed"));
        }
        let raw = parse(text).map_err(|e| in_file(name, e))?;
        for (app, value) in raw.github_apps {
            if merged.github_apps.insert(app.clone(), value).is_some() {
                return Err(err(
                    &format!("{name}: github_apps.{app}"),
                    "defined in more than one file",
                ));
            }
        }
        for (customer, value) in raw.customers {
            if merged.customers.insert(customer.clone(), value).is_some() {
                return Err(err(
                    &format!("{name}: customers.{customer}"),
                    "defined in more than one file",
                ));
            }
            home.insert(customer, name);
        }
    }
    build(merged).map_err(|e| {
        // Say which file the faulty customer lives in.
        let customer =
            e.at.strip_prefix("customers.")
                .and_then(|rest| rest.split('.').next());
        match customer.and_then(|c| home.get(c)) {
            Some(file) => in_file(file, e),
            None => e,
        }
    })
}

fn in_file(file: &str, e: PolicyError) -> PolicyError {
    let at = if e.at.is_empty() {
        file.to_owned()
    } else {
        format!("{file}: {}", e.at)
    };
    PolicyError {
        at,
        problem: e.problem,
    }
}

fn build(raw: RawFile) -> Result<Loaded, PolicyError> {
    let mut github_apps = BTreeMap::new();
    for (name, app) in raw.github_apps {
        let at = format!("github_apps.{name}");
        let name = SecretName::new(&name).map_err(|e| ident_err(&at, e))?;
        let id = &app.client_id;
        if !(1..=40).contains(&id.len())
            || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.')
        {
            return Err(err(&at, "client_id must be 1-40 letters, digits or dots"));
        }
        github_apps.insert(name, app.client_id);
    }

    let mut policy = Policy::default();
    let mut methods = BTreeMap::new();
    for (customer, raw_customer) in raw.customers {
        let at = format!("customers.{customer}");
        let customer = CustomerId::new(&customer).map_err(|e| ident_err(&at, e))?;
        for (system, raw_system) in raw_customer.systems {
            let at = format!("{at}.systems.{system}");
            let system = SystemId::new(&system).map_err(|e| ident_err(&at, e))?;
            for (action, raw_action) in raw_system.actions {
                let at = format!("{at}.actions.{action}");
                let action = ActionId::new(&action).map_err(|e| ident_err(&at, e))?;
                let (rule, method) = check_action(&at, raw_action)?;
                if let Method::GithubApp(gh) = &method
                    && !github_apps.contains_key(&gh.app)
                {
                    return Err(err(&at, "app is not defined under [github_apps]"));
                }
                policy.insert(customer.clone(), system.clone(), action.clone(), rule);
                methods.insert((customer.clone(), system.clone(), action), method);
            }
        }
    }
    Ok(Loaded {
        policy,
        methods,
        github_apps,
    })
}

fn check_action(at: &str, raw: RawAction) -> Result<(ActionRule, Method), PolicyError> {
    let level = match raw.level {
        1 => Level::One,
        2 => Level::Two,
        3 => Level::Three,
        _ => return Err(err(at, "level must be 1, 2 or 3")),
    };
    let agents = unique(at, "agents", &raw.agents, AgentId::new)?;
    let targets = unique(at, "targets", &raw.targets, Target::new)?;
    let pin = raw.pin.map(|p| match p {
        RawPin::Commit => PinKind::Commit,
        RawPin::Digest => PinKind::Digest,
    });

    let (method, ttl_secs) = match raw.method {
        RawMethod::GithubApp { app, permissions } => {
            if pin.is_some() {
                return Err(err(at, "pin: a GitHub token cannot be held to one commit"));
            }
            if !targets.iter().all(|t| is_repo(t.as_str())) {
                return Err(err(at, "targets: a github_app target must be owner/repo"));
            }
            if permissions.is_empty() {
                return Err(err(at, "permissions must not be empty"));
            }
            if !permissions
                .keys()
                .all(|k| GITHUB_PERMISSIONS.contains(&k.as_str()))
            {
                return Err(err(at, "permissions: unknown permission"));
            }
            let app = SecretName::new(&app).map_err(|e| ident_err(at, e))?;
            let permissions = permissions
                .into_iter()
                .map(|(k, v)| match v {
                    RawAccess::Read => (k, Access::Read),
                    RawAccess::Write => (k, Access::Write),
                })
                .collect();
            (
                Method::GithubApp(GithubApp { app, permissions }),
                GITHUB_TOKEN_TTL_SECS,
            )
        }
        RawMethod::SshCert {
            ca,
            principal,
            source_address,
            force_command,
            ttl_secs,
        } => {
            if !targets.iter().all(|t| is_host(t.as_str())) {
                return Err(err(at, "targets: an ssh_cert target must be a host name"));
            }
            if !is_principal(&principal) {
                return Err(err(at, "principal is not a valid user name"));
            }
            if source_address.is_empty() {
                return Err(err(at, "source_address must not be empty"));
            }
            if !source_address.iter().all(|a| is_narrow_network(a)) {
                return Err(err(
                    at,
                    "source_address must be IP addresses or networks, not /0",
                ));
            }
            check_force_command(at, force_command.as_deref(), pin)?;
            let ttl_secs = ttl_secs.unwrap_or(SSH_CERT_MAX_TTL_SECS);
            if !(SSH_CERT_MIN_TTL_SECS..=SSH_CERT_MAX_TTL_SECS).contains(&ttl_secs) {
                return Err(err(at, "ttl_secs must be between 60 and 1800"));
            }
            let ca = SecretName::new(&ca).map_err(|e| ident_err(at, e))?;
            (
                Method::SshCert(SshCert {
                    ca,
                    principal,
                    source_address,
                    force_command,
                    ttl_secs,
                }),
                ttl_secs,
            )
        }
    };
    Ok((
        ActionRule {
            level,
            agents,
            targets,
            pin,
            ttl_secs,
        },
        method,
    ))
}

/// A pinned action must pass its pin to the command, or the approval of
/// "this commit" would not bind what actually runs.
fn check_force_command(
    at: &str,
    command: Option<&str>,
    pin: Option<PinKind>,
) -> Result<(), PolicyError> {
    let Some(command) = command else {
        return match pin {
            Some(_) => Err(err(at, "force_command is required when pin is set")),
            None => Ok(()),
        };
    };
    if !(1..=200).contains(&command.len())
        || !command.bytes().all(|c| c.is_ascii_graphic() || c == b' ')
    {
        return Err(err(
            at,
            "force_command must be 1-200 printable ASCII characters",
        ));
    }
    let wanted = pin.map(placeholder);
    let mut rest = command.to_owned();
    for kind in [PinKind::Commit, PinKind::Digest] {
        let p = placeholder(kind);
        if rest.contains(p) && wanted != Some(p) {
            return Err(err(
                at,
                "force_command uses a placeholder that pin does not provide",
            ));
        }
        rest = rest.replace(p, "");
    }
    if rest.contains(['{', '}']) {
        return Err(err(
            at,
            "force_command: only {commit} and {digest} may use braces",
        ));
    }
    if wanted.is_some_and(|p| !command.contains(p)) {
        return Err(err(at, "force_command must contain the pin placeholder"));
    }
    Ok(())
}

fn placeholder(kind: PinKind) -> &'static str {
    match kind {
        PinKind::Commit => "{commit}",
        PinKind::Digest => "{digest}",
    }
}

fn unique<T: Ord>(
    at: &str,
    field: &'static str,
    items: &[String],
    parse: fn(&str) -> Result<T, InvalidIdent>,
) -> Result<BTreeSet<T>, PolicyError> {
    let mut set = BTreeSet::new();
    for item in items {
        let value = parse(item).map_err(|e| err(at, &format!("{field}: {e}")))?;
        if !set.insert(value) {
            return Err(err(at, &format!("{field}: listed twice")));
        }
    }
    if set.is_empty() {
        return Err(err(at, &format!("{field} must not be empty")));
    }
    Ok(set)
}

fn is_repo(s: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    };
    matches!(s.split_once('/'), Some((owner, repo)) if part(owner) && part(repo))
}

fn is_host(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && !s.starts_with(['.', '-'])
}

fn is_principal(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c))
}

/// One address, or `address/prefix` with a prefix of at least 1.
fn is_narrow_network(s: &str) -> bool {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return false;
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => true,
        // No sign, no leading zero: `u8::from_str` alone would take "+8".
        Some(p) => {
            p.bytes().all(|c| c.is_ascii_digit())
                && !p.starts_with('0')
                && p.parse::<u8>().is_ok_and(|n| n <= max)
        }
    }
}

fn err(at: &str, problem: &str) -> PolicyError {
    PolicyError {
        at: at.to_owned(),
        problem: problem.to_owned(),
    }
}

fn ident_err(at: &str, e: InvalidIdent) -> PolicyError {
    err(at, &e.to_string())
}
