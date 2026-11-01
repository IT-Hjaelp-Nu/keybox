//! The policy file: what loads, and what is refused.

use keybox_core::engine::Engine;
use keybox_core::ident::{ActionId, AgentId, CustomerId, Pin, RequestId, SystemId, Target};
use keybox_core::policy::Deny;
use keybox_core::request::{Reason, RequestSpec};
use keybox_policy::{Access, MAX_POLICY_BYTES, Method, is_file_name, load, load_files};

const EXAMPLE: &str = include_str!("../../../policy.example.toml");
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn spec(c: &str, s: &str, a: &str, t: &str, pin: Option<Pin>) -> RequestSpec {
    RequestSpec {
        customer: CustomerId::new(c).unwrap(),
        system: SystemId::new(s).unwrap(),
        action: ActionId::new(a).unwrap(),
        target: Target::new(t).unwrap(),
        pin,
    }
}

/// A valid one-action file with one line swapped out.
fn ssh_with(replace: &str, with: &str) -> String {
    let base = r#"
[customers.acme.systems.web01.actions.deploy]
level = 2
agents = ["hermes"]
targets = ["web01.acme.example"]
pin = "commit"
[customers.acme.systems.web01.actions.deploy.method.ssh_cert]
ca = "ssh-ca-acme"
principal = "deploy"
source_address = ["100.64.0.10"]
force_command = "/usr/local/bin/deploy {commit}"
"#;
    assert!(base.contains(replace), "test bug: {replace}");
    base.replacen(replace, with, 1)
}

fn github_with(replace: &str, with: &str) -> String {
    let base = r#"
[github_apps.github-app]
client_id = "Iv23liTESTCLIENTID"

[customers.acme.systems.github.actions.read-code]
level = 1
agents = ["hermes"]
targets = ["org/acme-web"]
method = { github_app = { app = "github-app", permissions = { contents = "read" } } }
"#;
    assert!(base.contains(replace), "test bug: {replace}");
    base.replacen(replace, with, 1)
}

fn problem(text: &str) -> String {
    load(text)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "LOADED".into())
}

#[test]
fn example_file_loads_and_drives_the_engine() {
    let loaded = load(EXAMPLE).unwrap();
    let deploy = spec(
        "bager-jensen",
        "web01",
        "deploy",
        "web01.bager-jensen.example",
        Some(Pin::commit(SHA).unwrap()),
    );
    let Some(Method::SshCert(ssh)) = loaded.method(&deploy) else {
        panic!("deploy should be an ssh_cert action");
    };
    assert_eq!(ssh.ca.as_str(), "ssh-ca-bager-jensen");
    assert_eq!(ssh.ttl_secs, 1800);
    assert_eq!(
        ssh.force_command_for(deploy.pin.as_ref()).unwrap(),
        format!("/usr/local/bin/deploy {SHA}")
    );

    let read = spec(
        "bager-jensen",
        "github",
        "read-code",
        "IT-Hjaelp-Nu/bager-jensen-web",
        None,
    );
    let Some(Method::GithubApp(gh)) = loaded.method(&read) else {
        panic!("read-code should be a github_app action");
    };
    assert_eq!(gh.permissions.get("contents"), Some(&Access::Read));

    let mut engine = Engine::new(loaded.policy.clone());
    let id = RequestId::new(&"1".repeat(32)).unwrap();
    let reason = Reason::new("test").unwrap();
    // hermes is not listed for deploy; deployer is.
    let hermes = AgentId::new("hermes").unwrap();
    assert!(
        engine
            .submit(0, &hermes, id.clone(), deploy.clone(), reason.clone())
            .is_err()
    );
    let deployer = AgentId::new("deployer").unwrap();
    assert!(engine.submit(0, &deployer, id, deploy, reason).is_ok());
}

#[test]
fn empty_file_is_a_policy_that_allows_nothing() {
    let loaded = load("").unwrap();
    let s = spec("acme", "web01", "deploy", "web01.acme.example", None);
    let agent = AgentId::new("hermes").unwrap();
    assert_eq!(loaded.policy.check(&agent, &s), Err(Deny::UnknownCustomer));
    assert!(loaded.method(&s).is_none());
}

#[test]
fn the_two_templates_are_valid() {
    assert_eq!(problem(&ssh_with("level = 2", "level = 2")), "LOADED");
    assert_eq!(problem(&github_with("level = 1", "level = 1")), "LOADED");
}

#[test]
fn unknown_fields_are_refused_everywhere() {
    for text in [
        "extra = 1".to_owned(),
        "[customers.acme]\nnote = \"x\"".to_owned(),
        "[customers.acme.systems.web01]\nnote = \"x\"".to_owned(),
        ssh_with("level = 2", "level = 2\nauto_approve = true"),
        ssh_with(
            "principal = \"deploy\"",
            "principal = \"deploy\"\npermit_pty = true",
        ),
        github_with(
            "app = \"github-app\"",
            "app = \"github-app\", all_repos = true",
        ),
        github_with("github_app", "static_key"),
    ] {
        assert_ne!(problem(&text), "LOADED", "{text}");
    }
}

#[test]
fn bad_names_and_lists_are_refused() {
    let cases = [
        ssh_with(
            "customers.acme.systems.web01.actions.deploy]\nlevel",
            "customers.Acme.systems.web01.actions.deploy]\nlevel",
        ),
        ssh_with("level = 2", "level = 0"),
        ssh_with("level = 2", "level = 4"),
        ssh_with("level = 2", "level = \"2\""),
        ssh_with("agents = [\"hermes\"]", "agents = []"),
        ssh_with("agents = [\"hermes\"]", "agents = [\"hermes\", \"hermes\"]"),
        ssh_with("agents = [\"hermes\"]", "agents = [\"*\"]"),
        ssh_with("targets = [\"web01.acme.example\"]", "targets = []"),
        ssh_with("targets = [\"web01.acme.example\"]", "targets = [\"*\"]"),
        ssh_with(
            "targets = [\"web01.acme.example\"]",
            "targets = [\"web01.acme.example; id\"]",
        ),
        ssh_with("pin = \"commit\"", "pin = \"branch\""),
    ];
    for text in cases {
        assert_ne!(problem(&text), "LOADED", "{text}");
    }
}

#[test]
fn ssh_rules_are_enforced() {
    let cases = [
        // Target must be a host name, not a repo or user@host.
        ssh_with(
            "targets = [\"web01.acme.example\"]",
            "targets = [\"org/repo\"]",
        ),
        ssh_with(
            "targets = [\"web01.acme.example\"]",
            "targets = [\"root@web01.acme.example\"]",
        ),
        ssh_with(
            "ca = \"ssh-ca-acme\"",
            "ca = \"-----BEGIN OPENSSH PRIVATE KEY-----\"",
        ),
        ssh_with("principal = \"deploy\"", "principal = \"deploy,root\""),
        ssh_with("principal = \"deploy\"", "principal = \"\""),
        // A certificate must be tied to where the agent calls from.
        ssh_with("source_address = [\"100.64.0.10\"]", "source_address = []"),
        ssh_with(
            "source_address = [\"100.64.0.10\"]",
            "source_address = [\"0.0.0.0/0\"]",
        ),
        ssh_with(
            "source_address = [\"100.64.0.10\"]",
            "source_address = [\"::/0\"]",
        ),
        ssh_with(
            "source_address = [\"100.64.0.10\"]",
            "source_address = [\"100.64.0.10/33\"]",
        ),
        ssh_with(
            "source_address = [\"100.64.0.10\"]",
            "source_address = [\"agent-host\"]",
        ),
        ssh_with(
            "source_address = [\"100.64.0.10\"]",
            "source_address = [\"100.64.0.10,10.0.0.1\"]",
        ),
        // A pinned action whose command ignores the pin would approve nothing.
        ssh_with("force_command = \"/usr/local/bin/deploy {commit}\"\n", ""),
        ssh_with("deploy {commit}", "deploy"),
        ssh_with("deploy {commit}", "deploy {digest}"),
        ssh_with("deploy {commit}", "deploy {commit} {target}"),
        ssh_with("deploy {commit}", "deploy {commit}\\nrm -rf /"),
        ssh_with("deploy {commit}", "deploy {commit} }"),
        ssh_with("pin = \"commit\"\n", ""), // placeholder without a pin
        ssh_with("force_command", "ttl_secs = 1801\nforce_command"),
        ssh_with("force_command", "ttl_secs = 0\nforce_command"),
    ];
    for text in cases {
        assert_ne!(problem(&text), "LOADED", "{text}");
    }
}

#[test]
fn ssh_source_address_accepts_hosts_and_narrow_networks() {
    for ok in [
        "100.64.0.10",
        "100.64.0.0/24",
        "fd7a:115c:a1e0::1",
        "fd7a:115c:a1e0::/64",
    ] {
        let text = ssh_with("\"100.64.0.10\"", &format!("\"{ok}\""));
        assert_eq!(problem(&text), "LOADED", "{ok}");
    }
}

#[test]
fn github_rules_are_enforced() {
    let cases = [
        github_with("targets = [\"org/acme-web\"]", "targets = [\"acme-web\"]"),
        github_with(
            "targets = [\"org/acme-web\"]",
            "targets = [\"org/acme-web/extra\"]",
        ),
        github_with("targets = [\"org/acme-web\"]", "targets = [\"org/\"]"),
        github_with("contents = \"read\"", "contents = \"admin\""),
        github_with("contents = \"read\"", "administration = \"write\""),
        github_with("contents = \"read\"", "metadata = \"write\""),
        github_with("permissions = { contents = \"read\" }", "permissions = {}"),
        // A token cannot be held to one commit, so a pin would be a false promise.
        github_with("level = 1", "level = 2\npin = \"commit\""),
    ];
    for text in cases {
        assert_ne!(problem(&text), "LOADED", "{text}");
    }
}

#[test]
fn github_app_must_be_defined_with_a_plain_client_id() {
    let cases = [
        github_with(
            "[github_apps.github-app]\nclient_id = \"Iv23liTESTCLIENTID\"\n",
            "",
        ),
        github_with("app = \"github-app\"", "app = \"another-app\""),
        github_with("Iv23liTESTCLIENTID", ""),
        github_with("Iv23liTESTCLIENTID", "Iv23 li"),
        github_with("Iv23liTESTCLIENTID", "-----BEGIN RSA PRIVATE KEY-----"),
        github_with(
            "client_id = \"Iv23liTESTCLIENTID\"",
            "client_id = \"x\"\nprivate_key = \"y\"",
        ),
        github_with("[github_apps.github-app]", "[github_apps.Github_App]"),
    ];
    for text in cases {
        assert_ne!(problem(&text), "LOADED", "{text}");
    }
    let loaded = load(&github_with("level = 1", "level = 1")).unwrap();
    let app = keybox_core::ident::SecretName::new("github-app").unwrap();
    assert_eq!(loaded.github_client_id(&app), Some("Iv23liTESTCLIENTID"));
}

#[test]
fn errors_say_where_the_problem_is() {
    let msg = problem(&ssh_with("level = 2", "level = 4"));
    assert!(
        msg.contains("customers.acme.systems.web01.actions.deploy"),
        "{msg}"
    );
    assert!(msg.contains("level"), "{msg}");
}

#[test]
fn oversized_file_is_refused_before_parsing() {
    let big = format!("# {}\n", "x".repeat(MAX_POLICY_BYTES));
    assert_ne!(problem(&big), "LOADED");
}

#[test]
fn force_command_without_pin_is_used_as_written() {
    let loaded = load(EXAMPLE).unwrap();
    let s = spec(
        "bager-jensen",
        "web01",
        "restart-web",
        "web01.bager-jensen.example",
        None,
    );
    let Some(Method::SshCert(ssh)) = loaded.method(&s) else {
        panic!("restart-web should be an ssh_cert action");
    };
    assert_eq!(ssh.ttl_secs, 300);
    assert_eq!(
        ssh.force_command_for(None).unwrap(),
        "/usr/bin/systemctl restart nginx"
    );
}

// ----------------------------------------------------- one file per customer

fn files(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
        .collect()
}

const APPS: &str = "[github_apps.github-app]\nclient_id = \"Iv23liTESTCLIENTID\"\n";

fn customer(name: &str) -> String {
    format!(
        "[customers.{name}.systems.github.actions.read-code]\nlevel = 1\nagents = [\"hermes\"]\n\
         targets = [\"org/{name}-web\"]\n\
         method = {{ github_app = {{ app = \"github-app\", permissions = {{ contents = \"read\" }} }} }}\n"
    )
}

fn files_problem(list: &[(&str, &str)]) -> String {
    load_files(&files(list))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "LOADED".into())
}

#[test]
fn several_files_load_as_one_policy() {
    let (acme, bravo) = (customer("acme"), customer("bravo"));
    let loaded = load_files(&files(&[
        ("apps.toml", APPS),
        ("acme.toml", &acme),
        ("bravo.toml", &bravo),
    ]))
    .unwrap();
    let names: Vec<_> = loaded
        .actions()
        .map(|(c, s, a, ..)| format!("{c}/{s}/{a}"))
        .collect();
    assert_eq!(names, ["acme/github/read-code", "bravo/github/read-code"]);
    assert_eq!(loaded.github_apps().count(), 1);
    // The order of the files does not matter.
    let other = load_files(&files(&[
        ("bravo.toml", &bravo),
        ("acme.toml", &acme),
        ("apps.toml", APPS),
    ]))
    .unwrap();
    assert_eq!(format!("{loaded:?}"), format!("{other:?}"));
    // No files at all is a policy that allows nothing.
    assert_eq!(load_files(&[]).unwrap().actions().count(), 0);
}

#[test]
fn a_customer_or_app_cannot_be_spread_over_two_files() {
    let acme = customer("acme");
    let more = acme
        .replace("read-code", "wipe")
        .replace("level = 1", "level = 2");
    let msg = files_problem(&[
        ("apps.toml", APPS),
        ("acme.toml", &acme),
        ("ekstra.toml", &more),
    ]);
    assert!(
        msg.contains("customers.acme") && msg.contains("more than one file"),
        "{msg}"
    );
    let msg = files_problem(&[("apps.toml", APPS), ("apps2.toml", APPS)]);
    assert!(
        msg.contains("github_apps.github-app") && msg.contains("more than one file"),
        "{msg}"
    );
}

#[test]
fn one_bad_file_stops_the_whole_policy_and_is_named() {
    let (acme, bravo) = (customer("acme"), customer("bravo"));
    let broken = bravo.replace("level = 1", "level = 9");
    let msg = files_problem(&[
        ("apps.toml", APPS),
        ("acme.toml", &acme),
        ("bravo.toml", &broken),
    ]);
    assert!(msg.contains("bravo.toml") && msg.contains("level"), "{msg}");
    let msg = files_problem(&[("apps.toml", APPS), ("acme.toml", "this is not toml [")]);
    assert!(msg.contains("acme.toml"), "{msg}");
    // A customer file that needs an app nobody defined.
    assert_ne!(files_problem(&[("acme.toml", &acme)]), "LOADED");
    // Unknown fields are refused in every file.
    let extra = format!("{acme}\n[settings]\nauto_approve = true\n");
    assert_ne!(
        files_problem(&[("apps.toml", APPS), ("acme.toml", &extra)]),
        "LOADED"
    );
}

#[test]
fn file_names_are_plain() {
    for ok in ["apps.toml", "bager-jensen.toml", "kunde_2.toml", "a.toml"] {
        assert!(is_file_name(ok), "{ok}");
    }
    for bad in [
        "",
        ".toml",
        ".skjult.toml",
        "Acme.toml",
        "acme.TOML",
        "acme.txt",
        "../acme.toml",
        "a/b.toml",
        "acme .toml",
        "-rf.toml",
    ] {
        assert!(!is_file_name(bad), "{bad}");
        assert_ne!(files_problem(&[(bad, APPS)]), "LOADED", "{bad}");
    }
}
