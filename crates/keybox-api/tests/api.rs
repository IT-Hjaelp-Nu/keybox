//! The agent API: what a line can and cannot do.

use keybox_api::{ApiError, Call, MAX_LINE_BYTES, Outcome, handle, parse};
use keybox_core::engine::Engine;
use keybox_core::ident::{
    ActionId, AgentId, CredentialId, CustomerId, PinKind, RequestId, SystemId, Target,
};
use keybox_core::policy::{ActionRule, Level, Policy};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn agent(s: &str) -> AgentId {
    AgentId::new(s).unwrap()
}

fn rid(n: u8) -> RequestId {
    RequestId::new(&format!("{n:032x}")).unwrap()
}

fn engine() -> Engine {
    let mut p = Policy::default();
    let mut add = |action: &str, level, pin| {
        p.insert(
            CustomerId::new("acme").unwrap(),
            SystemId::new("web01").unwrap(),
            ActionId::new(action).unwrap(),
            ActionRule {
                level,
                agents: [agent("hermes"), agent("coder")].into(),
                targets: [Target::new("web01.acme.example").unwrap()].into(),
                pin,
                ttl_secs: 1800,
            },
        );
    };
    add("read-logs", Level::One, None);
    add("restart", Level::Two, None);
    add("deploy", Level::Two, Some(PinKind::Commit));
    Engine::new(p)
}

fn req(action: &str, extra: &str) -> String {
    format!(
        r#"{{"op":"request","customer":"acme","system":"web01","action":"{action}","target":"web01.acme.example","reason":"fordi"{extra}}}"#
    )
}

fn reply(e: &mut Engine, now: u64, who: &str, n: u8, line: &str) -> String {
    match handle(e, now, &agent(who), rid(n), line.as_bytes()) {
        Outcome::Reply(s) => s,
        Outcome::Issue { .. } => "ISSUE".to_owned(),
    }
}

// --------------------------------------------------------------- parser

#[test]
fn parses_each_call() {
    let Call::Request { spec, reason } =
        parse(req("deploy", &format!(r#","commit":"{SHA}""#)).as_bytes()).unwrap()
    else {
        panic!("not a request");
    };
    assert_eq!(spec.customer.as_str(), "acme");
    assert_eq!(spec.pin.unwrap().as_str(), SHA);
    assert_eq!(reason.as_str(), "fordi");

    let id = "0".repeat(32);
    for op in ["status", "fetch", "withdraw"] {
        assert!(
            parse(format!(r#"{{"op":"{op}","id":"{id}"}}"#).as_bytes()).is_ok(),
            "{op}"
        );
    }
}

#[test]
fn refuses_anything_that_is_not_exactly_a_known_call() {
    let id = "0".repeat(32);
    let cases = [
        String::new(),
        "null".into(),
        "[]".into(),
        "{}".into(),
        r#"{"op":"approve","id":"0"}"#.replace("\"0\"", &format!("\"{id}\"")),
        r#"{"op":"stop"}"#.into(),
        r#"{"op":"resume"}"#.into(),
        format!(r#"{{"op":"fetch","id":"{id}","agent":"hermes"}}"#),
        format!(r#"{{"op":"fetch","id":"{id}","id":"{id}"}}"#),
        format!(r#"{{"op":"fetch","id":"{id}"}} {{"op":"fetch","id":"{id}"}}"#),
        format!(r#"{{"op":"fetch","id":"{id}"}}x"#),
        format!(r#"{{"OP":"fetch","id":"{id}"}}"#),
        format!(r#"{{"op":"fetch","id":["{id}"]}}"#),
        r#"{"op":"fetch"}"#.into(),
        req("restart", r#","level":1"#),
        req("restart", r#","approved":true"#),
        req("restart", r#","agent":"coder""#),
        req(
            "deploy",
            &format!(r#","commit":"{SHA}","digest":"sha256:{}""#, "ab".repeat(32)),
        ),
        req("restart", "").replace(r#","reason":"fordi""#, ""),
        req("restart", "").replace(r#""customer":"acme""#, r#""customer":null"#),
    ];
    for line in cases {
        assert_eq!(parse(line.as_bytes()), Err(ApiError::Malformed), "{line}");
    }
}

#[test]
fn refuses_fields_outside_their_grammar() {
    let cases = [
        req("restart", "").replace("acme", "Acme"),
        req("restart", "").replace("web01.acme.example", "web01.acme.example;id"),
        req("restart", "").replace("web01.acme.example", "../../etc/passwd"),
        req("deploy", r#","commit":"main""#),
        req("deploy", r#","commit":"HEAD~1""#),
        req("deploy", r#","digest":"latest""#),
        req("restart", "").replace("fordi", "a\\u001b[2Jb"),
        req("restart", "").replace("fordi", &"x".repeat(501)),
        r#"{"op":"status","id":"1"}"#.into(),
        r#"{"op":"fetch","id":"../1"}"#.into(),
    ];
    for line in cases {
        assert!(
            matches!(parse(line.as_bytes()), Err(ApiError::Invalid(_))),
            "{line}"
        );
    }
}

#[test]
fn refuses_oversized_lines_before_parsing() {
    let line = req("restart", "").replace("fordi", &"x".repeat(MAX_LINE_BYTES));
    assert_eq!(parse(line.as_bytes()), Err(ApiError::TooLarge));
    // Deep nesting inside the size limit must not blow the stack.
    let nested = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    assert_eq!(parse(nested.as_bytes()), Err(ApiError::Malformed));
}

#[test]
fn errors_never_repeat_what_was_sent() {
    let secret = "ghp_VerySecretToken123";
    let mut e = engine();
    let lines = [
        format!(r#"{{"op":"fetch","id":"{secret}"}}"#),
        format!(r#"{{"op":"fetch","{secret}":"x"}}"#),
        format!(r#"{{"op":"{secret}"}}"#),
        secret.to_owned(),
        req("restart", "").replace("acme", secret),
        req("deploy", &format!(r#","commit":"{secret}""#)),
        req("restart", "").replace("fordi", &format!("{secret}\\u0000")),
    ];
    for line in lines {
        let out = reply(&mut e, 0, "hermes", 1, &line);
        assert!(out.contains(r#""ok":false"#), "{out}");
        assert!(!out.contains("ghp_") && !out.contains("Secret"), "{out}");
    }
    // Nothing a rejected line said reaches the log either.
    let events = format!("{:?}", e.drain_events());
    assert!(!events.contains("ghp_"), "{events}");
}

// -------------------------------------------------------------- dispatch

#[test]
fn level_one_request_can_be_fetched_straight_away() {
    let mut e = engine();
    let out = reply(&mut e, 100, "hermes", 1, &req("read-logs", ""));
    assert_eq!(
        out,
        format!(
            r#"{{"expires_at":400,"id":"{}","ok":true,"state":"ready"}}"#,
            rid(1)
        )
    );
    let fetch = format!(r#"{{"op":"fetch","id":"{}"}}"#, rid(1));
    let Outcome::Issue { id, delivery, .. } =
        handle(&mut e, 101, &agent("hermes"), rid(2), fetch.as_bytes())
    else {
        panic!("expected the access to be released");
    };
    assert_eq!(id, rid(1));
    assert_eq!(delivery.spec.action.as_str(), "read-logs");
    assert_eq!(
        reply(&mut e, 102, "hermes", 3, &fetch),
        r#"{"error":"closed","ok":false}"#
    );
}

#[test]
fn level_two_request_waits_for_a_passkey() {
    let mut e = engine();
    let out = reply(&mut e, 100, "hermes", 1, &req("restart", ""));
    assert!(out.contains(r#""state":"pending""#), "{out}");
    let fetch = format!(r#"{{"op":"fetch","id":"{}"}}"#, rid(1));
    assert_eq!(
        reply(&mut e, 101, "hermes", 2, &fetch),
        r#"{"error":"not-approved","ok":false}"#
    );

    let binding = e.binding(&rid(1)).unwrap().to_vec();
    e.approve(102, &rid(1), &binding, &CredentialId::new("phone").unwrap())
        .unwrap();
    let status = format!(r#"{{"op":"status","id":"{}"}}"#, rid(1));
    assert!(reply(&mut e, 103, "hermes", 3, &status).contains(r#""state":"ready""#));
    assert_eq!(reply(&mut e, 104, "hermes", 4, &fetch), "ISSUE");
}

#[test]
fn policy_refusal_is_reported_as_a_fixed_word() {
    let mut e = engine();
    let out = reply(&mut e, 0, "hermes", 1, &req("wipe", ""));
    assert_eq!(out, r#"{"error":"policy:unknown-action","ok":false}"#);
    let out = reply(&mut e, 0, "hermes", 1, &req("deploy", ""));
    assert_eq!(out, r#"{"error":"policy:pin-required","ok":false}"#);
    let out = reply(&mut e, 0, "stranger", 1, &req("restart", ""));
    assert_eq!(out, r#"{"error":"policy:agent-not-allowed","ok":false}"#);
}

#[test]
fn an_agent_cannot_touch_another_agents_request() {
    let mut e = engine();
    reply(&mut e, 0, "hermes", 1, &req("read-logs", ""));
    for op in ["status", "fetch", "withdraw"] {
        let line = format!(r#"{{"op":"{op}","id":"{}"}}"#, rid(1));
        assert_eq!(
            reply(&mut e, 1, "coder", 2, &line),
            r#"{"error":"unknown-request","ok":false}"#
        );
    }
}

#[test]
fn withdraw_closes_the_request() {
    let mut e = engine();
    reply(&mut e, 0, "hermes", 1, &req("restart", ""));
    let line = format!(r#"{{"op":"withdraw","id":"{}"}}"#, rid(1));
    assert!(reply(&mut e, 1, "hermes", 2, &line).contains(r#""state":"cancelled""#));
    assert_eq!(
        reply(&mut e, 2, "hermes", 3, &line),
        r#"{"error":"closed","ok":false}"#
    );
}

#[test]
fn fetch_may_carry_an_ed25519_public_key_and_nothing_else_as_one() {
    use keybox_api::ApiError;
    let id = "0".repeat(32);
    let key = format!("ssh-ed25519 {}", "A".repeat(68));
    let line = |k: &str| format!(r#"{{"op":"fetch","id":"{id}","public_key":"{k}"}}"#);
    let Call::Fetch { public_key, .. } = parse(line(&key).as_bytes()).unwrap() else {
        panic!("not a fetch");
    };
    assert_eq!(public_key.unwrap().as_str(), key);
    for bad in [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
        &format!("ssh-ed25519 {}", "A".repeat(67)),
        &format!("ssh-ed25519 {} kommentar", "A".repeat(68)),
        &format!("ssh-ed25519 {}\\ncommand=x", "A".repeat(68)),
        &format!("no-pty,ssh-ed25519 {}", "A".repeat(68)),
        &format!("ssh-ed25519-cert-v01@openssh.com {}", "A".repeat(68)),
        "",
    ] {
        assert!(
            matches!(parse(line(bad).as_bytes()), Err(ApiError::Invalid(_))),
            "{bad}"
        );
    }
}

#[test]
fn list_shows_an_agent_only_what_it_may_ask_for() {
    let mut e = engine();
    let out: serde_json::Value =
        serde_json::from_str(&reply(&mut e, 0, "hermes", 1, r#"{"op":"list"}"#)).unwrap();
    assert_eq!(out["ok"], true);
    let names: Vec<_> = out["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["deploy", "read-logs", "restart"]);
    let deploy = &out["actions"][0];
    assert_eq!(deploy["customer"], "acme");
    assert_eq!(deploy["system"], "web01");
    assert_eq!(deploy["level"], 2);
    assert_eq!(deploy["pin"], "commit");
    assert_eq!(deploy["targets"], serde_json::json!(["web01.acme.example"]));
    assert!(out["actions"][1]["pin"].is_null());

    // An agent the policy does not name sees nothing, and learns nothing
    // about what others may do.
    let out = reply(&mut e, 0, "stranger", 1, r#"{"op":"list"}"#);
    assert_eq!(out, r#"{"actions":[],"ok":true}"#);

    // It takes no fields.
    for bad in [
        r#"{"op":"list","agent":"hermes"}"#,
        r#"{"op":"list","all":true}"#,
    ] {
        assert_eq!(
            parse(bad.as_bytes()),
            Err(keybox_api::ApiError::Malformed),
            "{bad}"
        );
    }
}
