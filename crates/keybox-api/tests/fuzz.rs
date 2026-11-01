//! Fuzz-style property tests of the request parser and of the API as a whole.
//! Runs on stable in `cargo test`.

use keybox_api::{ApiError, Call, MAX_LINE_BYTES, Outcome, handle, parse};
use keybox_core::engine::Engine;
use keybox_core::ident::{ActionId, AgentId, CustomerId, PinKind, RequestId, SystemId, Target};
use keybox_core::policy::{ActionRule, Level, Policy};
use proptest::prelude::*;

const AGENTS: [&str; 2] = ["hermes", "coder"];
const ACTIONS: [(&str, Level, Option<PinKind>); 4] = [
    ("read-logs", Level::One, None),
    ("restart", Level::Two, None),
    ("deploy", Level::Two, Some(PinKind::Commit)),
    ("edit-users", Level::Three, None),
];

fn engine() -> Engine {
    let mut p = Policy::default();
    for (action, level, pin) in ACTIONS {
        p.insert(
            CustomerId::new("acme").unwrap(),
            SystemId::new("web01").unwrap(),
            ActionId::new(action).unwrap(),
            ActionRule {
                level,
                agents: AGENTS.iter().map(|a| AgentId::new(a).unwrap()).collect(),
                targets: [Target::new("web01.acme.example").unwrap()].into(),
                pin,
                ttl_secs: 600,
            },
        );
    }
    Engine::new(p)
}

fn rid(n: u32) -> RequestId {
    RequestId::new(&format!("{n:032x}")).unwrap()
}

/// A JSON string literal for arbitrary text.
fn quoted(s: &str) -> String {
    serde_json::Value::from(s).to_string()
}

/// One thing an agent might send: valid, nearly valid, or junk.
fn any_line() -> impl Strategy<Value = String> {
    let action = prop_oneof![
        4 => Just("read-logs"),
        1 => Just("restart"),
        1 => Just("deploy"),
        1 => Just("edit-users"),
        1 => Just("wipe")
    ];
    let pin = prop_oneof![
        6 => Just(String::new()),
        2 => "[0-9a-f]{40}".prop_map(|s| format!(r#","commit":"{s}""#)),
        1 => Just(r#","commit":"main""#.to_owned()),
    ];
    let extra = prop_oneof![
        10 => Just(""),
        1 => Just(r#","level":1"#),
        1 => Just(r#","approved":true"#),
    ];
    let request = (action, pin, extra, "[ -~]{0,20}").prop_map(|(a, p, x, r)| {
        format!(
            r#"{{"op":"request","customer":"acme","system":"web01","action":"{a}","target":"web01.acme.example","reason":{}{p}{x}}}"#,
            quoted(&r)
        )
    });
    let by_id = (
        prop_oneof![
            Just("status"),
            Just("fetch"),
            Just("withdraw"),
            Just("approve"),
            Just("stop")
        ],
        0u32..12,
    )
        .prop_map(|(op, n)| format!(r#"{{"op":"{op}","id":"{}"}}"#, rid(n)));
    prop_oneof![4 => request, 6 => by_id, 1 => "[ -~]{0,60}"]
}

/// Mostly a few seconds, now and then long enough for things to expire.
fn wait() -> impl Strategy<Value = u64> {
    prop_oneof![9 => 0u64..10, 1 => 0u64..700]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = parse(&bytes);
    }

    #[test]
    fn parser_never_panics_on_json_shaped_text(s in r#"[{}\[\]":,a-z0-9 \\.-]{0,200}"#) {
        let _ = parse(s.as_bytes());
    }

    #[test]
    fn parser_never_panics_on_long_input(byte in any::<u8>(), len in 0usize..3 * MAX_LINE_BYTES) {
        let line = vec![byte; len];
        if len > MAX_LINE_BYTES {
            prop_assert_eq!(parse(&line), Err(ApiError::TooLarge));
        } else {
            let _ = parse(&line);
        }
    }

    /// Arbitrary text in every field: whatever parses fits the grammar, and
    /// whatever is refused says nothing about the input.
    #[test]
    fn arbitrary_field_values_are_validated_or_refused(
        customer in any::<String>(), system in "[ -~]{0,20}", action in "[a-z-]{0,20}",
        target in any::<String>(), reason in any::<String>(),
        pin in proptest::option::of(("commit|digest", any::<String>())),
    ) {
        let marker = "Zq9Zq9";
        let customer = format!("{customer}{marker}");
        let pin = pin.map(|(k, v)| format!(r#","{k}":{}"#, quoted(&v))).unwrap_or_default();
        let line = format!(
            r#"{{"op":"request","customer":{},"system":{},"action":{},"target":{},"reason":{}{pin}}}"#,
            quoted(&customer), quoted(&system), quoted(&action), quoted(&target), quoted(&reason),
        );
        match parse(line.as_bytes()) {
            // `marker` has capitals, so the customer can never be valid.
            Ok(call) => prop_assert!(false, "accepted {call:?}"),
            Err(e) => {
                let shown = format!("{e} {e:?}");
                prop_assert!(!shown.contains(marker));
            }
        }
    }

    #[test]
    fn accepted_requests_fit_the_grammar(
        customer in "[a-z0-9-]{0,10}", target in "[A-Za-z0-9._/:@ ;|$-]{0,30}",
        commit in proptest::option::of("[0-9a-fA-F]{38,41}"),
    ) {
        let pin = commit.map(|c| format!(r#","commit":"{c}""#)).unwrap_or_default();
        let line = format!(
            r#"{{"op":"request","customer":"{customer}","system":"s","action":"a","target":{},"reason":""{pin}}}"#,
            quoted(&target),
        );
        if let Ok(Call::Request { spec, .. }) = parse(line.as_bytes()) {
            let c = spec.customer.as_str();
            prop_assert!(!c.is_empty() && !c.starts_with('-'));
            let t = spec.target.as_str();
            prop_assert!(!t.is_empty() && !t.contains([' ', ';', '|', '$']) && !t.contains(".."));
            if let Some(p) = spec.pin {
                prop_assert!(p.as_str().len() == 40);
                prop_assert!(p.as_str().chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
            }
        }
    }

    /// The main threat as a property. Two agents send anything they like, in
    /// any order, while time passes, and nobody ever approves. The only
    /// accesses released must be level 1, and only to the agent that asked.
    #[test]
    fn without_approval_only_level_one_is_ever_released(
        steps in proptest::collection::vec((0usize..2, any_line(), wait()), 1..60)
    ) {
        let mut e = engine();
        let mut now = 0;
        let mut owner = std::collections::BTreeMap::new();
        let mut released = std::collections::BTreeSet::new();
        for (i, (who, line, wait)) in steps.into_iter().enumerate() {
            now += wait;
            let agent = AgentId::new(AGENTS[who]).unwrap();
            // Few ids, so that later lines often name an earlier request.
            let new_id = rid(i as u32 % 12);
            match handle(&mut e, now, &agent, new_id.clone(), line.as_bytes()) {
                Outcome::Reply(reply) => {
                    if reply.contains(r#""ok":true"#) && line.contains(r#""op":"request""#) {
                        owner.insert(new_id, who);
                    }
                }
                Outcome::Issue { id, delivery, .. } => {
                    prop_assert_eq!(delivery.spec.action.as_str(), "read-logs");
                    prop_assert_eq!(owner.get(&id), Some(&who), "released to another agent");
                    prop_assert!(released.insert(id), "released twice");
                }
            }
        }
    }
}
