//! Property tests: random input must never panic, and anything accepted must
//! fit the grammar. Runs on stable in `cargo test`.

use keybox_core::ident::{CustomerId, Pin, RequestId, Target};
use keybox_core::request::Reason;
use keybox_policy::{Method, load};
use proptest::prelude::*;

/// The slug grammar, written out again independently of the code under test.
fn slug_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && s.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

/// Characters that would matter in a shell, a path or a log line.
fn dangerous(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || !c.is_ascii()
        || " ;|&$`'\"\\<>()*?!#~{}[]=,%^".contains(c)
}

fn policy_with(field: &str, value: &str) -> String {
    let mut lines = vec![
        ("level", "2".to_owned()),
        ("agents", "[\"hermes\"]".to_owned()),
        ("targets", "[\"web01.acme.example\"]".to_owned()),
        ("pin", "\"commit\"".to_owned()),
    ];
    let mut method = vec![
        ("ca", "\"ssh-ca-acme\"".to_owned()),
        ("principal", "\"deploy\"".to_owned()),
        ("source_address", "[\"100.64.0.10\"]".to_owned()),
        (
            "force_command",
            "\"/usr/local/bin/deploy {commit}\"".to_owned(),
        ),
    ];
    for (k, v) in lines.iter_mut().chain(method.iter_mut()) {
        if *k == field {
            *v = value.to_owned();
        }
    }
    let join = |kv: &[(&str, String)]| {
        kv.iter()
            .map(|(k, v)| format!("{k} = {v}\n"))
            .collect::<String>()
    };
    format!(
        "[customers.acme.systems.web01.actions.deploy]\n{}[customers.acme.systems.web01.actions.deploy.method.ssh_cert]\n{}",
        join(&lines),
        join(&method)
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn slug_matches_its_grammar(s in prop_oneof![any::<String>(), "[a-z0-9-]{0,70}", "[ -~]{0,20}"]) {
        prop_assert_eq!(CustomerId::new(&s).is_ok(), slug_ok(&s));
    }

    #[test]
    fn accepted_target_has_no_dangerous_character(
        s in prop_oneof![any::<String>(), "[A-Za-z0-9._/:@ ;$-]{0,40}"]
    ) {
        if let Ok(t) = Target::new(&s) {
            prop_assert!(!t.as_str().chars().any(dangerous));
            prop_assert!(!t.as_str().contains(".."));
            prop_assert!(t.as_str().len() <= 200);
        }
    }

    #[test]
    fn pins_and_ids_are_hex_only(s in prop_oneof![any::<String>(), "[0-9a-fA-F:sh]{30,75}"]) {
        let hex = |x: &str| x.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if let Ok(p) = Pin::commit(&s) {
            prop_assert!(p.as_str().len() == 40 && hex(p.as_str()));
        }
        if let Ok(p) = Pin::digest(&s) {
            prop_assert!(p.as_str().len() == 71 && hex(&p.as_str()[7..]));
        }
        if let Ok(id) = RequestId::new(&s) {
            prop_assert!(id.as_str().len() == 32 && hex(id.as_str()));
        }
    }

    #[test]
    fn reason_never_keeps_control_characters(s in any::<String>()) {
        if let Ok(r) = Reason::new(&s) {
            prop_assert!(!r.as_str().chars().any(char::is_control));
            prop_assert!(r.as_str().chars().count() <= 500);
        }
    }

    #[test]
    fn load_never_panics_on_arbitrary_text(s in any::<String>()) {
        let _ = load(&s);
    }

    #[test]
    fn load_never_panics_on_toml_shaped_text(s in "[a-z_.=\\[\\]{}\"0-9, \n-]{0,200}") {
        let _ = load(&s);
    }

    /// One field of an otherwise valid file is replaced by arbitrary text.
    /// Whatever loads must still satisfy every rule.
    #[test]
    fn a_mutated_field_never_loads_something_unsafe(
        field in prop_oneof![
            Just("level"), Just("agents"), Just("targets"), Just("pin"), Just("ca"),
            Just("principal"), Just("source_address"), Just("force_command"),
        ],
        value in prop_oneof![
            "[ -~]{0,40}",
            "\"[ -~&&[^\"\\\\]]{0,40}\"",
            "\\[\"[ -~&&[^\"\\\\]]{0,30}\"\\]",
            "[0-9]{1,3}",
            // Close to valid, so a good share of cases get past the parser.
            "\"[a-z0-9./ {}_-]{1,30}\"",
            "\"/bin/[a-z]{1,8} \\{(commit|digest|target)\\}[ a-z{}]{0,6}\"",
            "\\[\"[a-f0-9.:]{1,20}(/[0-9]{1,3})?\"\\]",
            "\\[\"[a-z0-9.@/-]{1,20}\"(, \"[a-z0-9.-]{1,10}\")?\\]",
        ],
        sha in "[0-9a-f]{40}",
    ) {
        let Ok(loaded) = load(&policy_with(field, &value)) else { return Ok(()); };
        let text = format!("{loaded:?}");
        prop_assert!(!text.contains("0.0.0.0/0") && !text.contains("::/0"));
        // Find the one action, whatever its target turned out to be.
        let pin = Pin::commit(&sha).unwrap();
        for target in text.split('"').filter_map(|t| Target::new(t).ok()) {
            let spec = keybox_core::request::RequestSpec {
                customer: CustomerId::new("acme").unwrap(),
                system: keybox_core::ident::SystemId::new("web01").unwrap(),
                action: keybox_core::ident::ActionId::new("deploy").unwrap(),
                target,
                pin: Some(pin.clone()),
            };
            if let Some(Method::SshCert(ssh)) = loaded.method(&spec) {
                prop_assert!(!ssh.source_address.is_empty());
                prop_assert!((60..=1800).contains(&ssh.ttl_secs));
                if let Some(cmd) = ssh.force_command_for(Some(&pin)) {
                    let leftover = cmd.contains(['{', '}', '\n', '\r']);
                    prop_assert!(!leftover);
                    prop_assert!(cmd.is_ascii());
                }
            }
        }
    }
}
