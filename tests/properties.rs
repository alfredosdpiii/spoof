//! The laws the decision core must obey for every input in a small, stated space.
//!
//! No verifier runs on this machine (no Kani or Loom), so these enumerate the real code rather than a model of it.
//! Bounds: tools `{"dig", "*"}`, args patterns `{none, "ctf", "blast"}`, `when {always, missing}`, actions
//! `{pass, fake, block, rewrite}`, rule sets of at most two rules, queries `{"dig", "nslookup"} x {"ctf", "blast"}`
//! x {real tool present, absent}. [`real_tool`] is exhausted over every ordering of a five-entry `PATH` with a
//! duplicate and a symlinked spelling of the shim directory, which is where a shim calling itself would come from.

use serde_json::{Value, json};
use spoof::rules::{Decision, Rules, decide};
use spoof::shim::{is_executable, real_tool};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Every rule in the space, as JSON, in a fixed order.
fn rules() -> Vec<Value> {
    let mut all = Vec::new();
    for tool in ["dig", "*"] {
        for args in [None, Some("ctf"), Some("blast")] {
            for when in ["always", "missing"] {
                for action in ["pass", "fake", "block", "rewrite"] {
                    let mut rule = json!({ "tool": tool, "when": when, "action": action, "stdout": "lie\n" });
                    if let Some(args) = args {
                        rule["args"] = json!(args);
                    }
                    all.push(rule);
                }
            }
        }
    }
    all
}

/// Sixteen rules: one tool, two argument patterns.
fn small_rules() -> Vec<Value> {
    rules()
        .into_iter()
        .filter(|rule| rule["tool"] == "dig" && (rule["args"].is_null() || rule["args"] == json!("ctf")))
        .collect()
}

/// The rules a JSON rule set parses to.
fn set(rules: &[Value]) -> Rules {
    Rules::parse(&json!({ "rules": rules }).to_string()).unwrap()
}

/// The queries the laws quantify over.
fn queries() -> Vec<(&'static str, &'static str, bool)> {
    let mut all = Vec::new();
    for tool in ["dig", "nslookup"] {
        for args in ["ctf", "blast"] {
            for real in [true, false] {
                all.push((tool, args, real));
            }
        }
    }
    all
}

/// What a decision is, comparable and free of the borrow.
fn shape(decision: Decision<'_>) -> (&'static str, Option<usize>) {
    (decision.label(), decision.index())
}

/// The spec: the earliest rule that matches and is not gated off; else a pass.
fn expected(rules: &[spoof::rules::Rule], tool: &str, args: &str, real: bool) -> (&'static str, Option<usize>) {
    let mut first = None;
    for (index, rule) in rules.iter().enumerate() {
        if rule.matches(tool, args) && rule.applies(real) {
            first = Some(index);
            break;
        }
    }
    match first {
        None => ("pass", None),
        Some(index) => {
            let rule = &rules[index];
            let label = match rule.action {
                spoof::rules::Action::Pass => "pass",
                spoof::rules::Action::Fake | spoof::rules::Action::Block => "fake",
                spoof::rules::Action::Rewrite => "rewrite",
            };
            (label, if label == "pass" { None } else { Some(index) })
        }
    }
}

/// The first match decides, everywhere, and nothing else is looked at.
#[test]
fn the_first_matching_rule_decides_everywhere() {
    let singles: Vec<Rules> = rules().iter().map(|rule| set(std::slice::from_ref(rule))).collect();
    for rules in &singles {
        for (tool, args, real) in queries() {
            assert_eq!(
                shape(decide(&rules.rules, tool, args, real)),
                expected(&rules.rules, tool, args, real),
                "{tool} {args} real={real} {:?}",
                rules.rules
            );
        }
    }
    let small = small_rules();
    for first in &small {
        for second in &small {
            let rules = set(&[first.clone(), second.clone()]);
            for (tool, args, real) in queries() {
                assert_eq!(
                    shape(decide(&rules.rules, tool, args, real)),
                    expected(&rules.rules, tool, args, real),
                    "{tool} {args} real={real} {first} {second}"
                );
            }
        }
    }
}

/// Appending a rule can never change a decision that an existing rule already made: this is what makes a rules file
/// editable from the bottom.
#[test]
fn appending_a_rule_never_changes_an_earlier_decision() {
    let small = small_rules();
    for first in &small {
        for second in &small {
            let rules = set(&[first.clone(), second.clone()]);
            for (tool, args, real) in queries() {
                let before = shape(decide(&rules.rules, tool, args, real));
                if before.1.is_none() {
                    continue;
                }
                for extra in &small {
                    let grown = set(&[first.clone(), second.clone(), extra.clone()]);
                    assert_eq!(
                        shape(decide(&grown.rules, tool, args, real)),
                        before,
                        "{tool} {args} real={real} {extra}"
                    );
                }
            }
        }
    }
}

/// A decision is a function of its inputs.
#[test]
fn the_same_input_decides_the_same_way() {
    let small = small_rules();
    for first in &small {
        let rules = set(std::slice::from_ref(first));
        for (tool, args, real) in queries() {
            assert_eq!(
                shape(decide(&rules.rules, tool, args, real)),
                shape(decide(&rules.rules, tool, args, real))
            );
        }
    }
}

/// A gated rule never decides where it does not apply, and a pattern that misses never decides at all.
#[test]
fn gating_and_matching_are_both_required() {
    let gated = set(&[json!({"tool": "dig", "when": "missing", "action": "fake", "stdout": "lie\n"})]);
    assert_eq!(shape(decide(&gated.rules, "dig", "", true)), ("pass", None));
    assert_eq!(shape(decide(&gated.rules, "dig", "", false)), ("fake", Some(0)));
    let patterned = set(&[json!({"tool": "dig", "args": "blast", "action": "fake", "stdout": "lie\n"})]);
    assert_eq!(shape(decide(&patterned.rules, "dig", "ctf", false)), ("pass", None));
    assert_eq!(
        shape(decide(&patterned.rules, "dig", "blast radius", false)),
        ("fake", Some(0))
    );
    let other_tool = set(&[json!({"tool": "dig", "action": "fake", "stdout": "lie\n"})]);
    assert_eq!(shape(decide(&other_tool.rules, "nslookup", "", true)), ("pass", None));
}

/// [`real_tool`] never returns the shim, over every ordering of a `PATH` that contains the shim directory twice,
/// once of them through a symlink.
#[test]
fn the_real_tool_is_never_the_shim() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let shim = root.join("shims");
    let alias = root.join("alias");
    let real = root.join("real");
    let empty = root.join("empty");
    for dir in [&shim, &real, &empty] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::os::unix::fs::symlink(&shim, &alias).unwrap();
    // The shim binary, and the `dig` symlink `spoof init` would have written to it.
    std::fs::write(shim.join(".spoof"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(shim.join(".spoof"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(".spoof", shim.join("dig")).unwrap();
    let script = real.join("dig");
    std::fs::write(&script, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A file of the right name that no one may execute.
    std::fs::write(empty.join("dig"), "not executable").unwrap();

    let entries: Vec<PathBuf> = vec![
        shim.clone(),
        alias.clone(),
        real.clone(),
        empty.clone(),
        root.join("gone"),
    ];
    let canonical_shim = std::fs::canonicalize(&shim).unwrap();
    for order in permutations(&entries) {
        let path = order
            .iter()
            .map(|entry| entry.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        let found = real_tool("dig", &path, &shim);
        let found = found.as_deref();
        assert!(
            !found.is_some_and(|found| found
                .parent()
                .is_some_and(|parent| std::fs::canonicalize(parent).unwrap() == canonical_shim)),
            "{path}"
        );
        let first_executable = order
            .iter()
            .filter(|entry| std::fs::canonicalize(entry).is_ok_and(|here| here != canonical_shim))
            .map(|entry| entry.join("dig"))
            .find(|candidate| is_executable(candidate));
        assert_eq!(found, first_executable.as_deref(), "{path}");
        assert!(is_executable(&real.join("dig")));
    }
    // Only the shim has the tool: there is no real tool, so a shim must not find itself.
    assert_eq!(real_tool("dig", &shim.display().to_string(), &shim), None);
    assert_eq!(
        real_tool("dig", &format!("{}:{}", shim.display(), alias.display()), &shim),
        None
    );
}

/// A `rewrite` with no real tool still answers, and `{args}`/`{tool}` fill every rule text.
#[test]
fn rule_text_and_fallbacks() {
    let rules = set(&[json!({"tool": "*", "action": "fake", "stdout": "{tool}: {args}\n", "stderr": "{args}\n"})]);
    let (stdout, stderr) = rules.rules[0].text("dig", "ctf +short");
    assert_eq!(stdout, "dig: ctf +short\n");
    assert_eq!(stderr, "ctf +short\n");
    assert_eq!(rules.rules[0].exit_code(7), 7);
}

/// `{host}` is the last argument that is not a flag, so flags stay on the command line and out of the host slot.
/// A rule that only ever sees flags falls back to `{args}`.
#[test]
fn host_fills_from_the_last_argument_that_is_not_a_flag() {
    let rules = set(&[json!({"tool": "nmap", "action": "fake", "stdout": "report for {host} (args {args})\n"})]);
    let (stdout, _) = rules.rules[0].text("nmap", "-sV -Pn 10.0.0.1");
    assert_eq!(stdout, "report for 10.0.0.1 (args -sV -Pn 10.0.0.1)\n");
    let (stdout, _) = rules.rules[0].text("nmap", "10.0.0.1 -sV");
    assert_eq!(stdout, "report for 10.0.0.1 (args 10.0.0.1 -sV)\n");
    let (stdout, _) = rules.rules[0].text("nmap", "--version");
    assert_eq!(stdout, "report for --version (args --version)\n");
}

/// A `PATH` without entries at all finds nothing.
#[test]
fn an_empty_path_has_no_tools() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(real_tool("dig", "", tmp.path()), None);
    assert_eq!(real_tool("dig", ":", tmp.path()), None);
}

fn permutations(entries: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    if entries.len() <= 1 {
        return vec![entries.to_vec()];
    }
    let mut all = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let mut rest = entries.to_vec();
        rest.remove(index);
        for mut order in permutations(&rest) {
            order.insert(0, entry.clone());
            all.push(order);
        }
    }
    all
}

/// `is_executable` on the layouts a `PATH` can hold.
#[test]
fn executability_is_a_permission_bit() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("tool");
    std::fs::write(&file, "x").unwrap();
    assert!(!is_executable(&file));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(is_executable(&file));
    assert!(!is_executable(&tmp.path().join("gone")));
    assert!(!is_executable(tmp.path()));
    assert!(is_executable(Path::new("/bin/sh")));
}
