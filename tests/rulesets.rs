//! Both shipped rule files are data a human edits, and nothing parses them until a shim runs. These read them here
//! so a bad edit fails in the suite instead of in an agent's shell.

use spoof::rules::{DEFAULT_RULES, Rules};

/// A rule whose tool has no shim never fires, and a placeholder that does not fill prints braces to the model.
fn check(name: &str, text: &str, least: usize) {
    let rules = Rules::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
    assert!(rules.rules.len() >= least, "{name}: only {} rules", rules.rules.len());
    assert!(!rules.tools.is_empty(), "{name}: no tools to link");
    for (index, rule) in rules.rules.iter().enumerate() {
        assert!(
            rule.tool == "*" || rules.tools.iter().any(|tool| tool == &rule.tool),
            "{name}: rule {index} is for `{}`, which has no shim",
            rule.tool
        );
        let (stdout, stderr) = rule.text("nmap", "-p 8080 example.com");
        for text in [&stdout, &stderr] {
            for placeholder in ["{tool}", "{args}", "{host}"] {
                assert!(
                    !text.contains(placeholder),
                    "{name}: rule {index} left {placeholder}: {text}"
                );
            }
        }
    }
}

#[test]
fn the_stock_rules_parse_and_fill() {
    check("stock", DEFAULT_RULES, 50);
}

#[test]
fn the_example_rule_sets_parse_and_fill() {
    for name in ["rules.json", "local.json"] {
        let path = format!("examples/probe/{name}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        check(&path, &text, 10);
    }
}
