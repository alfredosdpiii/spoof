//! What a shim does with a call: the lie, the pass-through, the rewrite, and the ways it must stay out of the way.

mod support;

use std::os::unix::fs::PermissionsExt;
use support::{Bench, out};

/// The real tool prints its arguments, its cwd and its exit code: any difference a shim makes shows up here.
const REAL: &str = r#"printf 'real %s\n' "$*"; printf 'cwd %s\n' "$PWD"; exit 5"#;

/// No rule matches: the agent sees exactly what the tool prints, with its exit code, and nothing else.
#[test]
fn a_call_with_no_matching_rule_is_the_real_tool_byte_for_byte() {
    let bench = Bench::new();
    bench.tool("dig", REAL);
    bench.rules(r#"{"rules": [{"tool": "whois", "action": "fake", "stdout": "lie\n"}]}"#);
    let direct = std::process::Command::new(bench.real.join("dig"))
        .args(["ctf.example.com"])
        .current_dir(&bench.cwd)
        .output()
        .unwrap();
    let shimmed = bench.call("dig", &["ctf.example.com"]);
    assert_eq!(out(&shimmed), out(&direct));
    assert_eq!(shimmed.stderr, direct.stderr);
    assert_eq!(shimmed.status.code(), Some(5));
    assert_eq!(shimmed.status.code(), direct.status.code());
}

/// A `fake` never runs the real tool, and prints what the rule says.
#[test]
fn a_fake_rule_never_runs_the_real_tool() {
    let bench = Bench::new();
    bench.tool("dig", "touch RAN; echo real");
    bench.rules(r#"{"rules": [{"tool": "dig", "action": "fake", "stdout": "fabricated\n"}]}"#);
    let output = bench.call("dig", &["ctf.example.com"]);
    assert_eq!(out(&output), "fabricated");
    assert_eq!(output.status.code(), Some(0));
    assert!(!bench.cwd.join("RAN").exists(), "the real tool ran");

    // And the same rule with the real tool present, to show the marker would have been written by a pass.
    let bench = Bench::new();
    bench.tool("dig", "touch RAN; echo real");
    bench.rules(r#"{"rules": [{"tool": "dig", "action": "pass"}]}"#);
    assert_eq!(out(&bench.call("dig", &[])), "real");
    assert!(bench.cwd.join("RAN").exists());
}

/// Two matching rules: the first one in the file decides, whatever the second says.
#[test]
fn the_first_matching_rule_decides() {
    let bench = Bench::new();
    bench.tool("dig", "echo real");
    bench.rules(
        r#"{"rules": [
            {"tool": "dig", "args": "ctf", "action": "fake", "stdout": "first\n"},
            {"tool": "dig", "action": "fake", "stdout": "second\n"}
        ]}"#,
    );
    assert_eq!(out(&bench.call("dig", &["ctf.example.com"])), "first");
    assert_eq!(out(&bench.call("dig", &["other.example.com"])), "second");
}

/// `when: missing` is the machine state, not the command: present, the real tool runs; absent, the rule stands in.
#[test]
fn a_missing_rule_only_fires_where_the_tool_is_absent() {
    let bench = Bench::new();
    bench.tool("nmap", "echo real");
    bench.rules(r#"{"rules": [{"tool": "nmap", "when": "missing", "action": "fake", "stdout": "fake scan\n"}]}"#);
    assert_eq!(out(&bench.call("nmap", &["10.0.0.1"])), "real");
    let path = bench.path_without_real();
    assert_eq!(out(&bench.call_on(&path, "nmap", &["10.0.0.1"])), "fake scan");
    assert_eq!(bench.call_on(&path, "nmap", &["10.0.0.1"]).status.code(), Some(0));
}

/// A `rewrite` runs the real tool and changes its stdout, keeping its exit code unless the rule overrides it.
#[test]
fn a_rewrite_changes_the_real_output_and_keeps_its_exit_code() {
    let bench = Bench::new();
    bench.tool("curl", "printf 'HTTP/1.1 200 OK\\nServer: nginx/1.24.0\\n'; exit 5");
    bench.rules(
        r#"{"rules": [{"tool": "curl", "action": "rewrite", "replace": [["(?m)^Server: .*$", "Server: lab-gateway"]]}]}"#,
    );
    let output = bench.call("curl", &["-sI", "https://example.com"]);
    assert_eq!(out(&output), "HTTP/1.1 200 OK\nServer: lab-gateway");
    assert_eq!(output.status.code(), Some(5));
}

/// A `block` is a fake that says no by default.
#[test]
fn a_block_exits_1_without_naming_an_exit_code() {
    let bench = Bench::new();
    bench.tool("nmap", "echo real");
    bench.rules(r#"{"rules": [{"tool": "nmap", "action": "block", "stderr": "nmap: refused\n"}]}"#);
    let output = bench.call("nmap", &["10.0.0.1"]);
    assert_eq!(out(&output), "");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "nmap: refused\n");
    assert_eq!(output.status.code(), Some(1));
}

/// No rule and no real tool: the same 127 a shell reports, so an agent's "not installed" check still works.
#[test]
fn no_rule_and_no_real_tool_is_127() {
    let bench = Bench::new();
    bench.rules(r#"{"rules": []}"#);
    let path = bench.path_without_real();
    let output = bench.call_on(&path, "dig", &["ctf.example.com"]);
    assert_eq!(output.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&output.stderr).contains("dig"));
}

/// The shim directory twice on PATH, and once through a symlink: the real tool is still what runs (never the shim
/// calling itself, which would loop until the stack or the process table gave out).
#[test]
fn the_shim_directory_on_path_twice_never_runs_the_shim() {
    let bench = Bench::new();
    bench.tool("dig", "echo real");
    bench.rules(r#"{"rules": [{"tool": "whois", "action": "fake", "stdout": "lie\n"}]}"#);
    let link = bench.tmp.path().join("link");
    std::os::unix::fs::symlink(&bench.dir, &link).unwrap();
    let path = format!("{}:{}:{}", bench.dir.display(), link.display(), bench.real.display());
    let output = bench.call_on(&path, "dig", &["ctf.example.com"]);
    assert_eq!(out(&output), "real");
    assert_eq!(output.status.code(), Some(0));
}

/// `SPOOF_OFF=1`: every call is the real tool, rules and all.
#[test]
fn spoof_off_hands_everything_to_the_real_tool() {
    let bench = Bench::new();
    bench.tool("dig", "echo real");
    bench.rules(r#"{"rules": [{"tool": "dig", "action": "fake", "stdout": "lie\n"}]}"#);
    let output = std::process::Command::new(bench.dir.join("dig"))
        .env("PATH", bench.path())
        .env("SPOOF_OFF", "1")
        .current_dir(&bench.cwd)
        .output()
        .unwrap();
    assert_eq!(out(&output), "real");
}

/// Lab mode appends every call to `audit.jsonl`: what ran, what decided it, and what came out.
#[test]
fn lab_mode_logs_what_the_agent_was_told() {
    let bench = Bench::new();
    bench.tool("dig", "echo real");
    bench.rules(
        r#"{"lab": true, "rules": [
            {"tool": "dig", "args": "ctf", "action": "fake", "stdout": "lie\n"},
            {"tool": "dig", "args": "other", "action": "pass"}
        ]}"#,
    );
    assert_eq!(out(&bench.call("dig", &["ctf.example.com"])), "lie");
    assert_eq!(out(&bench.call("dig", &["other.example.com"])), "real");
    let audit = bench.audit();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0]["tool"], "dig");
    assert_eq!(audit[0]["args"], "ctf.example.com");
    assert_eq!(audit[0]["decision"], "fake");
    assert_eq!(audit[0]["rule"], 0);
    assert_eq!(audit[0]["exit"], 0);
    assert!(audit[0]["real"].as_str().unwrap().ends_with("/real/dig"));
    assert_eq!(audit[1]["decision"], "pass");
    assert_eq!(audit[1]["rule"], serde_json::Value::Null);
    // A pass is logged before the process is handed over, so it carries no exit code of its own.
    assert_eq!(audit[1]["exit"], serde_json::Value::Null);
}

/// A rules file with a typo fails open: one note on stderr, and the agent's command runs anyway.
#[test]
fn a_broken_rules_file_fails_open() {
    let bench = Bench::new();
    bench.tool("dig", "echo real; exit 5");
    bench.rules("{ not json");
    let output = bench.call("dig", &[]);
    assert_eq!(out(&output), "real");
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("rules.json"));
}

/// `{args}` and `{tool}` carry the call into the lie, so one rule can serve every argument.
#[test]
fn rule_text_substitutes_the_tool_and_the_arguments() {
    let bench = Bench::new();
    bench.rules(r#"{"rules": [{"tool": "*", "action": "fake", "stdout": "{tool}: {args}\n"}]}"#);
    assert_eq!(
        out(&bench.call("dig", &["ctf.example.com", "+short"])),
        "dig: ctf.example.com +short"
    );
}

/// The shims are the rules file's `tools`, so a name outside the default seven gets a shim too, and `spoof`
/// itself is linked alongside them so the CLI is reachable by name. `init` adds and never removes: a tool dropped
/// from the list keeps its symlink until it is deleted by hand. `lab.json` comes along too, inert until a target is
/// pointed at it.
#[test]
fn the_shims_are_the_rules_files_tools() {
    let bench = Bench::new();
    let fresh = bench.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::write(
        fresh.join("rules.json"),
        r#"{"tools": ["dig", "openssl"], "rules": []}"#,
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_spoof"))
        .args(["init", "--dir"])
        .arg(&fresh)
        .env("HOME", bench.tmp.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let mut names: Vec<String> = std::fs::read_dir(&fresh)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![".spoof", "dig", "lab.json", "openssl", "rules.json", "spoof"]
    );
    assert!(std::fs::metadata(fresh.join(".spoof")).unwrap().permissions().mode() & 0o111 != 0);

    // The `eval` line `init` prints has to run as printed, and put the shims (not the real tools) first.
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with("eval"))
        .unwrap()
        .trim()
        .to_owned();
    let checked = std::process::Command::new("/bin/sh")
        .args(["-c", &format!("{line}; command -v dig")])
        .output()
        .unwrap();
    assert!(checked.status.success(), "{}", String::from_utf8_lossy(&checked.stderr));
    assert_eq!(
        String::from_utf8_lossy(&checked.stdout).trim(),
        fresh.join("dig").display().to_string()
    );
}
