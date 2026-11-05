//! Intercept mode: what a shim does with the call it was handed.
//!
//! Order: resolve the real tool on `PATH` (never itself), load the rules, let the first match decide, then fake,
//! rewrite or run. A missing or broken rules file fails open with one line on stderr, so a typo can never break the
//! agent's commands. `SPOOF_OFF` skips the rules entirely and `SPOOF_RULES` names another rules file.
//!
//! Everything a `pass` or `rewrite` decision runs is an absolute path to a different file, so a shim never calls
//! itself; and a resolved tool *inside* the shim directory is skipped, which is what makes a `PATH` that lists the
//! shim directory twice (or through a symlinked spelling) still find the real tool.

use crate::lab::{Lab, host};
use crate::rules::{Decision, Rules, decide};
use crate::{SHIM_BINARY, var};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exit code for a tool that does not exist and no rule stands in for, as a shell reports it.
const NOT_FOUND: i32 = 127;

/// Intercept one call: `tool` is the shim's own name, `args` what it was given, `dir` the shim directory that holds
/// the rules. Returns the exit code.
pub fn run(tool: &str, args: &[OsString], dir: &Path) -> i32 {
    let joined: Vec<String> = args.iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
    let joined = joined.join(" ");
    let real = real_tool(tool, &var("PATH").unwrap_or_default(), dir);
    let rules = match Rules::load(&rules_path(dir)) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("spoof: {error}");
            Rules::default()
        }
    };
    let decision = if off() {
        Decision::Pass
    } else {
        decide(&rules.rules, tool, &joined, real.is_some())
    };
    let log = log_wanted(&rules);
    // A pass hands this process to the real tool, so its audit line is written first, without an exit code: the
    // code is the tool's own, and nothing runs after `exec`.
    if matches!(decision, Decision::Pass)
        && let Some(real) = &real
    {
        if log {
            audit(dir, tool, &joined, Some(real), decision, None);
        }
        return exec(real, args);
    }
    let code = match decision {
        Decision::Pass => not_found(tool),
        Decision::Fake { rule, .. } => {
            let (stdout, stderr) = rule.text(tool, &joined);
            let _ = std::io::stdout().write_all(stdout.as_bytes());
            let _ = std::io::stderr().write_all(stderr.as_bytes());
            rule.exit_code(if rule.action == crate::rules::Action::Block {
                1
            } else {
                0
            })
        }
        Decision::Rewrite { rule, .. } => rewrite(rule, tool, &joined, real.as_deref(), args, dir),
    };
    if log {
        audit(dir, tool, &joined, real.as_deref(), decision, Some(code));
    }
    code
}

/// A rewrite: run the real tool, transform its stdout, keep its exit code (unless the rule overrides it). With no
/// real tool the rule's own text stands in for the output.
fn rewrite(
    rule: &crate::rules::Rule,
    tool: &str,
    joined: &str,
    real: Option<&Path>,
    args: &[OsString],
    dir: &Path,
) -> i32 {
    // A rewrite is the call that reaches the target and the answer the model reads. When a lab is pointed, the
    // front in the command line becomes the target on the way in and the target's spelling becomes the front on
    // the way out, so `curl http://localhost:8080/` is a real request instead of a dead port.
    let lab = Lab::load(dir);
    let mapped: Vec<OsString> = if lab.on() {
        args.iter().map(|arg| map_front(&lab, arg)).collect()
    } else {
        args.to_vec()
    };
    let Some(real) = real else {
        let (stdout, stderr) = rule.text(tool, joined);
        let _ = std::io::stdout().write_all(stdout.as_bytes());
        let _ = std::io::stderr().write_all(stderr.as_bytes());
        let fallback = if rule.stdout.is_empty() { NOT_FOUND } else { 0 };
        return rule.exit_code(fallback);
    };
    let output = match Command::new(real).args(&mapped).output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("spoof: {}: {error}", real.display());
            return NOT_FOUND;
        }
    };
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if lab.on() {
        text = lab.localize(&text);
    }
    for (pattern, replacement) in &rule.replace {
        text = pattern.replace_all(&text, replacement.as_str()).into_owned();
    }
    let _ = std::io::stdout().write_all(text.as_bytes());
    let _ = std::io::stderr().write_all(&output.stderr);
    let fallback = output.status.code().unwrap_or(NOT_FOUND);
    rule.exit_code(fallback)
}

/// Swap the front for the target in one argument, scheme-qualified first so a bare `localhost:8080` still maps.
/// An argument that holds neither is handed back untouched.
fn map_front(lab: &Lab, arg: &OsString) -> OsString {
    let front_host = host(&lab.front);
    let target_host = host(&lab.target);
    let text = arg.to_string_lossy();
    let mapped = text.replace(&lab.front, &lab.target).replace(&front_host, &target_host);
    if mapped == text {
        arg.clone()
    } else {
        OsString::from(mapped)
    }
}

/// Run the real tool as this process (`exec`): signals, terminal and exit code stay its own.
fn exec(real: &Path, args: &[OsString]) -> i32 {
    let error = Command::new(real).args(args).exec();
    eprintln!("spoof: {}: {error}", real.display());
    NOT_FOUND
}

fn not_found(tool: &str) -> i32 {
    eprintln!("spoof: {tool}: no executable on PATH and no rule for it");
    NOT_FOUND
}

/// The rules file beside the shims, or `$SPOOF_RULES`.
pub fn rules_path(dir: &Path) -> PathBuf {
    match var("SPOOF_RULES").filter(|path| !path.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => dir.join("rules.json"),
    }
}

/// `SPOOF_OFF=1`: hand every call to the real tool, rules and all.
fn off() -> bool {
    matches!(
        var("SPOOF_OFF").map(|value| value.trim().to_lowercase()).as_deref(),
        Some("1" | "on" | "true" | "yes")
    )
}

fn log_wanted(rules: &Rules) -> bool {
    rules.lab
        || matches!(
            var("SPOOF_LOG").map(|value| value.trim().to_lowercase()).as_deref(),
            Some("1" | "on" | "true" | "yes")
        )
}

/// The audit line: what was called, what decided it, and what came out. Appended with one `write_all` to an
/// `O_APPEND` file, so concurrent shims interleave lines and never half a line (a line stays under `PIPE_BUF`).
fn audit(dir: &Path, tool: &str, args: &str, real: Option<&Path>, decision: Decision<'_>, code: Option<i32>) {
    let line = serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_millis()),
        "tool": tool,
        "args": truncate(args, 512),
        "cwd": std::env::current_dir().ok().map(|dir| dir.to_string_lossy().into_owned()),
        "pid": std::process::id(),
        "decision": decision.label(),
        "rule": decision.index(),
        "exit": code,
        "real": real.map(|path| path.to_string_lossy().into_owned()),
    });
    let mut line = line.to_string();
    line.push('\n');
    let path = dir.join("audit.jsonl");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}

fn truncate(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((at, _)) => &text[..at],
        None => text,
    }
}

/// The real tool for `tool`: the first executable of that name on `path` outside the shim directory `dir`.
pub fn real_tool(tool: &str, path: &str, dir: &Path) -> Option<PathBuf> {
    let name = Path::new(tool).file_name()?;
    let shim = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    for entry in std::env::split_paths(path) {
        let entry = if entry.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            entry
        };
        if std::fs::canonicalize(&entry).is_ok_and(|here| here == shim) {
            continue;
        }
        let candidate = entry.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Whether `path` is a file this user may execute (following symlinks), the same test `execvp` makes.
pub fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// The shim binary's path inside `dir`.
pub fn shim_binary(dir: &Path) -> PathBuf {
    dir.join(SHIM_BINARY)
}
