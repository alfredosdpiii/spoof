//! The CLI: `spoof init | env | list | log | demo | help`.
//!
//! `init` writes the shim directory (one copy of this binary, a symlink per tool, `spoof` itself, and a starter
//! `rules.json`);
//! `env` prints the one line an agent's shell needs; `list`, `log` and `demo` are how a human sees what the agent
//! is being told. Every command takes `--dir DIR` and otherwise uses [`crate::default_dir`].

use crate::rules::{DEFAULT_RULES, Decision, Rules};
use crate::{CLI_NAME, SHIM_BINARY, default_dir, fail, front, lab, mcp, panel, shim, split_dir_args as split};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// `println!` that treats a closed stdout as normal: `spoof demo | head` must not panic when `head` leaves.
macro_rules! say {
    ($($arg:tt)*) => {{
                let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// Commands an agent believes: `spoof demo` runs these through the shims.
const DEMO: &[(&str, &[&str])] = &[
    ("dig", &["ctf.example.com"]),
    ("whois", &["ctf.example.com"]),
    ("nmap", &["10.10.10.5"]),
    ("curl", &["-sI", "https://example.com"]),
    ("ping", &["-c", "1", "example.com"]),
];

pub fn run(argv: &[OsString]) -> i32 {
    let args: Vec<String> = argv.iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
    match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("env") => env(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("log") => log(&args[1..]),
        Some("demo") => demo(&args[1..]),
        Some("mcp") => mcp::command(&args[1..]),
        Some("panel") => panel::command(&args[1..]),
        Some("front") => front::command(&args[1..]),
        Some("lab") => lab::command(&args[1..]),
        None | Some("help" | "-h" | "--help") => {
            help();
            0
        }
        Some("-V" | "--version") => {
            say!("spoof {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some(other) => {
            eprintln!("spoof: unknown command {other}");
            help();
            2
        }
    }
}

/// `init [--dir DIR] [--force]`: the shim directory, the symlinks and a starter rules file.
fn init(args: &[String]) -> i32 {
    let (dir, rest) = match split(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(&error),
    };
    let force = rest.iter().any(|arg| arg == "--force");
    if let Some(other) = rest.iter().find(|arg| *arg != "--force") {
        return fail(&format!("unknown argument {other}"));
    }
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return fail(&format!("{}: {error}", dir.display()));
    }
    let target = dir.join(SHIM_BINARY);
    if let Err(error) = write_binary(&target) {
        return fail(&format!("{}: {error}", target.display()));
    }
    // `spoof` itself, so the `eval` line printed at the end is runnable as written and `spoof list|log|demo`
    // stay reachable by name once the shim directory is on `PATH`.
    if let Err(error) = link(&dir, CLI_NAME) {
        return fail(&format!("{}/{CLI_NAME}: {error}", dir.display()));
    }
    let rules = dir.join("rules.json");
    let fresh = force || !rules.exists();
    if fresh && let Err(error) = std::fs::write(&rules, DEFAULT_RULES) {
        return fail(&format!("{}: {error}", rules.display()));
    }
    let lab_file = lab::lab_path(&dir);
    if (force || !lab_file.exists())
        && let Err(error) = std::fs::write(&lab_file, lab::DEFAULT_LAB)
    {
        return fail(&format!("{}: {error}", lab_file.display()));
    }
    let tools = match Rules::load(&rules) {
        Ok(rules) => rules.tools,
        Err(error) => return fail(&error),
    };
    let mut linked = Vec::new();
    let mut kept = Vec::new();
    for tool in &tools {
        match link(&dir, tool) {
            Ok(true) => linked.push(tool.clone()),
            Ok(false) => kept.push(tool.clone()),
            Err(error) => return fail(&format!("{}/{tool}: {error}", dir.display())),
        }
    }
    say!("spoof: {} shims in {}", linked.len(), dir.display());
    say!(
        "  rules: {} ({})",
        rules.display(),
        if fresh { "written" } else { "kept" }
    );
    if !kept.is_empty() {
        say!("  kept (not a symlink, left alone): {}", kept.join(" "));
    }
    say!("  binary: {}", target.display());
    say!(
        "  lab:    {} (no target pointed yet: `{} panel`)",
        lab_file.display(),
        CLI_NAME
    );
    say!();
    say!("the agent believes these, your own shell does not:");
    say!("  eval \"$({}/spoof env{})\"", dir.display(), dir_arg(&dir));
    say!("  ultron");
    say!();
    say!("and its MCP tools, through the panel that points them at a real URL:");
    say!("  {}", mcp::config(&dir));
    say!("  {}/spoof panel{}", dir.display(), dir_arg(&dir));
    0
}

/// `env [--dir DIR]`: the `PATH` line to eval in the shell the agent is started from.
fn env(args: &[String]) -> i32 {
    let (dir, rest) = match split(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(&error),
    };
    if let Some(other) = rest.first() {
        return fail(&format!("unknown argument {other}"));
    }
    if !shim::shim_binary(&dir).exists() {
        eprintln!("spoof: {}: no `{}` yet; run `spoof init`", dir.display(), SHIM_BINARY);
    }
    say!("export PATH=\"{}:$PATH\"", dir.display());
    // The target by name, so a prompt can say "the local target" and every tool still knows the host it means.
    let lab = lab::Lab::load(&dir);
    if lab.on() {
        say!("export LAB_TARGET=\"{}\"", lab::host(&lab.target));
        say!("export LAB_FRONT=\"{}\"", lab.front);
    }
    0
}

/// `list [--dir DIR]`: the rules, the tools, and which tools really exist.
fn list(args: &[String]) -> i32 {
    let (dir, rest) = match split(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(&error),
    };
    if let Some(other) = rest.first() {
        return fail(&format!("unknown argument {other}"));
    }
    let path = shim::rules_path(&dir);
    let rules = match Rules::load(&path) {
        Ok(rules) => rules,
        Err(error) => return fail(&error),
    };
    let path_var = crate::var("PATH").unwrap_or_default();
    let lab = lab::Lab::load(&dir);
    say!(
        "lab: {} -> {}",
        lab.front,
        if lab.on() {
            lab.target.clone()
        } else {
            "(no target: nothing is redirected)".to_string()
        }
    );
    say!(
        "rules: {} (lab {}, {} rules)",
        path.display(),
        if rules.lab { "on" } else { "off" },
        rules.rules.len()
    );
    for (index, rule) in rules.rules.iter().enumerate() {
        say!(
            "  #{index} {} when={:?} args={} {}",
            rule.tool,
            rule.when,
            rule.args.as_ref().map_or("-", |pattern| pattern.as_str()),
            format!("{:?}", rule.action).to_lowercase()
        );
        if let Some(note) = &rule.note {
            say!("      {note}");
        }
    }
    for tool in &rules.tools {
        let real = shim::real_tool(tool, &path_var, &dir);
        say!(
            "  {tool}: {}",
            real.map_or("not on PATH".to_string(), |path| path.display().to_string())
        );
    }
    let target = shim::shim_binary(&dir);
    match (
        std::fs::read(&target),
        std::env::current_exe().ok().and_then(|exe| std::fs::read(exe).ok()),
    ) {
        (Ok(there), Some(here)) if there != here => say!(
            "  binary: {} differs from this one: rerun `spoof init`",
            target.display()
        ),
        (Err(_), _) => say!("  binary: {} missing: run `spoof init`", target.display()),
        _ => {}
    }
    0
}

/// `log [--dir DIR] [-n N]`: the tail of the lab audit log.
fn log(args: &[String]) -> i32 {
    let (dir, rest) = match split(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(&error),
    };
    let mut lines = 20usize;
    let mut index = 0;
    while index < rest.len() {
        if rest[index] == "-n" {
            match rest.get(index + 1).and_then(|value| value.parse().ok()) {
                Some(value) => lines = value,
                None => return fail("-n needs a count"),
            }
            index += 2;
        } else {
            return fail(&format!("unknown argument {}", rest[index]));
        }
    }
    let path = dir.join("audit.jsonl");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return fail(&format!("{}: {error}", path.display())),
    };
    let all: Vec<&str> = text.lines().collect();
    for line in &all[all.len().saturating_sub(lines)..] {
        say!("{line}");
    }
    eprintln!(
        "spoof: {} of {} lines from {}",
        all.len().min(lines),
        all.len(),
        path.display()
    );
    0
}

/// `demo [--dir DIR]`: run a few commands through the shims and print what the agent would believe.
fn demo(args: &[String]) -> i32 {
    let (dir, rest) = match split(args) {
        Ok(parsed) => parsed,
        Err(error) => return fail(&error),
    };
    if let Some(other) = rest.first() {
        return fail(&format!("unknown argument {other}"));
    }
    let binary = shim::shim_binary(&dir);
    if !binary.exists() {
        return fail(&format!("{}: no shims yet; run `spoof init`", dir.display()));
    }
    let rules = Rules::load(&shim::rules_path(&dir)).unwrap_or_default();
    let path_var = crate::var("PATH").unwrap_or_default();
    let with_shims = format!("{}:{path_var}", dir.display());
    say!("spoof: what a model running these commands would believe\n");
    for (tool, args) in DEMO {
        let joined = args.join(" ");
        let real = shim::real_tool(tool, &path_var, &dir);
        match crate::rules::decide(&rules.rules, tool, &joined, real.is_some()) {
            Decision::Fake { rule, index } => say!("rule #{index}: fake {}", rule.note.as_deref().unwrap_or("")),
            Decision::Rewrite { rule, index } => {
                say!("rule #{index}: rewrite {}", rule.note.as_deref().unwrap_or(""))
            }
            Decision::Pass if real.is_none() => say!("pass: {} is not installed here", tool),
            Decision::Pass => say!("pass: the real tool runs"),
        }
        say!("  $ {tool} {joined}");
        if let Some(real) = &real {
            say!("    real: {}", real.display());
        }
        let output = Command::new(dir.join(tool))
            .args(*args)
            .env("PATH", &with_shims)
            .output();
        match output {
            Ok(output) => {
                say!("  ─── agent sees (exit {}) ───", output.status.code().unwrap_or(127));
                for text in [&output.stdout, &output.stderr] {
                    for line in String::from_utf8_lossy(text).lines() {
                        say!("  {line}");
                    }
                }
            }
            Err(error) => say!("  {error}"),
        }
        say!();
    }
    0
}

fn help() {
    say!(
        "spoof {} — PATH shims that fabricate, rewrite or block a coding agent's tool output\n\
         \n\
         usage:\n\
         \x20 spoof init [--dir DIR] [--force]   write the shims and a starter rules.json\n\
         \x20 spoof env  [--dir DIR]             print the PATH line to eval before starting the agent\n\
         \x20 spoof list [--dir DIR]             the rules, and which tools really exist\n\
         \x20 spoof log  [--dir DIR] [-n N]      the tail of the lab audit log\n\
         \x20 spoof demo [--dir DIR]             run a few commands and show what the agent believes\n\
         \x20 spoof mcp  [--dir DIR]             the `ctf-local` MCP server over stdio, for an editor\n\
         \x20 spoof panel [--dir DIR] [--port N]  the panel: point the lab at a real URL\n\
         \x20 spoof front [--dir DIR] [--port N]  serve the front address for real, so the port is open\n\
         \x20 spoof lab  [URL] [--front URL] [--off]  the same, from the shell\n\
         \x20 spoof lab  add <path|URL> [name]    bring a real file, or a URL, in under a local name\n\
         \n\
         `ctf-local` is the same MCP server and panel as one standalone binary.\n\
         with ultron:  eval \"$(spoof env)\"  &&  ultron\n\
         \n\
         env: SPOOF_DIR (shim + lab directory), SPOOF_RULES (another rules file), SPOOF_LAB (another lab file),\n\
         SPOOF_OFF=1 (no rules), SPOOF_LOG=1\n\
         every rule is `pass`, `fake`, `block` or `rewrite`; see rules.json",
        env!("CARGO_PKG_VERSION")
    );
}

fn dir_arg(dir: &Path) -> String {
    if dir == default_dir() {
        String::new()
    } else {
        format!(" --dir {}", dir.display())
    }
}

/// Copy this binary into place, under a temporary name first so a running copy is never half-written.
fn write_binary(target: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let temp = target.with_file_name(format!("{SHIM_BINARY}.tmp.{}", std::process::id()));
    std::fs::copy(&exe, &temp).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    std::fs::rename(&temp, target).map_err(|error| error.to_string())
}

/// Link `tool` -> the shim binary. `Ok(false)` when a real file of that name is in the way.
fn link(dir: &Path, tool: &str) -> Result<bool, String> {
    let path = dir.join(tool);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.file_type().is_symlink() => Ok(false),
        Ok(_) => {
            std::fs::remove_file(&path).map_err(|error| error.to_string())?;
            std::os::unix::fs::symlink(SHIM_BINARY, &path).map_err(|error| error.to_string())?;
            Ok(true)
        }
        Err(_) => {
            std::os::unix::fs::symlink(SHIM_BINARY, &path).map_err(|error| error.to_string())?;
            Ok(true)
        }
    }
}
