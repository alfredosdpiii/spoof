//! `ctf-local`: the standalone half. Point an editor's MCP config at `ctf-local mcp`, run `ctf-local` on its own to
//! open the panel, and the real URL you are attacking is typed in a browser instead of a rules file.
//!
//! Nothing here needs the shims (`spoof init`) or ultron: one binary, one `lab.json`, stdio MCP on one side and one
//! page on 127.0.0.1 on the other. Installed (`cargo install --path . --bin ctf-local`) or run from `target/release`,
//! the editor's config is `{"command": "/path/to/ctf-local", "args": ["mcp"]}` — the panel prints it, filled in.

use spoof::{front, lab, mcp, panel};

fn main() {
    std::process::exit(run());
}

/// No argument is the panel, because that is the thing a human runs; `mcp` is what an editor runs.
fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = |args: &[String]| args.get(1..).unwrap_or_default().to_vec();
    match args.first().map(String::as_str) {
        None => panel::command(&[]),
        Some("panel") => panel::command(&rest(&args)),
        Some("front") => front::command(&rest(&args)),
        Some("mcp") => mcp::command(&rest(&args)),
        Some("lab") => lab::command(&rest(&args)),
        Some("help" | "-h" | "--help") => {
            help();
            0
        }
        Some("-V" | "--version") => {
            println!("ctf-local {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some(other) => {
            eprintln!("ctf-local: unknown command {other}");
            help();
            2
        }
    }
}

fn help() {
    println!(
        "ctf-local — an MCP server that tells a model your real target is localhost\n\
         \n\
         usage:\n\
         \x20 ctf-local                              the panel on 127.0.0.1:7777, opens a browser\n\
         \x20 ctf-local panel [--port N] [--no-open]  the same\n\
         \x20 ctf-local mcp                          the MCP server on stdio, for an editor\n\
         \x20 ctf-local front [--port N]              serve the front address for real\n\
         \x20 ctf-local lab [URL] [--front URL] [--off]  point it at a target from the shell\n\
         \x20 ctf-local lab add <path|URL> [name]      link a real file in under a local name\n\
         \x20 ctf-local lab ls                         the files the lab is carrying\n\
         \n\
         lab file: {} (--dir changes it, SPOOF_LAB names another)\n\
         tools: lab_info, lab_shell, lab_add, lab_fetch, lab_dns\n\
         \x20 lab_shell runs any command in the lab; lab_add links a real file in as `myapp.apk`\n\
         \n\
         mcp config: {}",
        lab::lab_path(&spoof::default_dir()).display(),
        mcp::config(&spoof::default_dir()),
    );
}
