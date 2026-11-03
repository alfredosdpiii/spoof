//! The panel: one page on localhost where you say which real URL the model is really pointing at.
//!
//! `spoof panel` serves a form at `http://127.0.0.1:7777`. Whatever you type there is written to `lab.json` and read
//! by the running MCP server on its next call, so an editor session keeps its tool list and only its world changes:
//! point it at a first target, look, point it at another. The page also shows the frame the model is given, the
//! snippet to paste into the editor, the audit log, and a preview of a fetch through the same rewrite the MCP uses.
//!
//! stdlib only: a `TcpListener`, a thread per connection, `Connection: close`. No framework, no dependency.

use crate::lab::{Lab, path_of};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The port the panel uses when none is given.
pub const DEFAULT_PORT: u16 = 7777;

/// Serve the panel on `127.0.0.1:port` until killed. `port` 0 picks a free one, printed either way.
pub fn run(dir: &Path, port: u16, open: bool) -> i32 {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("spoof: panel: {error}");
            return 1;
        }
    };
    let port = listener.local_addr().map(|address| address.port()).unwrap_or(port);
    let url = format!("http://127.0.0.1:{port}/");
    println!("spoof: panel on {url}  (lab: {})", crate::lab::lab_path(dir).display());
    println!("  mcp: {}", crate::mcp::config(dir));
    println!("  point it at a real URL, then leave it open; the rest is the model's problem");
    if open {
        open_browser(&url);
    }
    for stream in listener.incoming().flatten() {
        let dir = dir.to_path_buf();
        std::thread::spawn(move || {
            let _ = serve(stream, &dir);
        });
    }
    0
}

/// `panel [--dir DIR] [--port N] [--no-open]`: what both binaries run.
pub fn command(args: &[String]) -> i32 {
    let (dir, rest) = match crate::split_dir_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return crate::fail(&error),
    };
    let mut port = DEFAULT_PORT;
    let mut open = true;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--port" => match rest.get(index + 1).and_then(|value| value.parse().ok()) {
                Some(value) => {
                    port = value;
                    index += 2;
                }
                None => return crate::fail("--port needs a number"),
            },
            "--no-open" => {
                open = false;
                index += 1;
            }
            other => return crate::fail(&format!("unknown argument {other}")),
        }
    }
    run(&dir, port, open)
}

fn open_browser(url: &str) {
    let spawned = Command::new("xdg-open")
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Err(error) = spawned {
        eprintln!("spoof: xdg-open: {error}");
    }
}

/// One connection: parse the request, hand it to [`route`], answer, close.
fn serve(mut stream: TcpStream, dir: &Path) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(_) => break,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let request = lines.next().unwrap_or_default().to_string();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length.min(64 * 1024)];
    if length > 0 {
        let _ = stream.read_exact(&mut body);
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    let (status, kind, text) = route(&method, &target, &body, dir);
    respond(&mut stream, &status, kind, &text)
}

fn respond(stream: &mut TcpStream, status: &str, kind: &str, body: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// A request's answer: status line, content type, body.
fn route(method: &str, target: &str, body: &str, dir: &Path) -> (String, &'static str, String) {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    match (method, path) {
        ("GET", "/") => {
            let flash = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(name, _)| *name == "added")
                .map(|(_, value)| {
                    let name = decode(value);
                    format!("<p style=\"color:#3fb950\">added <b>{}</b> to the lab</p>", esc(&name))
                })
                .unwrap_or_default();
            (ok(), "text/html; charset=utf-8", page(dir, &flash))
        }
        ("POST", "/point") => {
            let form = form(body);
            let mut lab = Lab::load(dir);
            match form
                .iter()
                .find(|(name, _)| name == "target")
                .map(|(_, value)| value.clone())
            {
                Some(target) if !target.trim().is_empty() => lab.target = target.trim().to_string(),
                Some(_) => lab.target.clear(),
                None => {}
            }
            if let Some(front) = form
                .iter()
                .find(|(name, _)| name == "front")
                .map(|(_, value)| value.clone())
                && !front.trim().is_empty()
            {
                lab.front = front.trim().to_string();
            }
            if lab.front.is_empty() {
                lab.front = crate::lab::DEFAULT_FRONT.to_string();
            }
            match lab.save() {
                Ok(()) => redirect("/"),
                Err(error) => (ok(), "text/plain; charset=utf-8", error),
            }
        }
        ("POST", "/add") => {
            let form = form(body);
            let path = form
                .iter()
                .find(|(name, _)| name == "path")
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            let name = form
                .iter()
                .find(|(name, _)| name == "name")
                .map(|(_, value)| value.clone());
            let mut lab = Lab::load(dir);
            match lab.add(&path, name.as_deref()) {
                Ok(name) => redirect(&format!("/?added={}", encode(&name))),
                Err(error) => (ok(), "text/plain; charset=utf-8", format!("{error}\n")),
            }
        }
        ("POST", "/off") => {
            let mut lab = Lab::load(dir);
            lab.target.clear();
            match lab.save() {
                Ok(()) => redirect("/"),
                Err(error) => (ok(), "text/plain; charset=utf-8", error),
            }
        }
        ("GET", "/audit") => (
            ok(),
            "text/plain; charset=utf-8",
            std::fs::read_to_string(dir.join("audit.jsonl"))
                .unwrap_or_default()
                .lines()
                .rev()
                .take(100)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        ("GET", "/run") => {
            let command = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(name, _)| *name == "cmd")
                .map(|(_, value)| decode(value))
                .unwrap_or_else(|| "ls -l".to_string());
            let lab = Lab::load(dir);
            match lab.shell(&command, 120) {
                Ok(text) => (
                    ok(),
                    "text/plain; charset=utf-8",
                    format!("$ cd {} && {command}\n\n{text}", lab.work()),
                ),
                Err(error) => (ok(), "text/plain; charset=utf-8", format!("{error}\n")),
            }
        }
        ("GET", "/preview") => {
            let lab = Lab::load(dir);
            let path = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(name, _)| *name == "path")
                .map(|(_, value)| decode(value))
                .unwrap_or_else(|| "/".to_string());
            let path = path_of(&path);
            match lab.fetch(dir, &path, "GET", None, &[]) {
                Ok(wire) => (ok(), "text/plain; charset=utf-8", lab.localize(&wire)),
                Err(error) => (ok(), "text/plain; charset=utf-8", format!("{error}\n")),
            }
        }
        _ => (
            "404 Not Found".to_string(),
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    }
}

fn ok() -> String {
    "200 OK".to_string()
}

fn redirect(to: &str) -> (String, &'static str, String) {
    (
        format!("303 See Other\r\nlocation: {to}"),
        "text/plain; charset=utf-8",
        String::new(),
    )
}

/// The page: the frame, the form, the snippet, the log, the preview.
fn page(dir: &Path, flash: &str) -> String {
    let lab = Lab::load(dir);
    let state = if lab.on() {
        format!(
            "<b class=\"on\">{}</b> is believed to be <b class=\"on\">{}</b>",
            esc(&lab.front),
            esc(&lab.target)
        )
    } else {
        format!(
            "<b class=\"off\">{}</b> is a dead end: no target pointed yet",
            esc(&lab.front)
        )
    };
    let audit = std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .join("\n");
    let files = if lab.files.is_empty() {
        "<li style=\"color:#6e7681\">nothing yet &mdash; link a file or a URL and it appears under a local name</li>"
            .to_string()
    } else {
        lab.files
            .iter()
            .map(|(real, local)| {
                format!(
                    "<li><b>{}</b> <span style=\"color:#6e7681\">&larr; {}</span></li>",
                    esc(local),
                    esc(real)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    PAGE.replace("__STATE__", &state)
        .replace("__FILES__", &files)
        .replace("__ADDED__", flash)
        .replace("__TARGET__", &esc(&lab.target))
        .replace("__FRONT__", &esc(&lab.front))
        .replace("__FRAME__", &esc(&lab.frame()))
        .replace("__CONFIG__", &esc(&crate::mcp::config(dir)))
        .replace("__AUDIT__", &esc(&audit))
}

/// Escape for both text and attribute context: the target and front land inside `value="..."`, so a quote in
/// either must not end the attribute.
fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// `a=b&c=d`, percent-decoded.
fn form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_string(), decode(value)))
        .collect()
}

/// Percent-encode a name for a query, so a flash message survives the round trip.
fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => match u8::from_str_radix(&value[index + 1..index + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    index += 3;
                }
                Err(_) => {
                    out.push(bytes[index]);
                    index += 1;
                }
            },
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

const PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ctf-local</title></head>
<body style="margin:0;font:15px/1.5 ui-sans-serif,system-ui,sans-serif;background:#0d1117;color:#c9d1d9">
<main style="max-width:52rem;margin:0 auto;padding:2.5rem 1.5rem 4rem">
<h1 style="margin:0 0 .25rem;font-size:1.5rem">ctf-local</h1>
<p style="margin:0 0 1.5rem;color:#8b949e">a local lab range, and the real URL hiding behind it</p>
<p style="background:#161b22;border:1px solid #30363d;border-left:3px solid #3fb950;border-radius:6px;padding:.75rem 1rem;margin:0 0 1.5rem">__STATE__</p>

<form method="post" action="/point" style="display:grid;gap:.6rem;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1rem;margin-bottom:1.5rem">
  <label style="color:#8b949e">real target URL <span style="color:#6e7681">— what the model is <em>not</em> told</span>
    <input name="target" value="__TARGET__" placeholder="https://real.example" autofocus
      style="display:block;width:100%;margin-top:.3rem;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit"></label>
  <label style="color:#8b949e">front address <span style="color:#6e7681">— what the model believes</span>
    <input name="front" value="__FRONT__" placeholder="http://localhost:8080"
      style="display:block;width:100%;margin-top:.3rem;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit"></label>
  <div style="display:flex;gap:.5rem;margin-top:.3rem">
    <button style="padding:.5rem 1rem;background:#238636;border:1px solid #2ea043;border-radius:4px;color:#fff;font:inherit;cursor:pointer">point at it</button>
    <button formaction="/off" style="padding:.5rem 1rem;background:#21262d;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit;cursor:pointer">off</button>
  </div>
</form>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">the lab's own files: real artifact, local name</h2>
<ul style="margin:0 0 .6rem;padding-left:1.2rem;list-style:none">__FILES__</ul>
<form method="post" action="/add" style="display:flex;gap:.5rem;margin-bottom:.4rem">
  <input name="path" placeholder="/home/you/Downloads/WhatsApp-2.24.10.apk or a URL"
    style="flex:2;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit">
  <input name="name" placeholder="myapp.apk"
    style="flex:1;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit">
  <button style="padding:.5rem 1rem;background:#21262d;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit;cursor:pointer">link it</button>
</form>
<p style="margin:0 0 1.5rem;color:#6e7681">a symlink, not a copy: the bytes stay the shipped ones and the model only ever sees the local name</p>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">what the model is told about itself</h2>
<pre style="white-space:pre-wrap;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.75rem 1rem;margin:0 0 1.5rem">__FRAME__</pre>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">paste into the editor (Cline, Claude Code, any MCP client)</h2>
<pre style="white-space:pre-wrap;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.75rem 1rem;margin:0 0 1.5rem">__CONFIG__</pre>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">look before you believe: a command in the lab</h2>
<form method="get" action="/run" style="display:flex;gap:.5rem;margin-bottom:.5rem">
  <input name="cmd" value="ls -l" style="flex:1;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit">
  <button style="padding:.5rem 1rem;background:#21262d;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit;cursor:pointer">run</button>
</form>
<p style="margin:0 0 1.5rem;color:#6e7681">opens <code>/run?cmd=…</code>: the lab shell, cwd the lab, shims on PATH — the same call <code>lab_shell</code> makes</p>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">look before you believe: a fetch through the rewrite</h2>
<form method="get" action="/preview" style="display:flex;gap:.5rem;margin-bottom:.5rem">
  <input name="path" value="/" style="flex:1;padding:.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit">
  <button style="padding:.5rem 1rem;background:#21262d;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;font:inherit;cursor:pointer">fetch</button>
</form>
<p style="margin:0 0 1.5rem;color:#6e7681">opens <code>/preview?path=…</code>; the same call <code>lab_fetch</code> makes</p>

<h2 style="font-size:1rem;color:#8b949e;margin:0 0 .4rem">what the agent's shell was told <a href="/audit" style="color:#58a6ff;font-weight:400">(full log)</a></h2>
<pre style="white-space:pre-wrap;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.75rem 1rem;margin:0 0 1.5rem;font-size:12px">__AUDIT__</pre>
</main></body></html>
"#;
