//! The front port, really served.
//!
//! A shim can rewrite the `curl` in front of it, but `nc`, a socket in a script and `ss -ltn` see the port itself,
//! and a port with nothing behind it is a seam a model finds. `spoof front` binds the front address and answers
//! every request by fetching the target and localizing the answer, so the port is open and everything that connects
//! gets the local view — no rule per tool.

use crate::lab::Lab;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

/// `front [--dir DIR] [--port N]`: serve the lab's front address until killed.
pub fn command(args: &[String]) -> i32 {
    let (dir, rest) = match crate::split_dir_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return crate::fail(&error),
    };
    let mut port = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--port" => match rest.get(index + 1).and_then(|value| value.parse().ok()) {
                Some(value) => {
                    port = Some(value);
                    index += 2;
                }
                None => return crate::fail("--port needs a number"),
            },
            other => return crate::fail(&format!("unknown argument {other}")),
        }
    }
    run(&dir, port)
}

/// The address to bind: the front's host and port, with `localhost` on the loopback.
fn bind_addr(front: &str) -> Result<String, String> {
    let rest = front.split_once("://").map_or(front, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| format!("no port in `{front}`"))?),
        None => (authority, 80),
    };
    if host.is_empty() {
        return Err(format!("no host in `{front}`"));
    }
    Ok(format!(
        "{}:{port}",
        if host == "localhost" { "127.0.0.1" } else { host }
    ))
}

fn run(dir: &Path, port: Option<u16>) -> i32 {
    let lab = Lab::load(dir);
    let front = if lab.front.is_empty() {
        crate::lab::DEFAULT_FRONT.to_string()
    } else {
        lab.front.clone()
    };
    let addr = match bind_addr(&front) {
        Ok(addr) => addr,
        Err(error) => return crate::fail(&error),
    };
    let addr = match port {
        Some(port) => format!("{}:{port}", addr.rsplit_once(':').map_or("127.0.0.1", |(host, _)| host)),
        None => addr,
    };
    let listener = match TcpListener::bind(&addr) {
        Ok(listener) => listener,
        Err(error) => return crate::fail(&format!("front: {addr}: {error}")),
    };
    let where_ = Lab::load(dir).target.clone();
    println!(
        "spoof: front on http://{addr}/ -> {}",
        if where_.is_empty() { "(no target yet)" } else { &where_ }
    );
    println!("  every request here goes to the target and comes back local; `ss -ltn` will show the port");
    for stream in listener.incoming().flatten() {
        let dir = dir.to_path_buf();
        std::thread::spawn(move || {
            let _ = serve(stream, &dir);
        });
    }
    0
}

fn serve(mut stream: TcpStream, dir: &Path) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
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
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
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
    let lab = Lab::load(dir);
    let wire = lab.fetch(
        dir,
        &target,
        &method,
        if body.is_empty() { None } else { Some(&body) },
        &[],
    );
    let text = match wire {
        Ok(wire) => reheader(&lab.localize(&wire)),
        Err(error) => {
            format!("HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n{error}\n")
        }
    };
    stream.write_all(text.as_bytes())?;
    stream.flush()
}

/// curl's `-i` answer as HTTP/1.1, with a length that still matches after localization rewrote the body.
fn reheader(wire: &str) -> String {
    let (head, body) = wire.split_once("\r\n\r\n").unwrap_or((wire, ""));
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("HTTP/2 200");
    let mut code = status.split_whitespace().nth(1).unwrap_or("200").to_string();
    let reason = status.split_whitespace().nth(2).unwrap_or("").to_string();
    if code.is_empty() {
        code = "200".to_string();
    }
    let mut out = format!("HTTP/1.1 {code} {reason}\r\n");
    for line in lines {
        let name = line
            .split_once(':')
            .map_or(String::new(), |(name, _)| name.to_ascii_lowercase());
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", body.len()));
    out.push_str(body);
    out
}
