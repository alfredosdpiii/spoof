//! The test kit: a temp workspace with shims from `spoof init`, a "real" tool directory, and a rules file.
//!
//! Each test binary uses part of it, so an unused helper is not dead code.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

/// One test's world: `shims/` (from `spoof init`), `real/` (stand-ins for the real tools) and `work/` (the cwd).
pub struct Bench {
    pub tmp: tempfile::TempDir,
    pub dir: PathBuf,
    pub real: PathBuf,
    pub cwd: PathBuf,
}

impl Bench {
    pub fn new() -> Bench {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let (dir, real, cwd) = (root.join("shims"), root.join("real"), root.join("work"));
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_spoof"))
            .args(["init", "--dir"])
            .arg(&dir)
            .env("HOME", &root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        Bench { tmp, dir, real, cwd }
    }

    /// Replace the starter rules.
    pub fn rules(&self, json: &str) {
        std::fs::write(self.dir.join("rules.json"), json).unwrap();
    }

    /// A stand-in real tool: `sh` runs `body` with the tool's arguments.
    pub fn tool(&self, name: &str, body: &str) {
        let path = self.real.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The agent's PATH: the shims first, then the real tools, then this machine's.
    pub fn path(&self) -> String {
        match std::env::var("PATH") {
            Ok(system) => format!("{}:{}:{system}", self.dir.display(), self.real.display()),
            Err(_) => format!("{}:{}", self.dir.display(), self.real.display()),
        }
    }

    /// The agent's PATH without the real tools: what a machine without them looks like. Only the shims, so the
    /// stand-in `real/` dir *and* this machine's own copies are out of reach (the shebang is absolute, so a
    /// stand-in still runs).
    pub fn path_without_real(&self) -> String {
        self.dir.display().to_string()
    }

    /// Run a shim the way a shell on the agent's PATH would, and return what the agent would see.
    pub fn call_on(&self, path: &str, tool: &str, args: &[&str]) -> Output {
        Command::new(self.dir.join(tool))
            .args(args)
            .env("PATH", path)
            .env("HOME", self.tmp.path())
            .current_dir(&self.cwd)
            .output()
            .unwrap()
    }

    pub fn call(&self, tool: &str, args: &[&str]) -> Output {
        let path = self.path();
        self.call_on(&path, tool, args)
    }

    /// The audit log's lines.
    pub fn audit(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// A run's stdout, trimmed.
pub fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim_end().to_string()
}
