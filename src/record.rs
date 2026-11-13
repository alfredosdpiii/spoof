//! The record: one append-only, hash-chained line for everything the lab did.
//!
//! The lab is believed, never watched, so the record is what is left when the session ends. Every line carries the
//! hash of the line before it: an edit anywhere invalidates that line and every line after it, and a deletion breaks
//! the link. `verify` walks the whole chain and names the first line that does not add up.
//!
//! One write per line, `O_APPEND`: the kernel serialises a write under a pipe buffer, so a line is capped below that
//! and two processes cannot interleave inside one. Two processes *can* both chain onto the same line and fork the
//! chain; `verify` reports a fork as a break rather than hiding it. ponytail: no lock file until a fork is seen.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// What one line may carry: below a pipe buffer, so a single `write` cannot interleave with another process.
pub const LIMIT: usize = 1024;

/// The record, beside the rules and the lab file.
pub fn path(dir: &Path) -> PathBuf {
    dir.join("audit.jsonl")
}

/// Append one chained entry. `fields` is what the caller knows; the chain is added here.
pub fn append(dir: &Path, kind: &str, fields: Map<String, Value>) {
    let path = path(dir);
    let (prev, seq) = last(&path);
    let mut entry = Map::new();
    entry.insert("seq".to_string(), json!(seq + 1));
    entry.insert("ts".to_string(), json!(now()));
    entry.insert("kind".to_string(), json!(kind));
    for (key, value) in fields {
        entry.insert(key, value);
    }
    entry.insert("prev".to_string(), json!(prev));
    let hash = hash(&Value::Object(entry.clone()));
    entry.insert("hash".to_string(), json!(hash));
    let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(0);
    let hash = entry
        .get("hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(format!("{}\n", Value::Object(entry)).as_bytes());
    }
    // The head is what makes the *last* line matter: without it, deleting the newest entry is indistinguishable
    // from never having written it. Written after the line, so a crash between the two leaves a head that is behind
    // the file, which reads as fine. ponytail: no lock, two processes can race the head; the file is the record.
    let _ = std::fs::write(head(dir), format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}\n"));
}

/// The anchor beside the record: the last entry's number and hash.
pub fn head(dir: &Path) -> PathBuf {
    dir.join("audit.head")
}

/// Read it back, checking every hash and every link. `Ok(n)` counts the chained entries; `Err` names the first line
/// that does not add up.
pub fn verify(dir: &Path) -> Result<usize, String> {
    let path = path(dir);
    if !path.exists() {
        return Ok(0); // nothing written yet is not a broken record
    }
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut prev = String::new();
    let mut checked = 0;
    let mut highest = 0;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line).map_err(|error| format!("line {}: {error}", index + 1))?;
        let Some(claimed) = entry.get("hash").and_then(Value::as_str) else {
            continue; // written before the chain existed
        };
        let mut bare = entry.clone();
        if let Some(map) = bare.as_object_mut() {
            map.remove("hash");
        }
        if hash(&bare) != claimed {
            return Err(format!("line {}: its contents do not match its hash", index + 1));
        }
        let link = entry.get("prev").and_then(Value::as_str).unwrap_or_default();
        if !prev.is_empty() && link != prev {
            return Err(format!("line {}: does not follow the line before it", index + 1));
        }
        prev = claimed.to_string();
        checked += 1;
        highest = entry.get("seq").and_then(Value::as_u64).unwrap_or(highest);
    }
    if let Ok(text) = std::fs::read_to_string(head(dir))
        && let Ok(anchor) = serde_json::from_str::<Value>(&text)
        && let Some(want) = anchor.get("seq").and_then(Value::as_u64)
        && highest < want
    {
        return Err(format!("the record stops at entry {highest}, its head names {want}"));
    }
    Ok(checked)
}

/// Shorten a payload to what one line can carry, on a character boundary.
pub fn clip(text: &str) -> (String, bool) {
    if text.len() <= LIMIT {
        return (text.to_string(), false);
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

fn last(path: &Path) -> (String, u64) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (String::new(), 0);
    };
    for line in text.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Value>(line) {
            let hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            return (hash, entry.get("seq").and_then(Value::as_u64).unwrap_or(0));
        }
    }
    (String::new(), 0)
}

fn hash(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}
