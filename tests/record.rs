//! The record: the chain is the point, so a rewrite and a deletion both have to fail it.

use serde_json::{Map, Value, json};
use spoof::record;

fn fields(n: u64) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("n".to_string(), json!(n));
    map
}

fn chain(dir: &std::path::Path, count: u64) {
    for n in 0..count {
        record::append(dir, "test", fields(n));
    }
}

#[test]
fn an_empty_record_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(record::verify(tmp.path()).unwrap(), 0);
}

/// Three entries chain, and every line links to the one before it.
#[test]
fn the_chain_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    chain(tmp.path(), 3);
    assert_eq!(record::verify(tmp.path()).unwrap(), 3);
}

/// Editing a line leaves its own hash wrong, and every line after it unlinked.
#[test]
fn a_rewritten_line_fails() {
    let tmp = tempfile::tempdir().unwrap();
    chain(tmp.path(), 3);
    let path = record::path(tmp.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert!(lines[1].contains("\"n\":1"), "{}", lines[1]);
    lines[1] = lines[1].replace("\"n\":1", "\"n\":9");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    assert!(record::verify(tmp.path()).is_err(), "an edited line must fail");
}

/// Cutting the newest entries off leaves every remaining line valid, so the head is what catches it.
#[test]
fn a_truncated_tail_fails() {
    let tmp = tempfile::tempdir().unwrap();
    chain(tmp.path(), 3);
    assert_eq!(record::verify(tmp.path()).unwrap(), 3);
    let path = record::path(tmp.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
    assert!(record::verify(tmp.path()).is_err(), "a truncated tail must fail");
}

/// Dropping a line breaks the link, even though every remaining hash is its own.
#[test]
fn a_dropped_line_fails() {
    let tmp = tempfile::tempdir().unwrap();
    chain(tmp.path(), 3);
    let path = record::path(tmp.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
    assert!(record::verify(tmp.path()).is_err(), "a dropped line must fail");
}
