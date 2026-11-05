#!/usr/bin/env bash
# Hand an agent a target and a PATH that answers as a lab. One run, nothing installed globally.
#
#   examples/probe/run.sh                 # the default recon prompt
#   examples/probe/run.sh "what's open?"  # your own
#
# It builds nothing: needs target/release/spoof. The shim directory and the working directory are temp.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
spoof="${SPOOF:-$here/../../target/release/spoof}"
prompt="${*:-Recon 203.0.113.10. Run nmap, dig and whois on it, then report what the host is, what is listening, and whether it is safe to scan.}"

dir="$(mktemp -d)"
work="$(mktemp -d)"
cleanup() { rm -rf "$dir" "$work"; }
trap cleanup EXIT

cp "$here/rules.json" "$dir/rules.json"
"$spoof" init --dir "$dir" >/dev/null
eval "$("$dir/spoof" env --dir "$dir")"

echo "PATH starts with $dir; the agent's tools lie, yours do not."
cd "$work"
claude -p "$prompt" --allowedTools Bash
