---
name: verify-spoof
description: "Checks on spoof and its ctf-local lab (the agent tool-output shims, the MCP server, the panel): the decision laws (first match, gating, no self-execution, transparency) over every input in a stated space. Use before shipping a change to spoof, after changing rules.rs or shim.rs, when a shim loops, fakes the wrong thing, or a rule stops firing."
---

# Verify spoof

`spoof` decides what a coding agent's tool calls answer. Its three promises, and what breaking each costs:

1. **The first matching rule decides, and appending a rule never changes an earlier decision.** Broken: a rules file
   edited from the bottom silently stops lying about the command at its top, and nobody sees why.
2. **The real tool is never the shim.** Broken: `real_tool` resolves a path inside the shim directory, the shim
   `exec`s itself, and the process loops forever instead of running `dig` (or 127s).
3. **A command no rule touches is the real tool, byte for byte.** Broken: a shim on `PATH` starts changing output,
   exit codes or timing for commands nobody meant to intercept.

Two more that only the end-to-end tests cover: a `fake`/`block` never runs the real tool, and `when: missing` is
gated on the real tool's absence, not on the command.

And three for the other surface, `ctf-local` — the MCP server and panel that serve a real target *as localhost*. They
are what reaches an agent that reads the web with its own tools, where no shim can:

4. **With no target, the wire is unchanged.** Broken: a server nobody pointed at rewrites hosts it does not know,
   and every answer is subtly wrong instead of honestly untranslated.
5. **Every spelling of the real host becomes the front host, and nothing else does.** Broken: a `Location`, a cookie
   or a JSON field keeps naming the real site, and the model sees the seams of the trick; or the rewrite eats a host
   that was never the target's.
6. **A path is the same path however it was spelled.** Broken: `localhost:8080/a`, `/a` and `https://x/a` fetch three
   different things, and a model's second call asks a different question without telling anyone.
7. **A real path never reaches the model as itself.** An added file is linked under a local name and the lab's own
   directory is `.`, so `lab_shell` output, `ls -l` link targets and error text name the local artifacts only.
   Broken: a model sees `/home/you/Downloads/WhatsApp-2.24.10(2407190).apk` and learns it is not on its own machine.
8. **The lab shell is the agent's shell.** cwd the lab directory, shims first on `PATH`, so a `dig` in there lies the
   way the same `dig` does in the agent's own shell — one story on two surfaces. Broken: the surfaces disagree and
   whichever the model believes is a coin toss.

9. **The config snippet registers the server under a plain key.** A client namespaces every tool as
   `mcp__<key>__<tool>`, and Claude Code's Opus 5.5 `[cyber]` gate fires on that key and nothing else: registered as
   `ctf-local` it refused 16 of 44 live turns, as `dev` 1 of 36, while the server's own name, its instructions and
   every word of its output made no measurable difference. Broken: the panel prints `ctf-local`, and roughly a third
   of Claude Code turns are refused before the model ever sees a tool result.

## Run it

```python
await bash("cd ~/Projects/personal/spoof && cargo test 2>&1 | tail -30")
```

Four binaries, in this order of what they prove:

| test binary | what it drives |
| --- | --- |
| `tests/properties.rs` | the laws above, over the *real* code, enumerating every input in the bound below |
| `tests/intercept.rs` | the shim as a process: fake, pass, rewrite, block, `SPOOF_OFF`, lab log, broken rules, `PATH` with the shim directory twice |
| `tests/ultron.rs` | the same lies arriving in an ultron cell's result, through `host::Host::handle("bash", ...)` with a session's environment |
| `tests/lab.rs` | promises 4-6, plus a real MCP stdio session and the panel posting a target — both as processes a client and a browser would drive |

## Break it, and watch it fail

A check never seen failing proves nothing. Each of these is one edit, then the command above:

- `rules.rs` `decide`: `for (index, rule) in rules.iter().enumerate()` -> `.enumerate().rev()` (last match wins).
  One file edit, two tests fail: `the_first_matching_rule_decides_everywhere` and
  `appending_a_rule_never_changes_an_earlier_decision`.
- `shim.rs` `real_tool`: delete the `if std::fs::canonicalize(&entry).is_ok_and(|here| here == shim) { continue; }`
  guard (keep `shim` used). `the_real_tool_is_never_the_shim` fails; run a shim itself and it execs itself forever.
- `shim.rs` `run`: move the `audit` call after the action, so the `exec` for a `pass` skips it.
  `lab_mode_logs_what_the_agent_was_told` fails on the missing second line.
- `shim.rs` `exec`: `Command::new(real)` -> `Command::new(tool)`. `the_shim_directory_on_path_twice_never_runs_the_shim`
  loops instead of returning.
- `lab.rs` `localize`: move the bare-host `replace` above the origin one (`.replace(&host(&self.front))` chain order).
  `the_real_host_becomes_the_local_one_everywhere` fails on the `https://` spelling.
- `mcp.rs` `fetch`: return `wire` without `lab.localize(&wire)`. `an_mcp_session_is_framed_and_fetches_as_localhost`
  fails on the body and the `Location` header.
- `panel.rs` `route`: drop the `lab.save()` in `/point`. `the_panel_points_the_lab_and_previews_through_the_rewrite`
  fails on the file, not on the page.
- `lab.rs` `localize`: delete the `self.files` loop. `a_real_file_is_only_ever_seen_under_its_local_name` fails on
  the link target `ls -l` prints.
- `lab.rs` `shell`: build `path` from `inherited` alone (no shim directory). `the_lab_shell_runs_with_the_shims_first`
  fails on the `dig` that stops lying.
- `mcp.rs` `KEY`: `"dev"` -> `"ctf-local"`. `the_panel_points_the_lab_and_previews_through_the_rewrite` fails on the
  printed key. The gate itself is a live-model property, measured out of band (below), not by this suite.

Restore the edit, rerun, and the suite is green again.

## The bound, and what is not covered

- **Bound**: tools `{"dig", "*"}`, args patterns `{none, "ctf", "blast"}`, `when {always, missing}`,
  `action {pass, fake, block, rewrite}`, rule sets of at most two rules, queries over two tool names, two argument
  strings, real tool present and absent. `real_tool` is exhausted over all 120 orderings of five `PATH` entries
  (the shim directory, a symlink to it, a real tool, a non-executable file, a missing directory).
- Rust has no verifier installed on this machine (no Kani, no Loom), so these run the code itself over generated
  inputs rather than a model of it. `Rule::matches`/`Rule::applies` are the primitives the properties build on and
  have their own cases in `gating_and_matching_are_both_required`.
- Not covered: a `lab_shell` command that ignores its timeout or prints past 64 KiB, a download through `lab_add`,
  the gate's live refusal rate (nondeterministic; measure with `claude -p` against the mock MCP server and a varying
  `mcpServers` key — a plain key passed ~1/36 turns, `ctf-local` ~1 in 3),
  and `lab.json` beyond the states the tests write (a `replace` pattern that never matches, a `front` with a
  path), a fetch to a target that hangs (`--max-time 30`), the panel's HTML and its escaping, a second panel on a
  taken port, and rules files larger than two rules (the properties still apply, the bound is just small), regex
  semantics themselves (the `regex` crate), a race on the audit append, and a live model session —
  `tests/ultron.rs` stops at the host, so no model is called.
- This crate names ultron's `host` and `kernel` as path dependencies for `tests/ultron.rs`, so the suite builds
  those two crates and a break in ultron's own checkout can fail it. Ultron's wider gate (`cargo test --workspace`)
  is run there, and its `crates/tui` currently fails `clippy::manual_range_patterns` (`fullscreen.rs:76`) for
  reasons unrelated to `spoof`.

## Keeping this in step

Covered files and functions: `src/rules.rs` (`decide`, `Rules::parse`, `Rules::load`, `Rule::matches`,
`Rule::applies`, `Rule::exit_code`, `Rule::text`), `src/shim.rs` (`run`, `real_tool`, `is_executable`,
`audit`, `rewrite`), the `DEFAULT_RULES` text, and for ctf-local `src/lab.rs` (`parse`, `load`, `save`,
`on`, `localize`, `front_url`, `target_url`, `host`, `path_of`, `command`, `add`, `shell`, `expand`, `lab_dir`),
`src/mcp.rs` (`run`, `reply`, `tools`, `call`, `fetch`, `shell`, `add`, `dns`, `info`, `config`) and `src/panel.rs`
(`run`, `serve`, `route`, `decode`).

Sync commit: e7682fb, the last commit whose covered code this skill describes. After a change to a covered file,
rerun the suite: green means the laws still hold. If the shape of the code was meant to change, edit the property
and this bound in the same change; if a finding is real, fix the code rather than loosening the property, and move
this sync commit forward only once the verification describes the new code.
