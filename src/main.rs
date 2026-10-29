//! The `spoof` binary: one copy serves the CLI and every shim it is linked as (see [`spoof::run`]).

fn main() {
    std::process::exit(spoof::run());
}
