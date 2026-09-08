#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cargo >/dev/null 2>&1; then
  echo "BLOCKED: install Rust 1.93.1 with rustfmt/clippy; no build was run." >&2
  exit 2
fi
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
python3 scripts/check_repository.py
python3 examples/e2e/drive.py --binary target/release/minotaur
if ! cargo audit --version >/dev/null 2>&1; then
  echo "BLOCKED: install cargo-audit; release security gate was not run." >&2
  exit 2
fi
cargo audit --deny warnings
