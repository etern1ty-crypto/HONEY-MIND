# Contributing

## Development

Use the pinned Rust toolchain, a linker and Python 3.11+.

```bash
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
python3 examples/e2e/drive.py --binary target/release/minotaur
python3 scripts/check_repository.py
```

Before a release, also run the security and deployment gates in
[TESTING](docs/TESTING.md). The initial review bundle has not run Cargo in its preparation environment.

## Change requirements

- Keep the low-interaction/no-command-execution boundary.
- Route network I/O through SessionIo; preserve input, deadline and task bounds.
- Add a regression that fails without your fix. No assertions based on packet atomicity or arbitrary startup sleeps.
- Use pre-bound port-zero listeners and deadlines; never probe Internet addresses from tests.
- Update schema_version/migration notes for incompatible event changes.
- Never add attacker-controlled metric labels, real credentials, private logs or fake passing badges.
- Keep config examples, API reference and defaults consistent.
- Preserve MIT attribution and review dependency/license changes.

Small targeted PRs are preferred. Include the reproduced defect, scope, actual commands
run and any checks that were blocked. A written test is not evidence that it passed.
