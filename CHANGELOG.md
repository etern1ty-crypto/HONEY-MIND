# Changelog

## 0.2.0 — source revision, 2026-09-08

**Not a verified production release.** See [verification](docs/VERIFICATION.md).

### Added

- Sensor identity/environment/tags and versioned JSONL schema v2.
- Metadata-only default, explicit full forensic mode and HTTP path minimisation.
- Absolute session lifetime, total input cap, bounded IP state and management connections.
- Rotating private log files, OS writer lock, exported loss metrics and fail-closed writer supervision.
- Pre-bound listeners, nested JoinSets, readiness, CLI print-config and healthcheck.
- Linux/systemd, container and Prometheus examples; regression and CLI/binary smoke tests.
- Product, architecture, configuration, API, audit and deployment documentation.

### Fixed

- Missing stdout output, partial-startup task leaks and swallowed fatal errors.
- Unbounded/unchecked network writes and misreported session completion.
- HTTP header caps, request framing validation, HEAD/no-body/status semantics.
- Telnet stream framing/IAC/subnegotiation, oversize input, whitespace and password EOF.
- Unvalidated SSH identification, preview truncation boundary and misleading documentation.

### Changed

- Relative log paths resolve against the TOML directory.
- More invalid configurations are rejected rather than coerced silently.
- Prometheus protobuf feature disabled; supplied third-party versions otherwise preserved.
- Conservative Rust baseline set to 1.93, pinned toolchain 1.93.1.

## 0.1.0 — supplied archive

Initial low-interaction SSH/HTTP/Telnet/raw TCP capture with JSONL and Prometheus.
No claim is made about the original release date or successful upstream CI runs.
