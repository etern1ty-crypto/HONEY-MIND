# E2E smoke test

`drive.py` exercises every protocol the honeypot speaks against a running
`minotaur` instance. Use it after a `cargo build --release` to confirm the
binary is wired correctly end-to-end (sockets, JSONL logging, Prometheus
exporter, graceful shutdown).

## Run

In one terminal:

```bash
cargo build --release
./target/release/minotaur --config examples/e2e/minotaur.toml run
```

In another:

```bash
python3 examples/e2e/drive.py
```

Then inspect what the honeypot captured:

```bash
jq -c . honeypot.jsonl
curl -s http://127.0.0.1:9090/metrics | grep '^minotaur_'
```

You should see four JSONL records (one per protocol), with parsed events
(SSH client banner, HTTP request line, Telnet `username` / `password`
pairs) and matching Prometheus counters.

## What the driver tests

| Driver step | What it proves |
|---|---|
| Sends a custom client identification string after reading the server banner on `:2222` | SSH banner read/write round-trip and `ssh_client_banner` event emission |
| `curl -A honeymind-test/1.0 -H Host: trap.local http://127.0.0.1:8080/admin?probe=1` | HTTP request-line + header parsing, configurable 404 + `Server` header |
| Sends `\xff\xfb\x18root\r\n` (IAC WILL TERMINAL_TYPE + username) as a Telnet username | IAC stripping: raw bytes appear in `data_preview_hex` but parsed `username` is `"root"` |
| Sends `b"admin\r\nhunter2\r\n"` in a single `sendall()` (one TCP segment) | Persistent line buffer in the Telnet handler — both fields are captured even if they arrive together |
| Sends `PING\r\nINFO\r\n` to `:6379` | Raw protocol byte counter (`bytes_received == 12`) and ASCII preview |

If any of those is silently broken, the JSONL records will visibly
diverge — the parsed events / counters won't match what was sent.

## Notes

- Loopback only. Do not edit this config to bind `0.0.0.0`; it disables the
  rate limit and is intended for local smoke testing.
- Stop the honeypot with `Ctrl+C`. It exits within a few seconds and
  flushes the JSONL writer.
- The driver expects `python3` and `curl` only. No external Python
  dependencies.
