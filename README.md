# HONEY-MIND

[![CI](https://github.com/etern1ty-crypto/HONEY-MIND/actions/workflows/ci.yml/badge.svg)](https://github.com/etern1ty-crypto/HONEY-MIND/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`minotaur` — a low-interaction TCP honeypot in Rust. It listens on configured
ports, emulates just enough protocol to make scanners commit (send banners,
credentials, request paths), and writes structured JSONL session logs plus
Prometheus metrics.

This repository previously contained an aspirational eBPF / XDP / AF_XDP /
adversarial-ML / LLM-honeypot scaffold. None of that was implemented. The
project was reset to a focused, honest scope: a working **userspace**
low-interaction honeypot. The eBPF / ML / LLM scope is not on the roadmap
here — there are better single-purpose projects for each of those.

## What it does

- Listens on one or more TCP endpoints described in a TOML config.
- Speaks four protocol shapes:
  - **`ssh`** — sends an `SSH-2.0-…` server identification string, captures
    the client's identification banner (libssh, paramiko, Go x/crypto, …),
    keeps reading raw bytes until the client closes or the session times out.
  - **`http`** — reads HTTP/1.x headers until `\r\n\r\n`, parses the request
    line and `Host` / `User-Agent`, returns a canned response (default 404,
    configurable status + `Server:` header).
  - **`telnet`** — banner, `login:` prompt, captures username; `Password:`
    prompt, captures password; `Login incorrect`; up to 3 attempts. Telnet
    `IAC` negotiation bytes are stripped from captured input.
  - **`raw`** — optional banner, then read bytes until close/timeout. Useful
    for catch-all ports.
- Writes one JSONL record per session to a configured file (and optionally
  also to stdout). Records contain:
  - timestamp, session UUID, protocol, `src` host:port, `dst_port`,
    duration, total bytes received, truncation flag, hex + ASCII preview
    of the first N bytes, parsed `events[]`, and a `close_reason`.
- Exposes a Prometheus `/metrics` endpoint with:
  - `minotaur_connections_total{protocol}`
  - `minotaur_rejected_total{protocol,reason}` (rate-limited, max-sessions)
  - `minotaur_active_sessions`
  - `minotaur_bytes_received_total{protocol}`
  - `minotaur_session_duration_seconds{protocol}` (histogram)
- Per-source-IP rate limit (sliding 60-second window), global concurrent
  session cap, per-session inactivity timeout, graceful shutdown on
  `SIGINT` / `SIGTERM`.

## What it does *not* do

Stated up front so nobody calls this something it isn't:

- It is **low-interaction**: no real SSH transport (no KEX, no shell), no
  real HTTP application, no real protocol fidelity beyond the banner /
  request-line surface. Sophisticated scanners that complete a handshake
  will detect this trivially.
- No eBPF, XDP, or AF_XDP. Plain `tokio::net::TcpListener` userspace
  sockets.
- No anti-fingerprinting. The default banners are realistic strings, but
  there's no jitter, no TCP/IP stack tuning, no TLS fingerprint shaping.
- No automated attack-response. The honeypot logs; it does not block,
  retaliate, or notify anything beyond the log file and metrics.
- No clustering, no log shipping. Use `tail -f`, `fluentbit`, `vector`,
  or your own sidecar to ship JSONL to a SIEM / object store.
- No GeoIP / ASN enrichment. Add it as a post-processing step on the
  JSONL stream if you need it; in-process MaxMind lookups bloat the
  binary and most operators want to control that data path themselves.

## Build

```
cargo build --release
```

Requires a recent stable Rust toolchain (MSRV 1.75; tested on 1.95).

## Configuration

Copy `config.example.toml` to `minotaur.toml` and edit. Each `[[endpoint]]`
binds a port to one of the four supported protocols:

```toml
[logging]
output = "honeypot.jsonl"
stdout = false
buffer_size = 1024

[metrics]
enabled = true
bind = "127.0.0.1:9090"

[server]
max_concurrent_sessions = 1024
session_timeout_seconds = 60
rate_limit_per_ip_per_min = 120
max_bytes_per_session = 8192

[[endpoint]]
bind = "0.0.0.0:2222"
protocol = "ssh"
banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"

[[endpoint]]
bind = "0.0.0.0:8080"
protocol = "http"
server_header = "nginx/1.18.0"
http_status = 404

[[endpoint]]
bind = "0.0.0.0:2323"
protocol = "telnet"
banner = "Welcome to Ubuntu 22.04 LTS"

[[endpoint]]
bind = "0.0.0.0:6379"
protocol = "raw"
banner = "-NOAUTH Authentication required.\r\n"
```

Validate before running:

```
./target/release/minotaur --config minotaur.toml validate-config
```

## Run

```
./target/release/minotaur --config minotaur.toml run
```

Binding ports < 1024 needs root or `CAP_NET_BIND_SERVICE`:

```
sudo setcap 'cap_net_bind_service=+ep' target/release/minotaur
```

Don't run this as root.

## Example session record

```json
{
  "ts": "2026-05-11T18:53:36.212461848Z",
  "session_id": "eb1ba5f6-13f0-44d2-9cf8-e2c2773600b8",
  "protocol": "http",
  "src": "203.0.113.4:54836",
  "dst_port": 8080,
  "duration_ms": 12,
  "bytes_received": 91,
  "bytes_truncated": false,
  "data_preview_hex": "474554202f77702d61646d696e20485454502f312e310d0a48...",
  "data_preview_ascii": "GET /wp-admin HTTP/1.1..Host: target.example..User-Agent: ...",
  "events": [{
    "type": "http_request",
    "method": "GET",
    "path": "/wp-admin",
    "version": "HTTP/1.1",
    "host": "target.example",
    "user_agent": "Mozilla/5.0 (compatible; Scanner)"
  }],
  "close_reason": "server_closed"
}
```

## Architecture

```
                ┌──────────────────────────────────────────┐
                │              minotaur (1 process)        │
                │                                          │
  TCP ──┐       │   ┌──────────┐                           │
        │       │   │ Endpoint │──┐                        │
  TCP ──┼─accept├──▶│ listeners│  │   ┌──────────────┐     │
        │       │   │  (per    │  └──▶│ protocol     │     │
  TCP ──┘       │   │  port)   │      │ handler task │     │
                │   └──────────┘      │ (1 per conn) │     │
                │       ▲             └──────┬───────┘     │
                │       │ check rate-limit   │ SessionState│
                │       │ acquire semaphore  │             │
                │   ┌───┴──────┐             ▼             │
                │   │ ratelimit│      ┌─────────────┐      │
                │   └──────────┘      │ Logger task │──▶ JSONL file
                │   ┌──────────┐      │ (bounded ch)│──▶ stdout
                │   │ metrics  │      └─────────────┘      │
                │   │ hyper /  │◀── /metrics scrape         │
                │   │  hyper-util                            │
                │   └──────────┘                            │
                └──────────────────────────────────────────┘
```

- One Tokio task per accepted connection.
- A single async logger task owns the JSONL writer; protocol handlers send
  records over a bounded `mpsc` channel. If the channel is full, records
  are dropped and counted, never blocking the accept loop.
- A global `Semaphore` enforces `max_concurrent_sessions` across all
  endpoints.
- Rate-limit state is sliding-window per source IP, evicted periodically.
- Shutdown uses `tokio-util` `CancellationToken`; all listener loops select
  on it and exit cleanly.

## Example `/metrics` output

After a handful of test connections:

```
# HELP minotaur_active_sessions Currently active honeypot sessions.
# TYPE minotaur_active_sessions gauge
minotaur_active_sessions 0
# HELP minotaur_connections_total Total accepted connections, labelled by protocol.
# TYPE minotaur_connections_total counter
minotaur_connections_total{protocol="http"} 1
minotaur_connections_total{protocol="raw"} 1
minotaur_connections_total{protocol="ssh"} 1
minotaur_connections_total{protocol="telnet"} 1
# HELP minotaur_bytes_received_total Total bytes received from clients, labelled by protocol.
# TYPE minotaur_bytes_received_total counter
minotaur_bytes_received_total{protocol="http"} 94
minotaur_bytes_received_total{protocol="raw"} 12
minotaur_bytes_received_total{protocol="ssh"} 31
minotaur_bytes_received_total{protocol="telnet"} 32
# HELP minotaur_session_duration_seconds Distribution of session durations in seconds, labelled by protocol.
# TYPE minotaur_session_duration_seconds histogram
minotaur_session_duration_seconds_count{protocol="http"} 1
minotaur_session_duration_seconds_count{protocol="ssh"} 1
...
```

## Testing

Unit + integration suite:

```
cargo test
```

Includes ~29 tests covering config parsing/validation, JSONL serialization,
the rate limiter, the Prometheus exporter, each protocol's parser/handler,
and end-to-end integration tests that bind to `127.0.0.1:0`, drive the
real handlers over a real TCP socket, and assert on the resulting JSONL.

A standalone smoke driver lives in [`examples/e2e/`](examples/e2e/) — it
builds against the release binary, drives each of the four protocols over
real sockets, exercises the IAC-stripping and single-TCP-segment
`username + password` edge cases, and prints what the server sent back.
Use it after a build to confirm the binary, JSONL writer, and `/metrics`
exporter are wired together.

## License

MIT.
