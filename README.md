<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1b27,50:DEA584,100:1a1b27&height=200&section=header&text=HONEY-MIND&fontSize=50&fontColor=FFFFFF&fontAlignY=35&desc=minotaur%20--%20Low-Interaction%20TCP%20Honeypot%20in%20Rust&descSize=16&descColor=DEA584&descAlignY=55&animation=fadeIn" width="100%"/>

<div align="center">

[![Rust](https://img.shields.io/badge/rust-stable_(1.75+)-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-29_passing-brightgreen?style=flat-square)]()
[![Prometheus](https://img.shields.io/badge/metrics-prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white)]()
[![Tokio](https://img.shields.io/badge/async-tokio-blue?style=flat-square)]()

**🇷🇺 [Русский](#-описание) · 🇬🇧 [English](#-overview)**

</div>

---

## 🇬🇧 Overview

`minotaur` is a low-interaction TCP honeypot written in Rust. It listens on configured ports, emulates just enough protocol surface to make scanners commit (banners, credentials, request paths), and writes structured JSONL session logs + Prometheus metrics.

### Protocol Support

| Protocol | Emulation | What it captures |
|:---|:---|:---|
| **SSH** | `SSH-2.0-…` server ident string | Client banner (libssh, paramiko, Go x/crypto…) + raw bytes |
| **HTTP** | `HTTP/1.x` response (404, configurable) | Request line, Host, User-Agent, full headers |
| **Telnet** | Login/Password prompt (3 attempts) | Usernames, passwords, IAC bytes stripped |
| **Raw** | Optional banner, then read until close | Any TCP traffic on catch-all ports |

### Key Features

- **Structured JSONL logs** — timestamp, UUID, protocol, src/dst, duration, hex + ASCII preview, parsed events
- **Prometheus `/metrics`** — connections, bytes, active sessions, duration histograms (per-protocol)
- **Per-IP rate limiting** — sliding 60s window, configurable per-minute limit
- **Global session cap** — `Semaphore`-based concurrent session limit
- **Graceful shutdown** — `SIGINT`/`SIGTERM` via `CancellationToken`
- **Zero external dependencies at runtime** — single static binary

### Quick Start

```bash
# Build
cargo build --release

# Configure
cp config.example.toml minotaur.toml
# Edit minotaur.toml to set ports, protocols, banners

# Validate config
./target/release/minotaur --config minotaur.toml validate-config

# Run
./target/release/minotaur --config minotaur.toml run

# For ports < 1024 (don't run as root!)
sudo setcap 'cap_net_bind_service=+ep' target/release/minotaur
```

### Configuration Example

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

### Architecture

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
                │   │ hyper-util│                            │
                │   └──────────┘                            │
                └──────────────────────────────────────────┘
```

### Session Record Example

```json
{
  "ts": "2026-05-11T18:53:36.212Z",
  "session_id": "eb1ba5f6-13f0-44d2-9cf8-e2c2773600b8",
  "protocol": "http",
  "src": "203.0.113.4:54836",
  "dst_port": 8080,
  "duration_ms": 12,
  "bytes_received": 91,
  "events": [{
    "type": "http_request",
    "method": "GET",
    "path": "/wp-admin",
    "host": "target.example",
    "user_agent": "Mozilla/5.0 (compatible; Scanner)"
  }],
  "close_reason": "server_closed"
}
```

### Testing

```bash
# Unit + integration tests (~29 tests)
cargo test

# End-to-end smoke test
cd examples/e2e && cargo run
```

Tests cover config parsing, JSONL serialization, rate limiter, Prometheus exporter, each protocol handler, and end-to-end TCP integration.

### What It Does NOT Do

> Stated up front so nobody calls this something it isn't.

- **No high-interaction** — no real SSH transport, no shell, no real HTTP app
- **No eBPF/XDP** — plain `tokio::net::TcpListener` userspace sockets
- **No anti-fingerprinting** — realistic defaults but no jitter/TLS shaping
- **No attack-response** — logs only, no blocking or retaliation
- **No log shipping** — use `fluentbit`, `vector`, or your own sidecar

### Tech Stack

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Tokio](https://img.shields.io/badge/tokio-async-blue?style=for-the-badge)
![Prometheus](https://img.shields.io/badge/prometheus-E6522C?style=for-the-badge&logo=prometheus&logoColor=white)

---

## 🇷🇺 Описание

`minotaur` — это low-interaction TCP-ханипот на Rust. Слушает настроенные порты, эмулирует минимум протокола для того, чтобы сканеры «засветились» (баннеры, логины, HTTP-запросы), и записывает структурированные JSONL-логи + Prometheus-метрики.

### Поддержка Протоколов

| Протокол | Эмуляция | Что захватывает |
|:---|:---|:---|
| **SSH** | `SSH-2.0-…` идентификация сервера | Баннер клиента + сырые байты |
| **HTTP** | HTTP/1.x ответ (404, настраиваемый) | URL, Host, User-Agent, заголовки |
| **Telnet** | Login/Password (3 попытки) | Логины, пароли, IAC-очистка |
| **Raw** | Опциональный баннер + чтение до закрытия | Любой TCP трафик |

### Ключевые Возможности

- **JSONL логи** — timestamp, UUID, протокол, src/dst, длительность, hex + ASCII
- **Prometheus `/metrics`** — подключения, байты, активные сессии, гистограммы
- **Rate-limiting** — скользящее окно 60с на IP
- **Graceful shutdown** — `SIGINT`/`SIGTERM` через `CancellationToken`
- **Один статический бинарник** — без зависимостей в runtime

### Быстрый старт

```bash
# Сборка
cargo build --release

# Настройка
cp config.example.toml minotaur.toml

# Проверка конфигурации
./target/release/minotaur --config minotaur.toml validate-config

# Запуск
./target/release/minotaur --config minotaur.toml run

# Тесты (~29 тестов)
cargo test
```

---

<div align="center">

### License

MIT — see [LICENSE](LICENSE) for details.

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1b27,50:DEA584,100:1a1b27&height=80&section=footer" width="100%"/>

</div>
