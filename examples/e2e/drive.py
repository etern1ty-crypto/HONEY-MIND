#!/usr/bin/env python3
"""End-to-end smoke driver for the minotaur honeypot.

Spins up a TCP client against each protocol endpoint on the default
example configuration (loopback only) and prints per-session
transcripts.  After the run, inspect:

    cat honeypot.jsonl | jq .
    curl http://127.0.0.1:9090/metrics

Run minotaur first in a separate terminal:

    ./target/release/minotaur --config examples/e2e/minotaur.toml run

then in another terminal:

    python3 examples/e2e/drive.py

No external dependencies beyond the Python standard library and
``curl`` (for the HTTP probe).
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"


def recv_until(sock: socket.socket, marker: bytes, max_wait: float = 3.0) -> bytes:
    sock.settimeout(max_wait)
    buf = b""
    deadline = time.monotonic() + max_wait
    while marker not in buf and time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def recv_for(sock: socket.socket, duration: float) -> bytes:
    sock.settimeout(duration)
    buf = b""
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def banner(name: str) -> None:
    print(f"\n=== {name} ===", flush=True)


def drive_ssh() -> None:
    banner("SSH @ 127.0.0.1:2222")
    s = socket.create_connection((HOST, 2222), timeout=3)
    server_banner = recv_until(s, b"\n", 2.0)
    print(f"server banner:  {server_banner!r}")
    s.sendall(b"SSH-2.0-paramiko-test\r\n")
    s.sendall(bytes([0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]))
    time.sleep(0.5)
    s.close()
    print("client banner sent + 8 random bytes; closed")


def drive_http() -> None:
    banner("HTTP @ 127.0.0.1:8080")
    out = subprocess.run(
        [
            "curl", "-sS", "-D-",
            "-o", "/dev/null",
            "-A", "honeymind-test/1.0",
            "-H", "Host: trap.local",
            "http://127.0.0.1:8080/admin?probe=1",
        ],
        capture_output=True, text=True, timeout=5,
    )
    print(out.stdout.strip())
    if out.stderr:
        print(f"curl stderr: {out.stderr.strip()}")


def drive_telnet() -> None:
    banner("TELNET @ 127.0.0.1:2323")
    s = socket.create_connection((HOST, 2323), timeout=3)
    head = recv_until(s, b"login: ", 2.0)
    print(f"banner+prompt:  {head!r}")
    # Attempt 1: username prefixed with IAC WILL TERMINAL_TYPE to verify stripping.
    s.sendall(b"\xff\xfb\x18root\r\n")
    print("sent username:  b'\\xff\\xfb\\x18root\\r\\n' (IAC-prefixed)")
    pw_prompt = recv_until(s, b"Password: ", 2.0)
    print(f"password prompt: {pw_prompt!r}")
    s.sendall(b"12345\r\n")
    incorrect = recv_until(s, b"Login incorrect\r\n", 2.0)
    print(f"server reply:   {incorrect!r}")
    recv_until(s, b"login: ", 2.0)
    # Attempt 2: username + password in ONE TCP segment (single sendall).
    s.sendall(b"admin\r\nhunter2\r\n")
    print("sent username+password in a single TCP segment")
    print(f"server tail:    {recv_for(s, 0.8)!r}")
    s.close()


def drive_raw() -> None:
    banner("RAW @ 127.0.0.1:6379")
    s = socket.create_connection((HOST, 6379), timeout=3)
    srv_banner = recv_until(s, b"\n", 2.0)
    print(f"server banner:  {srv_banner!r}")
    s.sendall(b"PING\r\nINFO\r\n")
    print("sent 12 bytes: PING\\r\\nINFO\\r\\n")
    time.sleep(0.2)
    s.close()


def main() -> int:
    print("Driving minotaur on 127.0.0.1 (2222 / 8080 / 2323 / 6379).")
    print("If a connection fails, ensure minotaur is running with examples/e2e/minotaur.toml.")
    try:
        drive_ssh()
        drive_http()
        drive_telnet()
        drive_raw()
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"\nERROR: could not reach minotaur: {e}", file=sys.stderr)
        return 1
    print("\nDone. Now inspect honeypot.jsonl (4 records) and /metrics.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
