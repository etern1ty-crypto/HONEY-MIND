#!/usr/bin/env python3
"""Bounded loopback smoke test. Uses only Python 3.11+ standard library.

Manual mode attaches to examples/e2e/minotaur.toml. --binary launches a fresh
sensor with ephemeral ports, reads its announced addresses, verifies JSONL
stdout (including output='-'), then checks graceful SIGTERM on POSIX.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class Peer:
    def __init__(self, port: int) -> None:
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.pending = bytearray()

    def __enter__(self) -> Peer:
        return self

    def __exit__(self, *_: object) -> None:
        self.socket.close()

    def send(self, payload: bytes) -> None:
        self.socket.sendall(payload)

    def until(self, marker: bytes) -> bytes:
        deadline = time.monotonic() + 4
        while marker not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"deadline waiting for {marker!r}")
            self.socket.settimeout(remaining)
            chunk = self.socket.recv(4096)
            if not chunk:
                raise RuntimeError(f"EOF before {marker!r}")
            self.pending.extend(chunk)
            if len(self.pending) > 32768:
                raise RuntimeError("response exceeds smoke-test budget")
        end = self.pending.index(marker) + len(marker)
        result = bytes(self.pending[:end])
        del self.pending[:end]
        return result

    def eof(self) -> bytes:
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("deadline waiting for EOF")
            self.socket.settimeout(remaining)
            chunk = self.socket.recv(4096)
            if not chunk:
                return bytes(self.pending)
            self.pending.extend(chunk)
            if len(self.pending) > 262144:
                raise RuntimeError("response exceeds smoke-test budget")


def probe(ports: dict[str, int]) -> None:
    with Peer(ports["ssh"]) as peer:
        assert peer.until(b"\r\n").startswith(b"SSH-2.0-")
        peer.send(b"SSH-2.0-HoneyMindSmoke\r\n")
        peer.socket.shutdown(socket.SHUT_WR)
        peer.eof()
    with Peer(ports["http"]) as peer:
        peer.send(b"HEAD /admin?token=smoke-secret HTTP/1.1\r\nHost: smoke.local\r\n\r\n")
        response = peer.eof()
        assert response.startswith(b"HTTP/1.1 404 "), response
        assert response.endswith(b"\r\n\r\n"), "HEAD incorrectly returned a body"
    with Peer(ports["telnet"]) as peer:
        peer.until(b"login: ")
        peer.send(b"\xff\xfa\x18term\nvalue\xff\xf0root\r\nsmoke-secret\r\nadmin\r\nsmoke-secret\r\nuser\r\nsmoke-secret\r\n")
        assert b"Too many attempts" in peer.eof()
    with Peer(ports["raw"]) as peer:
        peer.send(b"PING\r\nINFO\r\n")
        peer.socket.shutdown(socket.SHUT_WR)
        peer.eof()
    with Peer(ports["metrics"]) as peer:
        peer.send(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = peer.eof()
        assert b"minotaur_connections_total" in response
        assert b"sensor_id=" in response


def pump(stream: object, destination: queue.Queue[str]) -> None:
    try:
        for line in stream:
            destination.put(line)
    finally:
        stream.close()


def launched(binary: Path) -> None:
    if os.name != "posix":
        raise RuntimeError("launched SIGTERM smoke requires POSIX; use cargo tests on other platforms")
    with tempfile.TemporaryDirectory(prefix="honeymind-smoke-") as directory:
        config = Path(directory) / "minotaur.toml"
        config.write_text(
            "[sensor]\nid='smoke'\nenvironment='test'\n"
            "[logging]\noutput='-'\nstdout=false\n"
            "[metrics]\nenabled=true\nbind='127.0.0.1:0'\n"
            "[server]\nrate_limit_per_ip_per_min=0\nsession_timeout_seconds=3\nmax_session_duration_seconds=10\n"
            + "".join(f"[[endpoint]]\nbind='127.0.0.1:0'\nprotocol='{protocol}'\n" for protocol in ("ssh", "http", "telnet", "raw")),
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["RUST_LOG"] = "minotaur=info"
        child = subprocess.Popen(
            [str(binary.resolve()), "-c", str(config), "run"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
            env=environment, bufsize=1,
        )
        assert child.stdout is not None and child.stderr is not None
        stdout: queue.Queue[str] = queue.Queue()
        stderr: queue.Queue[str] = queue.Queue()
        threads = [
            threading.Thread(target=pump, args=(child.stdout, stdout), daemon=True),
            threading.Thread(target=pump, args=(child.stderr, stderr), daemon=True),
        ]
        for thread in threads:
            thread.start()
        diagnostics: list[str] = []
        try:
            ports: dict[str, int] = {}
            deadline = time.monotonic() + 10
            while len(ports) < 5:
                if child.poll() is not None:
                    raise RuntimeError("sensor exited during startup: " + "".join(diagnostics))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sensor did not announce all listeners")
                try:
                    line = stderr.get(timeout=min(remaining, 0.2))
                except queue.Empty:
                    continue
                diagnostics.append(line)
                address = re.search(r"bind=127\.0\.0\.1:(\d+)", line)
                if not address:
                    continue
                if "management listening" in line:
                    ports["metrics"] = int(address[1])
                elif "endpoint listening" in line:
                    protocol = re.search(r"protocol=\"?(ssh|http|telnet|raw)\"?", line)
                    if protocol:
                        ports[protocol[1]] = int(address[1])
            probe(ports)
            records: list[dict] = []
            deadline = time.monotonic() + 6
            while len(records) < 4:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("stdout JSONL records were lost")
                records.append(json.loads(stdout.get(timeout=remaining)))
            assert {record["protocol"] for record in records} == {"ssh", "http", "telnet", "raw"}
            for record in records:
                assert record["schema_version"] == 2
                assert record["sensor"]["id"] == "smoke"
                assert record["data_preview_hex"] == ""
                assert "smoke-secret" not in json.dumps(record)
                assert record["dst_port"] == ports[record["protocol"]]
            raw = next(record for record in records if record["protocol"] == "raw")
            assert raw["bytes_received"] == 12
            telnet = next(record for record in records if record["protocol"] == "telnet")
            assert len(telnet["events"]) == 3
            # Keep one admitted session alive; SIGTERM must log its shutdown.
            with Peer(ports["ssh"]) as peer:
                peer.until(b"\r\n")
                child.send_signal(signal.SIGTERM)
                assert child.wait(timeout=15) == 0, "graceful shutdown failed"
            for thread in threads:
                thread.join(timeout=2)
            tail = []
            while not stdout.empty():
                tail.append(json.loads(stdout.get_nowait()))
            assert len(tail) == 1 and tail[0]["close_reason"] == "shutdown", tail
            print("PASS: all protocols, metrics, stdout privacy and SIGTERM drain")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="launch this binary with an isolated temporary config")
    args = parser.parse_args()
    try:
        if args.binary:
            launched(args.binary)
        else:
            probe({"ssh": 2222, "http": 8080, "telnet": 2323, "raw": 6379, "metrics": 9090})
            print("PASS: protocol/metrics probes; inspect examples/e2e/honeypot.jsonl for records")
        return 0
    except (OSError, RuntimeError, AssertionError, TimeoutError, ValueError, queue.Empty, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
