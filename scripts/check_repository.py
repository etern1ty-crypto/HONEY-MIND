#!/usr/bin/env python3
"""Offline repository contracts; NOT a Rust compiler or a security audit.

Python 3.11+ standard library only. Emits JSON and a nonzero exit on failure.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Callable
from typing import Callable
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def files_with(suffix: str) -> list[Path]:
    return sorted(p for p in ROOT.rglob(f"*{suffix}") if not set(p.parts) & {"target", ".git", "__pycache__"})


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def lexical_delimiters(text: str) -> None:
    """Check closed literals/comments and balanced delimiters, not Rust grammar."""
    stack: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(text) and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            assert depth == 0, "unclosed block comment"
            continue
        raw = re.match(r'(?:br|r)(#*)"', text[i:])
        if raw:
            ending = '"' + raw[1]
            start = i + len(raw[0])
            end = text.find(ending, start)
            assert end >= 0, "unclosed raw string"
            i = end + len(ending)
            continue
        if text[i] == '"':
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise AssertionError("unclosed string")
            continue
        if text[i] == "'":
            character = re.match(r"'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'", text[i:])
            if character:
                i += len(character[0])
                continue
            lifetime = re.match(r"'[A-Za-z_][A-Za-z_0-9]*", text[i:])
            assert lifetime, "unclosed character or invalid lifetime"
            i += len(lifetime[0])
            continue
        char = text[i]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            expected = {")": "(", "]": "[", "}": "{"}[char]
            assert stack and stack.pop() == expected, f"unbalanced delimiter {char}"
        i += 1
    assert not stack, "unclosed delimiters"


def validate_lock() -> dict[str, int]:
    manifest = tomllib.loads(read_text(ROOT / "Cargo.toml"))
    lock = tomllib.loads(read_text(ROOT / "Cargo.lock"))
    packages = lock["package"]
    root = next(p for p in packages if p["name"] == manifest["package"]["name"])
    assert root["version"] == manifest["package"]["version"]
    dependencies = set(manifest.get("dependencies", {})) | set(manifest.get("dev-dependencies", {}))
    for target in manifest.get("target", {}).values():
        dependencies.update(target.get("dependencies", {}))
    assert dependencies == {dep.split()[0] for dep in root["dependencies"]}, "manifest/root dependency mismatch"
    assert manifest["dependencies"]["prometheus"]["default-features"] is False
    assert not any(p["name"] == "protobuf" for p in packages), "unneeded protobuf still locked"
    index: dict[str, list[dict]] = {}
    for package in packages:
        index.setdefault(package["name"], []).append(package)
        if package.get("source", "").startswith("registry+"):
            assert re.fullmatch(r"[a-f0-9]{64}", package["checksum"])
    for package in packages:
        for dependency in package.get("dependencies", []):
            parts = dependency.split()
            candidates = index.get(parts[0], [])
            if len(parts) > 1:
                candidates = [p for p in candidates if p["version"] == parts[1]]
            assert len(candidates) == 1, f"unresolved or ambiguous edge {dependency}"
    return {"locked_packages": len(packages), "direct_dependency_names": len(dependencies)}


def main() -> int:
    checks: list[dict[str, object]] = []

    def check(name: str, action: Callable[[], object]) -> None:
        try:
            detail = action()
            checks.append({"name": name, "status": "passed", "detail": detail})
        except Exception as error:
            checks.append({"name": name, "status": "failed", "detail": str(error)})

    def required() -> int:
        names = [
            "README.md", "LICENSE", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
            "config.example.toml", "docs/ARCHITECTURE.md", "docs/CONFIGURATION.md",
            "docs/DEPLOYMENT.md", "docs/API.md", "docs/PRODUCT.md", "docs/AUDIT.md",
            "docs/TESTING.md", "docs/VERIFICATION.md", "docs/DEPENDENCIES.md",
            "docs/session.schema.json", "examples/session.metadata.json",
            "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "Dockerfile", "compose.yaml",
            ".github/workflows/ci.yml", "deploy/minotaur.service", "deploy/alerts.yml",
            "deploy/alerts.test.yml", "scripts/check.sh", "tests/cli.rs",
        ]
        for name in names:
            assert (ROOT / name).is_file(), f"missing {name}"
            assert (ROOT / name).stat().st_size > 0, f"empty {name}"
        return len(names)

    def toml_configs() -> int:
        files = files_with(".toml")
        for path in files:
            config = tomllib.loads(read_text(path))
            if path.name in {"Cargo.toml", "rust-toolchain.toml"}:
                continue
            assert 1 <= len(config["endpoint"]) <= 32
            assert config.get("privacy", {}).get("mode", "metadata") == "metadata", f"unsafe example {path}"
            assert config.get("metrics", {}).get("enabled") is True
            for endpoint in config["endpoint"]:
                assert endpoint["protocol"] in {"ssh", "http", "telnet", "raw"}
        local = tomllib.loads(read_text(ROOT / "config.example.toml"))
        assert all(ep["bind"].startswith("127.0.0.1:") for ep in local["endpoint"])
        return len(files)

    def python_files() -> int:
        files = files_with(".py")
        for path in files:
            ast.parse(read_text(path), filename=str(path))
        return len(files)

    def rust_lexical() -> int:
        files = files_with(".rs")
        for path in files:
            try:
                lexical_delimiters(read_text(path))
            except AssertionError as error:
                raise AssertionError(f"{path.relative_to(ROOT)}: {error}") from error
        return len(files)

    def rust_contracts() -> int:
        for path in files_with(".rs"):
            text = read_text(path)
            assert not re.search(r"\b(?:TODO|FIXME)\b|\b(?:todo|unimplemented)!", text), f"unfinished code: {path}"
            for target in re.findall(r'include_str!\("([^\"]+)"\)', text):
                assert (path.parent / target).is_file(), f"broken include_str {target} in {path}"
        assert "pub struct ActiveGuard" in read_text(ROOT / "src/metrics.rs")
        assert "struct FileSink" in read_text(ROOT / "src/logger.rs")
        assert "max_session_duration_seconds" in read_text(ROOT / "src/server.rs")
        return len(files_with(".rs"))

    def links() -> int:
        total = 0
        for path in files_with(".md"):
            for target in re.findall(r"\[[^\]]+\]\(([^\s)]+)\)", read_text(path)):
                parsed = urlsplit(target)
                if parsed.scheme or not parsed.path:
                    continue
                destination = (path.parent / unquote(parsed.path)).resolve()
                assert destination.is_relative_to(ROOT), f"link leaves repo: {target}"
                assert destination.exists(), f"broken link in {path.relative_to(ROOT)}: {target}"
                total += 1
        return total

    def example() -> dict[str, object]:
        schema = json.loads(read_text(ROOT / "docs/session.schema.json"))
        record = json.loads(read_text(ROOT / "examples/session.metadata.json"))
        assert set(schema["required"]) == set(record)
        assert record["schema_version"] == 2 and record["privacy_mode"] == "metadata"
        assert record["payload_captured"] is False
        assert record["data_preview_hex"] == record["data_preview_ascii"] == ""
        assert record["events"][0]["path"] == "/admin"
        assert len(record["events"]) <= 16
        assert record["dst_port"] > 0
        return {"schema_parsed": True, "example_shape_checked": True, "full_json_schema_validation": False}

    def licence() -> str:
        data = (ROOT / "LICENSE").read_bytes()
        assert b"Copyright (c) 2025 etern1ty-crypto" in data
        assert b"MIT License" in data
        return hashlib.sha256(data).hexdigest()

    check("required_files", required)
    check("toml_parse_and_safe_examples", toml_configs)
    check("manifest_and_locked_graph", validate_lock)
    check("python_ast", python_files)
    check("rust_lexical_delimiters_only", rust_lexical)
    check("rust_source_contracts_and_includes", rust_contracts)
    check("relative_markdown_links", links)
    check("json_schema_parse_and_example_shape", example)
    check("mit_attribution", licence)
    rust_tests = sum(len(re.findall(r"#\[(?:tokio::)?test(?:\(|\])", read_text(p))) for p in files_with(".rs"))
    report = {
        "status": "passed" if all(c["status"] == "passed" for c in checks) else "failed",
        "scope": "offline contracts only; no Rust build/runtime/security claim",
        "checks": checks,
        "declared_rust_tests_not_executed": rust_tests,
        "tools_available": {name: shutil.which(name) is not None for name in ["rustc", "cargo", "docker", "promtool", "python3"]},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
