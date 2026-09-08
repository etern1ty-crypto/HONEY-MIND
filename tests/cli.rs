//! CLI contracts that do not rely on fixed listening ports.

#![allow(clippy::field_reassign_with_default)]

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_minotaur"))
}

#[test]
fn print_config_does_not_require_a_config_file() {
    let output = binary()
        .args(["--config", "/nonexistent/honeymind.toml", "print-config"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let config = minotaur::config::Config::from_toml(&text).unwrap();
    assert!(config
        .endpoints
        .iter()
        .all(|endpoint| endpoint.bind.ip().is_loopback()));
}

#[test]
fn validate_config_json_is_machine_readable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[[endpoint]]\nbind='127.0.0.1:0'\nprotocol='raw'\n").unwrap();
    let output = binary()
        .arg("-c")
        .arg(&path)
        .args(["validate-config", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert!(!directory.path().join("honeypot.jsonl").exists());
}

#[test]
fn startup_bind_error_is_nonzero_and_cannot_hang_on_logger() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let contents = format!(
        "[logging]\noutput='-'\n[metrics]\nenabled=true\nbind='{}'\n[[endpoint]]\nbind='127.0.0.1:0'\nprotocol='raw'\n",
        occupied.local_addr().unwrap()
    );
    std::fs::write(&path, contents).unwrap();
    let mut child = binary()
        .arg("-c")
        .arg(path)
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("startup failure hung instead of exiting");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
}

#[test]
fn invalid_config_is_nonzero() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[server]\nmax_concurrent_sessions=0\n").unwrap();
    let output = binary()
        .arg("-c")
        .arg(path)
        .arg("validate-config")
        .output()
        .unwrap();
    assert!(!output.status.success());
}
