//! Minimal HTTP/1.x request capture.
//!
//! Reads bytes up to the end of headers (`\r\n\r\n`) or a header-size cap,
//! parses the request line and a handful of useful headers, emits a fake
//! response (default 404), and closes. We don't implement chunked transfer or
//! pipelining — scanners don't need them.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::read_with_timeout;

/// Reasonable cap; real servers use 8–16 KiB.
const MAX_HEADERS_BYTES: usize = 8 * 1024;

pub async fn handle(
    mut stream: TcpStream,
    state: &mut SessionState,
    ep: &EndpointConfig,
    session_timeout: Duration,
) -> CloseReason {
    let mut buf = [0u8; 4096];
    let mut accumulated: Vec<u8> = Vec::with_capacity(1024);

    let end_offset = loop {
        if accumulated.len() >= MAX_HEADERS_BYTES {
            break None;
        }
        match read_with_timeout(&mut stream, &mut buf, session_timeout).await {
            Ok(None) => return CloseReason::ClientClosed,
            Ok(Some(n)) => {
                state.record_bytes(&buf[..n]);
                accumulated.extend_from_slice(&buf[..n]);
                if let Some(pos) = find_double_crlf(&accumulated) {
                    break Some(pos + 4);
                }
            }
            Err(reason) => return reason,
        }
    };

    let header_slice = match end_offset {
        Some(pos) => &accumulated[..pos],
        None => &accumulated[..accumulated.len().min(MAX_HEADERS_BYTES)],
    };

    if let Some(req) = parse_request(header_slice) {
        state.push_event(req);
    }

    let server_header = ep.server_header.as_deref().unwrap_or("nginx/1.18.0");
    let status = ep.http_status.unwrap_or(404);
    let (reason, body) = canned_response(status);
    let body_bytes = body.as_bytes();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Server: {server}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        status = status,
        reason = reason,
        server = server_header,
        len = body_bytes.len(),
    );

    if stream.write_all(response.as_bytes()).await.is_err() {
        return CloseReason::Error;
    }
    if stream.write_all(body_bytes).await.is_err() {
        return CloseReason::Error;
    }
    let _ = stream.flush().await;
    CloseReason::ServerClosed
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request(header_slice: &[u8]) -> Option<SessionEvent> {
    let text = std::str::from_utf8(header_slice).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let version = parts.next().unwrap_or("").to_string();

    let mut host = None;
    let mut user_agent = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            match name.as_str() {
                "host" => host = Some(value),
                "user-agent" => user_agent = Some(value),
                _ => {}
            }
        }
    }

    Some(SessionEvent::HttpRequest {
        method,
        path,
        version,
        host,
        user_agent,
    })
}

fn canned_response(status: u16) -> (&'static str, &'static str) {
    match status {
        200 => (
            "OK",
            "<!doctype html><html><body><h1>It works!</h1></body></html>",
        ),
        301 => ("Moved Permanently", ""),
        401 => (
            "Unauthorized",
            "<!doctype html><html><body><h1>401 Unauthorized</h1></body></html>",
        ),
        403 => (
            "Forbidden",
            "<!doctype html><html><body><h1>403 Forbidden</h1></body></html>",
        ),
        500 => (
            "Internal Server Error",
            "<!doctype html><html><body><h1>500 Internal Server Error</h1></body></html>",
        ),
        _ => (
            "Not Found",
            "<!doctype html><html><body><h1>404 Not Found</h1></body></html>",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_request() {
        let raw = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: scanner\r\n\r\n";
        let ev = parse_request(raw).unwrap();
        match ev {
            SessionEvent::HttpRequest {
                method,
                path,
                version,
                host,
                user_agent,
            } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/admin");
                assert_eq!(version, "HTTP/1.1");
                assert_eq!(host.as_deref(), Some("example.com"));
                assert_eq!(user_agent.as_deref(), Some("scanner"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_missing_headers() {
        let raw = b"POST /upload HTTP/1.0\r\n\r\n";
        let ev = parse_request(raw).unwrap();
        if let SessionEvent::HttpRequest {
            method,
            host,
            user_agent,
            ..
        } = ev
        {
            assert_eq!(method, "POST");
            assert!(host.is_none());
            assert!(user_agent.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn double_crlf_offset() {
        let s = b"GET / HTTP/1.0\r\nA: b\r\n\r\nbody";
        let pos = find_double_crlf(s).unwrap();
        assert_eq!(&s[pos..pos + 4], b"\r\n\r\n");
    }
}
