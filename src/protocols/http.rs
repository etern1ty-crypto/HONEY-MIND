//! Strict, bounded HTTP/1.x header capture followed by one fixed response.
//! Bodies, proxying, HTTP/2, keep-alive and pipelining are intentionally absent.

use hyper::StatusCode;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::SessionIo;

const MAX_HEADER_BYTES: usize = 8192;
const MAX_HEADER_COUNT: usize = 64;

pub async fn handle(
    io: &mut SessionIo,
    state: &mut SessionState,
    ep: &EndpointConfig,
) -> CloseReason {
    let server = ep.server_header.as_deref().unwrap_or("nginx");
    let mut buffer = [0u8; 2048];
    let mut headers = Vec::with_capacity(1024);
    let header_end = loop {
        let remaining = MAX_HEADER_BYTES - headers.len();
        if remaining == 0 {
            state.notice("http_headers_too_large");
            return match io.write(&response(431, false, server)).await {
                Ok(()) => CloseReason::ProtocolError,
                Err(reason) => reason,
            };
        }
        let read_size = remaining.min(buffer.len());
        match io.read(state, &mut buffer[..read_size]).await {
            Ok(None) => {
                if !headers.is_empty() {
                    state.notice("http_incomplete_headers");
                }
                return CloseReason::ClientClosed;
            }
            Ok(Some(n)) => {
                let scan_from = headers.len().saturating_sub(3);
                headers.extend_from_slice(&buffer[..n]);
                if let Some(offset) = headers[scan_from..]
                    .windows(4)
                    .position(|v| v == b"\r\n\r\n")
                {
                    break scan_from + offset + 4;
                }
            }
            Err(reason) => return reason,
        }
    };

    let event = match parse_request(&headers[..header_end]) {
        Ok(event) => event,
        Err(message) => {
            state.notice(message);
            return match io.write(&response(400, false, server)).await {
                Ok(()) => CloseReason::ProtocolError,
                Err(reason) => reason,
            };
        }
    };
    let head = matches!(&event, SessionEvent::HttpRequest { method, .. } if method == "HEAD");
    state.push_event(event);
    match io
        .write(&response(ep.http_status.unwrap_or(404), head, server))
        .await
    {
        Ok(()) => CloseReason::ServerClosed,
        Err(reason) => reason,
    }
}

fn parse_request(bytes: &[u8]) -> Result<SessionEvent, &'static str> {
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err("http_incomplete_headers");
    }
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or("http_missing_request_line")?;
    let mut parts = line.split(' ');
    let method = parts.next().ok_or("http_missing_method")?;
    let path = parts.next().ok_or("http_missing_target")?;
    let version = parts.next().ok_or("http_missing_version")?;
    if parts.next().is_some()
        || method.is_empty()
        || method.len() > 32
        || !method.bytes().all(token_byte)
    {
        return Err("http_invalid_request_line");
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("http_unsupported_version");
    }
    if path.is_empty()
        || !(path.starts_with('/') || (method == "OPTIONS" && path == "*"))
        || !path.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err("http_invalid_target");
    }

    let mut host = None;
    let mut user_agent = None;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for (count, line) in lines.enumerate() {
        if line.is_empty() {
            break;
        }
        if count >= MAX_HEADER_COUNT {
            return Err("http_too_many_headers");
        }
        let (name, value) = line.split_once(':').ok_or("http_invalid_header")?;
        if name.is_empty()
            || !name.bytes().all(token_byte)
            || value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err("http_invalid_header");
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                if host.is_some() || value.is_empty() || value.len() > 2048 {
                    return Err("http_invalid_host");
                }
                host = Some(value.to_owned());
            }
            "user-agent" => {
                if user_agent.is_none() {
                    user_agent = Some(value.chars().take(1024).collect());
                }
            }
            "content-length" => {
                if content_length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err("http_invalid_content_length");
                }
                content_length = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "http_invalid_content_length")?,
                );
            }
            "transfer-encoding" => {
                if transfer_encoding || !value.eq_ignore_ascii_case("chunked") {
                    return Err("http_invalid_transfer_encoding");
                }
                transfer_encoding = true;
            }
            _ => {}
        }
    }
    if version == "HTTP/1.1" && host.is_none() {
        return Err("http_missing_host");
    }
    if transfer_encoding && content_length.is_some() {
        return Err("http_ambiguous_framing");
    }
    Ok(SessionEvent::HttpRequest {
        method: method.into(),
        path: path.into(),
        version: version.into(),
        host,
        user_agent,
    })
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn response(status: u16, head: bool, server: &str) -> Vec<u8> {
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("Unknown");
    let no_body_status = matches!(status, 204 | 205 | 304);
    let body = if no_body_status {
        String::new()
    } else {
        format!("{status} {reason}\n")
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nServer: {server}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n"
    );
    // RFC 9110 forbids Content-Length on 204. A 304 has no selected representation here.
    if !matches!(status, 204 | 304) {
        headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if status == 401 {
        headers.push_str("WWW-Authenticate: Basic realm=\"Administration\"\r\n");
    }
    headers.push_str("\r\n");
    if !head {
        headers.push_str(&body);
    }
    headers.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_without_reflecting_input_into_response() {
        let event = parse_request(
            b"GET /admin HTTP/1.1\r\nHost: target.example\r\nUser-Agent: scanner\r\n\r\n",
        )
        .unwrap();
        assert!(
            matches!(event, SessionEvent::HttpRequest { method, path, .. } if method == "GET" && path == "/admin")
        );
    }

    #[test]
    fn http10_may_omit_host() {
        assert!(parse_request(b"POST /upload HTTP/1.0\r\n\r\n").is_ok());
    }

    #[test]
    fn rejects_malformed_and_ambiguous_headers() {
        for bytes in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &b"GET / HTTP/1.1 EXTRA\r\nHost: a\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost : a\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            &b"GET http://user:secret@host/ HTTP/1.1\r\nHost: host\r\n\r\n"[..],
        ] {
            assert!(parse_request(bytes).is_err());
        }
    }

    #[test]
    fn head_has_headers_only_and_correct_representation_length() {
        let head = String::from_utf8(response(404, true, "nginx")).unwrap();
        assert!(head.ends_with("\r\n\r\n"));
        assert!(head.contains("Content-Length: 14\r\n"));
    }

    #[test]
    fn empty_statuses_do_not_emit_404_bodies() {
        for status in [204, 205, 304] {
            let response = String::from_utf8(response(status, false, "nginx")).unwrap();
            assert!(response.ends_with("\r\n\r\n"));
            assert!(!response.contains("404"));
            if status == 204 {
                assert!(!response.contains("Content-Length"));
            }
        }
    }

    #[test]
    fn configured_status_has_its_own_reason() {
        let body = String::from_utf8(response(503, false, "nginx")).unwrap();
        assert!(body.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(body.ends_with("503 Service Unavailable\n"));
    }
}
