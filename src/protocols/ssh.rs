//! RFC 4253 identification only: deliberately no KEX, authentication or shell.

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::SessionIo;

const DEFAULT_BANNER: &str = "SSH-2.0-OpenSSH_9.6";
const MAX_IDENTIFICATION_BYTES: usize = 255;

pub async fn handle(
    io: &mut SessionIo,
    state: &mut SessionState,
    ep: &EndpointConfig,
) -> CloseReason {
    let banner = format!("{}\r\n", ep.banner.as_deref().unwrap_or(DEFAULT_BANNER));
    if let Err(reason) = io.write(banner.as_bytes()).await {
        return reason;
    }
    let mut buffer = [0u8; 4096];
    let mut identification = Vec::with_capacity(MAX_IDENTIFICATION_BYTES);
    let mut identified = false;
    loop {
        match io.read(state, &mut buffer).await {
            Ok(None) => {
                if !identified && !identification.is_empty() {
                    state.notice("ssh_incomplete_identification");
                }
                return CloseReason::ClientClosed;
            }
            Ok(Some(n)) => {
                if identified {
                    continue;
                }
                for &byte in &buffer[..n] {
                    identification.push(byte);
                    if byte == b'\n' {
                        let line = identification
                            .strip_suffix(b"\n")
                            .unwrap_or(&identification);
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        if !valid_identification(line) {
                            state.notice("ssh_invalid_identification");
                            return CloseReason::ProtocolError;
                        }
                        state.push_event(SessionEvent::SshClientBanner {
                            banner: String::from_utf8_lossy(line).into_owned(),
                        });
                        identified = true;
                        break;
                    }
                    if identification.len() >= MAX_IDENTIFICATION_BYTES {
                        state.notice("ssh_identification_too_long");
                        return CloseReason::ProtocolError;
                    }
                }
            }
            Err(reason) => return reason,
        }
    }
}

fn valid_identification(line: &[u8]) -> bool {
    let software = line
        .strip_prefix(b"SSH-2.0-")
        .or_else(|| line.strip_prefix(b"SSH-1.99-"));
    software.is_some_and(|value| !value.is_empty() && value[0] != b' ')
        && line.iter().all(|b| (0x20..=0x7e).contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification_is_not_arbitrary_first_line() {
        assert!(valid_identification(b"SSH-2.0-Client_1.0 comment"));
        assert!(!valid_identification(b"GET / HTTP/1.1"));
        assert!(!valid_identification(b"SSH-2.0-test\0"));
        assert!(!valid_identification(b"SSH-2.0-"));
    }
}
