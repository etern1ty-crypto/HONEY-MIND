//! Stateful Telnet negotiation stripping and bounded login dialogue.

use std::collections::VecDeque;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::SessionIo;

const MAX_LINE: usize = 256;
const MAX_ATTEMPTS: usize = 3;

pub async fn handle(
    io: &mut SessionIo,
    state: &mut SessionState,
    ep: &EndpointConfig,
) -> CloseReason {
    if let Some(banner) = &ep.banner {
        let banner = if banner.ends_with('\n') {
            banner.clone()
        } else {
            format!("{banner}\r\n")
        };
        if let Err(reason) = io.write(banner.as_bytes()).await {
            return reason;
        }
    }
    let prompt = ep.login_prompt.as_deref().unwrap_or("login: ");
    let mut reader = LineReader::default();
    for _ in 0..MAX_ATTEMPTS {
        if let Err(reason) = io.write(prompt.as_bytes()).await {
            return reason;
        }
        let username = match reader.read_line(io, state).await {
            Ok(Some(value)) => String::from_utf8_lossy(&value).into_owned(),
            Ok(None) => return CloseReason::ClientClosed,
            Err(reason) => return reason,
        };
        if username.is_empty() {
            continue;
        }
        if let Err(reason) = io.write(b"Password: ").await {
            login(state, username, None);
            return reason;
        }
        let password = match reader.read_line(io, state).await {
            Ok(Some(value)) => Some(String::from_utf8_lossy(&value).into_owned()),
            Ok(None) => {
                login(state, username, None);
                return CloseReason::ClientClosed;
            }
            Err(reason) => {
                login(state, username, None);
                return reason;
            }
        };
        login(state, username, password);
        if let Err(reason) = io.write(b"Login incorrect\r\n").await {
            return reason;
        }
    }
    match io.write(b"Too many attempts. Disconnecting.\r\n").await {
        Ok(()) => CloseReason::ServerClosed,
        Err(reason) => reason,
    }
}

fn login(state: &mut SessionState, username: String, password: Option<String>) {
    state.push_event(SessionEvent::TelnetLogin {
        username,
        password,
        credentials_redacted: false,
    });
}

#[derive(Default)]
struct LineReader {
    pending: VecDeque<u8>,
    decoder: TelnetDecoder,
    line: Vec<u8>,
    pending_cr: bool,
}

impl LineReader {
    async fn read_line(
        &mut self,
        io: &mut SessionIo,
        state: &mut SessionState,
    ) -> Result<Option<Vec<u8>>, CloseReason> {
        let mut buffer = [0u8; 256];
        loop {
            while let Some(byte) = self.pending.pop_front() {
                let Some(byte) = self.decoder.feed(byte) else {
                    continue;
                };
                if self.pending_cr {
                    self.pending_cr = false;
                    if byte == b'\n' {
                        return Ok(Some(std::mem::take(&mut self.line)));
                    }
                    self.append(b'\r', state)?;
                    // NVT CR NUL is a literal CR, not a credential boundary.
                    if byte == 0 {
                        continue;
                    }
                }
                match byte {
                    b'\r' => self.pending_cr = true,
                    b'\n' => return Ok(Some(std::mem::take(&mut self.line))),
                    byte => self.append(byte, state)?,
                }
            }
            match io.read(state, &mut buffer).await? {
                None => {
                    if !self.line.is_empty() || self.pending_cr {
                        state.notice("telnet_incomplete_line");
                    }
                    return Ok(None);
                }
                Some(n) => self.pending.extend(&buffer[..n]),
            }
        }
    }

    fn append(&mut self, byte: u8, state: &mut SessionState) -> Result<(), CloseReason> {
        if self.line.len() >= MAX_LINE {
            state.notice("telnet_line_too_long");
            return Err(CloseReason::ProtocolError);
        }
        self.line.push(byte);
        Ok(())
    }
}

#[derive(Default)]
struct TelnetDecoder {
    state: DecodeState,
}

#[derive(Clone, Copy, Default)]
enum DecodeState {
    #[default]
    Data,
    Iac,
    Option,
    Subnegotiation,
    SubnegotiationIac,
}

impl TelnetDecoder {
    /// Keeps state across read boundaries. Negotiation contents never become lines.
    fn feed(&mut self, byte: u8) -> Option<u8> {
        use DecodeState::*;
        match self.state {
            Data if byte == 255 => self.state = Iac,
            Data => return Some(byte),
            Iac => match byte {
                255 => {
                    self.state = Data;
                    return Some(255);
                }
                251..=254 => self.state = Option,
                250 => self.state = Subnegotiation,
                _ => self.state = Data,
            },
            Option => self.state = Data,
            Subnegotiation if byte == 255 => self.state = SubnegotiationIac,
            Subnegotiation => {}
            SubnegotiationIac => self.state = if byte == 240 { Data } else { Subnegotiation },
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(chunks: &[&[u8]]) -> Vec<u8> {
        let mut decoder = TelnetDecoder::default();
        chunks
            .iter()
            .flat_map(|chunk| chunk.iter())
            .filter_map(|b| decoder.feed(*b))
            .collect()
    }

    #[test]
    fn strips_fragmented_option_negotiation() {
        assert_eq!(
            decode(&[b"\xff", b"\xfb", b"\x01ad", b"min\r\n"]),
            b"admin\r\n"
        );
    }

    #[test]
    fn strips_subnegotiation_including_embedded_newlines() {
        assert_eq!(
            decode(&[b"\xff\xfa\x18term\n", b"type\xff", b"\xf0root\n"]),
            b"root\n"
        );
    }

    #[test]
    fn escaped_iac_is_data_not_a_command() {
        assert_eq!(decode(&[b"ab\xff", b"\xffcd\n"]), b"ab\xffcd\n");
    }

    #[test]
    fn does_not_strip_ordinary_bytes() {
        assert_eq!(decode(&[b"user name\r\n"]), b"user name\r\n");
    }
}
