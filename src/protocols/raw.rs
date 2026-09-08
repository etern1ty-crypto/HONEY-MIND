//! Optional fixed banner, then bounded capture. No commands are executed.

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionState};

use super::SessionIo;

pub async fn handle(
    io: &mut SessionIo,
    state: &mut SessionState,
    ep: &EndpointConfig,
) -> CloseReason {
    if let Some(banner) = &ep.banner {
        if let Err(reason) = io.write(banner.as_bytes()).await {
            return reason;
        }
    }
    let mut buffer = [0u8; 4096];
    loop {
        match io.read(state, &mut buffer).await {
            Ok(None) => return CloseReason::ClientClosed,
            Ok(Some(_)) => {}
            Err(reason) => return reason,
        }
    }
}
