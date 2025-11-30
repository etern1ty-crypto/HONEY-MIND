pub mod xsk;

use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use anyhow::Context;
use log::{info, warn, debug};

pub struct NetworkController {
    bpf: Bpf,
}

impl NetworkController {
    pub fn new() -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/minotaur-net-ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/minotaur-net-ebpf"
        ))?;

        if let Err(e) = BpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        Ok(Self { bpf })
    }

    pub fn attach(&mut self, interface: &str) -> anyhow::Result<()> {
        let program: &mut Xdp = self.bpf.program_mut("minotaur_xdp").unwrap().try_into()?;
        program.load()?;
        program.attach(interface, XdpFlags::default())
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
        
        info!("XDP program attached to {}", interface);
        Ok(())
    }
}
