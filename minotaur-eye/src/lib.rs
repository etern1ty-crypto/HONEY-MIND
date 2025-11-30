pub mod scanner;

use aya::Bpf;
use anyhow::Result;

pub struct EyeController {
    bpf: Bpf,
}

impl EyeController {
    pub fn new() -> Result<Self> {
        // Placeholder for BPF loading logic
        Ok(Self {
            bpf: Bpf::load(&[])?, // This will fail, just a skeleton
        })
    }
}
