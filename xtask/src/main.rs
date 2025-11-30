use anyhow::Context as _;
use clap::Parser;
use std::process::Command;
use std::path::PathBuf;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: CommandOpts,
}

#[derive(Parser)]
enum CommandOpts {
    BuildEbpf(BuildEbpfOpts),
}

#[derive(Parser)]
pub struct BuildEbpfOpts {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: String,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();

    match opts.command {
        CommandOpts::BuildEbpf(opts) => build_ebpf(opts),
    }
}

fn build_ebpf(opts: BuildEbpfOpts) -> anyhow::Result<()> {
    let crates = ["minotaur-net-ebpf", "minotaur-eye-ebpf"];
    
    for crate_name in crates {
        let dir = PathBuf::from(crate_name);
        let target = format!("--target={}", opts.target);
        let mut args = vec![
            "build",
            target.as_str(),
            "-Z",
            "build-std=core",
        ];

        if opts.release {
            args.push("--release");
        }

        let status = Command::new("cargo")
            .current_dir(dir)
            .args(&args)
            .status()
            .context(format!("Failed to build eBPF program {}", crate_name))?;

        if !status.success() {
            anyhow::bail!("Build failed for {}", crate_name);
        }
    }

    Ok(())
}
