use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "dadophoros build orchestration")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the eBPF crate for bpfel-unknown-none via nightly cargo.
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
    /// Build the eBPF crate, then the userspace workspace.
    Build {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::BuildEbpf { release } => build_ebpf(release),
        Cmd::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
    }
}

fn workspace_root() -> Result<PathBuf> {
    let mut p = std::env::current_dir().context("getting cwd")?;
    loop {
        if p.join("Cargo.toml").exists() && p.join("dadophoros-ebpf").is_dir() {
            return Ok(p);
        }
        if !p.pop() {
            bail!("could not locate workspace root (looking for Cargo.toml + dadophoros-ebpf/)");
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root()?;
    let ebpf_dir = root.join("dadophoros-ebpf");
    let target_dir = root.join("target");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);
    cmd.env("CARGO_TARGET_DIR", &target_dir);
    // The parent cargo (stable) injects RUSTC / CARGO / RUSTUP_TOOLCHAIN
    // into our env. If left in place, the child cargo invocation uses
    // those instead of resolving nightly from dadophoros-ebpf's
    // rust-toolchain.toml, which produces "can't find crate for `core`".
    for var in [
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO",
        "CARGO_MANIFEST_DIR",
        "RUSTUP_TOOLCHAIN",
    ] {
        cmd.env_remove(var);
    }
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }
    eprintln!("xtask: building eBPF crate in {}", ebpf_dir.display());
    let status = cmd.status().context("invoking cargo for eBPF build")?;
    if !status.success() {
        bail!("eBPF build failed: {status}");
    }

    let profile = if release { "release" } else { "debug" };
    let out = target_dir
        .join("bpfel-unknown-none")
        .join(profile)
        .join("dadophoros-ebpf");
    if !out.exists() {
        bail!("expected eBPF object missing: {}", out.display());
    }
    eprintln!("xtask: eBPF object at {}", out.display());
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let root = workspace_root()?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args(["build", "--workspace"]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("invoking cargo for userspace build")?;
    if !status.success() {
        bail!("userspace build failed: {status}");
    }
    Ok(())
}
