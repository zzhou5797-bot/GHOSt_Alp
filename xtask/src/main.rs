use std::{env, path::PathBuf, process::Command};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build-ebpf") => build_ebpf(),
        Some(other) => {
            eprintln!("unknown xtask: {other}");
            eprintln!("usage: cargo xtask build-ebpf");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: cargo xtask build-ebpf");
            std::process::exit(2);
        }
    }
}

fn build_ebpf() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live inside the workspace")
        .to_path_buf();

    let custom = env::var("GHOST_BPF_CARGO").ok();
    let has_rustup = Command::new("rustup").arg("--version").output().is_ok();

    let mut command = if let Some(cargo) = custom {
        Command::new(cargo)
    } else if has_rustup {
        let mut cmd = Command::new("rustup");
        cmd.args(["run", "nightly", "cargo"]);
        cmd
    } else {
        eprintln!("Ghost eBPF build requires a nightly Cargo with rust-src.");
        eprintln!("Install rustup + nightly + rust-src, or set GHOST_BPF_CARGO to a nightly cargo executable.");
        eprintln!("Example: rustup toolchain install nightly --component rust-src");
        std::process::exit(1);
    };

    let status = command
        .current_dir(&root)
        .args([
            "build",
            "-Z",
            "build-std=core",
            "--release",
            "--manifest-path",
            "gateway-ebpf/Cargo.toml",
            "--target",
            "bpfel-unknown-none",
        ])
        .status()
        .expect("failed to start nightly cargo for eBPF build");

    if !status.success() {
        eprintln!("eBPF build failed. Ensure the nightly toolchain has the rust-src component.");
        std::process::exit(status.code().unwrap_or(1));
    }
}
