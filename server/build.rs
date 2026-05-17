use std::path::PathBuf;

fn main() {
    let sovereign_dir = PathBuf::from("sovereign");
    let lib_path = sovereign_dir.join("libgp_sovereign.a");

    if lib_path.exists() {
        println!("cargo:rustc-link-search=native={}", sovereign_dir.display());
        println!("cargo:rustc-link-lib=static=gp_sovereign");
        println!("cargo:rustc-cfg=feature=\"sovereign\"");
    } else {
        // Build the always-reject stub so the link target exists unconditionally.
        let stub = sovereign_dir.join("stub.c");
        cc::Build::new()
            .file(stub)
            .compile("gp_sovereign");
    }

    println!("cargo:rerun-if-changed=sovereign/libgp_sovereign.a");
    println!("cargo:rerun-if-changed=sovereign/stub.c");
}
