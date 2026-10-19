use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PEIOS_TRUST_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if let Some(directory) = env::var_os("PEIOS_TRUST_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            directory.to_string_lossy()
        );
    } else if let Ok(output) = Command::new("pkg-config")
        .args(["--libs-only-L", "trust"])
        .output()
        && output.status.success()
    {
        for flag in String::from_utf8_lossy(&output.stdout).split_whitespace() {
            if let Some(directory) = flag.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={directory}");
            }
        }
    }
}
