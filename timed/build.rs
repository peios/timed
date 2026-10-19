//! Use the recorded source epoch as a reproducible lower bound for the clock.
//! This is a bootstrap floor, not a claim that every certificate was valid then.
fn main() {
    println!("cargo:rerun-if-changed=../build/epoch.txt");
    let epoch = include_str!("../build/epoch.txt").trim();
    assert!(
        epoch.parse::<i64>().is_ok_and(|value| value > 0),
        "invalid source epoch"
    );
    println!("cargo:rustc-env=TIMED_BUILD_EPOCH={epoch}");
}
