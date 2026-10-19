fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libtimed.so.1");
}
