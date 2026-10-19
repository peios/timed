fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libtrust.so.1");
}
