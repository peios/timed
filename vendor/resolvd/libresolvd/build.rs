fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libresolvd.so.1");
}
