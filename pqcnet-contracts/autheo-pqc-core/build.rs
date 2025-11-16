#[cfg(target_os = "windows")]
fn main() {
    // `liboqs` pulls in Windows CryptoAPI symbols; ensure we link `Advapi32`.
    println!("cargo:rustc-link-lib=Advapi32");
}

#[cfg(not(target_os = "windows"))]
fn main() {}
