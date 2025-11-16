fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        // `liboqs` pulls in Windows CryptoAPI symbols; ensure we link `Advapi32`.
        println!("cargo:rustc-link-lib=Advapi32");
    }
}
