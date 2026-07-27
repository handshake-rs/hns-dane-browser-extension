fn main() {
    println!("cargo:rerun-if-env-changed=HNS_NATIVE_HOST_PATH");
    println!("cargo:rerun-if-changed=../../../../LICENSE");
    println!("cargo:rerun-if-changed=../../../../extension/THIRD_PARTY_NOTICES.txt");

    if std::env::var_os("CARGO_FEATURE_EMBEDDED_HOST").is_some()
        && std::env::var_os("HNS_NATIVE_HOST_PATH").is_none()
    {
        panic!("HNS_NATIVE_HOST_PATH is required when embedded-host is enabled");
    }
}
