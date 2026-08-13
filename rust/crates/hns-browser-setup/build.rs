fn main() {
    println!("cargo:rerun-if-env-changed=HNS_NATIVE_HOST_PATH");
    println!("cargo:rerun-if-env-changed=HNS_HEADER_SNAPSHOT_PATH");
    println!("cargo:rerun-if-env-changed=HNS_EXTENSION_IDS");
    println!("cargo:rerun-if-changed=../../../release/hns_headers_300000.snapshot.gzip");
    println!("cargo:rerun-if-changed=../../../release/header-snapshot-300000.json");
    println!("cargo:rerun-if-changed=../../../../LICENSE");
    println!("cargo:rerun-if-changed=../../../../extension/THIRD_PARTY_NOTICES.txt");

    if std::env::var_os("CARGO_FEATURE_EMBEDDED_HOST").is_some()
        && std::env::var_os("HNS_NATIVE_HOST_PATH").is_none()
    {
        panic!("HNS_NATIVE_HOST_PATH is required when embedded-host is enabled");
    }
    if std::env::var_os("CARGO_FEATURE_EMBEDDED_HOST").is_some()
        && std::env::var_os("HNS_HEADER_SNAPSHOT_PATH").is_none()
    {
        panic!("HNS_HEADER_SNAPSHOT_PATH is required when embedded-host is enabled");
    }

    let canonical = "idejjnoplngbhpnpjekblpalblbianio";
    let configured = std::env::var("HNS_EXTENSION_IDS").unwrap_or_else(|_| canonical.to_owned());
    let mut extension_ids = Vec::new();
    for value in configured.split(',') {
        let extension_id = value.trim();
        if extension_id.len() != 32
            || !extension_id
                .bytes()
                .all(|byte| (b'a'..=b'p').contains(&byte))
        {
            panic!("HNS_EXTENSION_IDS contains an invalid Chromium extension ID");
        }
        if !extension_ids.contains(&extension_id) {
            extension_ids.push(extension_id);
        }
    }
    if extension_ids.is_empty() || extension_ids.len() > 16 {
        panic!("HNS_EXTENSION_IDS must contain between 1 and 16 exact IDs");
    }
    if !extension_ids.contains(&canonical) {
        panic!("HNS_EXTENSION_IDS must include the canonical extension ID");
    }
    println!(
        "cargo:rustc-env=HNS_COMPILED_EXTENSION_IDS={}",
        extension_ids.join(",")
    );
}
