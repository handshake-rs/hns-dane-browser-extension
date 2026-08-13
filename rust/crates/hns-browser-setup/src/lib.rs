//! Cross-platform, per-user setup for HNS DANE Browser.

mod browser;
mod installer;
mod payload;

pub use browser::{Browser, BrowserSelection, detect_browsers};
pub use installer::{
    InstallRequest, InstallationStatus, Installer, OperationReport, SetupError,
    validate_extension_id,
};
pub use payload::{
    HEADER_SNAPSHOT_COMPRESSED_BYTES, HEADER_SNAPSHOT_COMPRESSED_SHA256,
    HEADER_SNAPSHOT_TARGET_HEIGHT, HEADER_SNAPSHOT_UNCOMPRESSED_BYTES,
    HEADER_SNAPSHOT_UNCOMPRESSED_SHA256, HeaderSnapshotPayload, NativePayload,
};

/// Native Messaging host name shared with the Chromium extension.
pub const NATIVE_HOST_NAME: &str = "com.denuoweb.hns_dane_browser";

/// Stable identity of the canonical GitHub/unpacked extension package.
pub const CANONICAL_EXTENSION_ID: &str = "idejjnoplngbhpnpjekblpalblbianio";

/// Exact extension IDs compiled into this Setup build by the release gate.
pub fn compiled_extension_ids() -> Vec<String> {
    env!("HNS_COMPILED_EXTENSION_IDS")
        .split(',')
        .map(str::to_owned)
        .collect()
}

/// Product version shared by the extension, native host, and setup program.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_ids_are_exact_unique_and_include_canonical_identity() {
        let extension_ids = compiled_extension_ids();
        assert!(!extension_ids.is_empty());
        assert!(extension_ids.len() <= 16);
        assert!(
            extension_ids
                .iter()
                .any(|value| value == CANONICAL_EXTENSION_ID)
        );
        for extension_id in &extension_ids {
            validate_extension_id(extension_id).unwrap();
        }
        let mut unique = extension_ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), extension_ids.len());
    }
}
