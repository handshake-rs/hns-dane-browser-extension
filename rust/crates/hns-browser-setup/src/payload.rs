use std::path::{Path, PathBuf};

/// Source of the version-matched native host installed by the setup program.
#[derive(Debug, Clone)]
pub enum NativePayload {
    Embedded(&'static [u8]),
    External(PathBuf),
}

/// Source of the mainnet header snapshot installed by the setup program.
#[derive(Debug, Clone)]
pub enum HeaderSnapshotPayload {
    Embedded(&'static [u8]),
    External(PathBuf),
}

pub const HEADER_SNAPSHOT_TARGET_HEIGHT: u32 = 300_000;
pub const HEADER_SNAPSHOT_COMPRESSED_BYTES: u64 = 35_030_894;
pub const HEADER_SNAPSHOT_COMPRESSED_SHA256: &str =
    "0ff3484e1dede5bc34ce41206b70934b809791927b5ad82a4dac08412ec1fdd1";
pub const HEADER_SNAPSHOT_UNCOMPRESSED_BYTES: u64 = 70_800_287;
pub const HEADER_SNAPSHOT_UNCOMPRESSED_SHA256: &str =
    "ff7c042b2f5d6dd035e0e083f0f31dd4dafb279288c0e929e092b71ce288d388";

impl NativePayload {
    #[cfg(feature = "embedded-host")]
    pub fn release_embedded() -> Self {
        Self::Embedded(include_bytes!(env!("HNS_NATIVE_HOST_PATH")))
    }

    #[cfg(not(feature = "embedded-host"))]
    pub fn release_embedded() -> Self {
        Self::External(default_development_host())
    }

    pub fn external(path: impl Into<PathBuf>) -> Self {
        Self::External(path.into())
    }

    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Embedded(bytes) => Ok(bytes.to_vec()),
            Self::External(path) => std::fs::read(path),
        }
    }

    pub fn source_path(&self) -> Option<&Path> {
        match self {
            Self::Embedded(_) => None,
            Self::External(path) => Some(path.as_path()),
        }
    }
}

impl HeaderSnapshotPayload {
    #[cfg(feature = "embedded-host")]
    pub fn release_embedded() -> Self {
        Self::Embedded(include_bytes!(env!("HNS_HEADER_SNAPSHOT_PATH")))
    }

    #[cfg(not(feature = "embedded-host"))]
    pub fn release_embedded() -> Self {
        Self::External(default_development_snapshot())
    }

    pub fn external(path: impl Into<PathBuf>) -> Self {
        Self::External(path.into())
    }

    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Embedded(bytes) => Ok(bytes.to_vec()),
            Self::External(path) => std::fs::read(path),
        }
    }

    pub fn source_path(&self) -> Option<&Path> {
        match self {
            Self::Embedded(_) => None,
            Self::External(path) => Some(path.as_path()),
        }
    }
}

#[cfg(not(feature = "embedded-host"))]
fn default_development_host() -> PathBuf {
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release")
        .join(format!("hns-chromium-native-host{suffix}"))
}

#[cfg(not(feature = "embedded-host"))]
fn default_development_snapshot() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../release")
        .join("hns_headers_300000.snapshot.gzip")
}

pub(crate) const PRODUCT_LICENSE: &str = include_str!("../../../../LICENSE");
pub(crate) const THIRD_PARTY_NOTICES: &str =
    include_str!("../../../../extension/THIRD_PARTY_NOTICES.txt");
