use std::path::{Path, PathBuf};

/// Source of the version-matched native host installed by the setup program.
#[derive(Debug, Clone)]
pub enum NativePayload {
    Embedded(&'static [u8]),
    External(PathBuf),
}

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

#[cfg(not(feature = "embedded-host"))]
fn default_development_host() -> PathBuf {
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release")
        .join(format!("hns-chromium-native-host{suffix}"))
}

pub(crate) const PRODUCT_LICENSE: &str = include_str!("../../../../LICENSE");
pub(crate) const THIRD_PARTY_NOTICES: &str =
    include_str!("../../../../extension/THIRD_PARTY_NOTICES.txt");
