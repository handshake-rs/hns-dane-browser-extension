//! Cross-platform, per-user setup for HNS DANE Browser.

mod browser;
mod installer;
mod payload;

pub use browser::{Browser, BrowserSelection, detect_browsers};
pub use installer::{
    InstallRequest, InstallationStatus, Installer, OperationReport, SetupError,
    validate_extension_id,
};
pub use payload::NativePayload;

/// Native Messaging host name shared with the Chromium extension.
pub const NATIVE_HOST_NAME: &str = "com.denuoweb.hns_dane_browser";

/// Stable identity of the canonical GitHub/unpacked extension package.
pub const CANONICAL_EXTENSION_ID: &str = "idejjnoplngbhpnpjekblpalblbianio";

/// Product version shared by the extension, native host, and setup program.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
