//! Fail-closed, per-user installation shared by the setup GUI and CLI.

use crate::CANONICAL_EXTENSION_ID;
use crate::payload::{PRODUCT_LICENSE, THIRD_PARTY_NOTICES};
use crate::{
    Browser, HEADER_SNAPSHOT_COMPRESSED_BYTES, HEADER_SNAPSHOT_COMPRESSED_SHA256,
    HEADER_SNAPSHOT_TARGET_HEIGHT, HEADER_SNAPSHOT_UNCOMPRESSED_BYTES,
    HEADER_SNAPSHOT_UNCOMPRESSED_SHA256, HeaderSnapshotPayload, NATIVE_HOST_NAME, NativePayload,
    VERSION,
};
#[cfg(target_os = "linux")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

const RECEIPT_SCHEMA_VERSION: u32 = 2;
const TRANSACTION_SCHEMA_VERSION: u32 = 2;
const LOCAL_CA_SCHEMA_VERSION: u32 = 1;
const MAX_EXTENSION_IDS: usize = 16;
const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_COMMAND_DIAGNOSTIC_CHARS: usize = 2_000;
#[cfg(target_os = "linux")]
const CA_COMMON_NAME: &str = "HNS DANE Browser Local CA";
const RECEIPT_FILE_NAME: &str = "installation-receipt.json";
const TRANSACTION_FILE_NAME: &str = "installation-transaction.json";
const NATIVE_HOST_FILE_NAME: &str = if cfg!(windows) {
    "hns-chromium-native-host.exe"
} else {
    "hns-chromium-native-host"
};
const BUNDLED_HEADER_SNAPSHOT: SnapshotIntegrity<'static> = SnapshotIntegrity {
    target_height: HEADER_SNAPSHOT_TARGET_HEIGHT,
    compressed_bytes: HEADER_SNAPSHOT_COMPRESSED_BYTES,
    compressed_sha256: HEADER_SNAPSHOT_COMPRESSED_SHA256,
    uncompressed_bytes: HEADER_SNAPSHOT_UNCOMPRESSED_BYTES,
    uncompressed_sha256: HEADER_SNAPSHOT_UNCOMPRESSED_SHA256,
};

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
struct SnapshotIntegrity<'a> {
    target_height: u32,
    compressed_bytes: u64,
    compressed_sha256: &'a str,
    uncompressed_bytes: u64,
    uncompressed_sha256: &'a str,
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub extension_ids: Vec<String>,
    pub browsers: BTreeSet<Browser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InstallationStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub extension_ids: Vec<String>,
    pub browsers: BTreeSet<Browser>,
    pub native_host_path: Option<PathBuf>,
    pub ca_installed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationReport {
    pub summary: String,
    pub details: Vec<String>,
    pub status: InstallationStatus,
}

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("invalid Chromium extension ID: {0}")]
    InvalidExtensionId(String),
    #[error("at least one Chromium browser must be selected")]
    NoBrowsers,
    #[error("setup operation failed: {0}")]
    Operation(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn validate_extension_id(value: &str) -> Result<(), SetupError> {
    if value.len() == 32 && value.bytes().all(|byte| (b'a'..=b'p').contains(&byte)) {
        Ok(())
    } else {
        Err(SetupError::InvalidExtensionId(value.to_owned()))
    }
}

#[derive(Debug, Clone)]
pub struct Installer {
    payload: NativePayload,
    header_snapshot: HeaderSnapshotPayload,
}

impl Installer {
    pub fn new(payload: NativePayload) -> Self {
        Self {
            payload,
            header_snapshot: HeaderSnapshotPayload::release_embedded(),
        }
    }

    pub fn with_header_snapshot(
        payload: NativePayload,
        header_snapshot: HeaderSnapshotPayload,
    ) -> Self {
        Self {
            payload,
            header_snapshot,
        }
    }

    /// Returns a fail-closed status. `installed` is true only when the receipt,
    /// payload, native manifest, selected registrations, CA marker, and
    /// platform trust store all agree.
    pub fn inspect(&self) -> Result<InstallationStatus, SetupError> {
        let layout = InstallLayout::from_environment()?;
        ensure_safe_root(&layout.install_root, &layout.protected_roots)?;
        validate_existing_ancestors_no_redirect(&layout.install_root, "install-root ancestor")?;
        let Some(receipt) = read_receipt(&layout)? else {
            return Ok(InstallationStatus {
                installed: false,
                version: None,
                extension_ids: Vec::new(),
                browsers: BTreeSet::new(),
                native_host_path: layout
                    .installed_host
                    .is_file()
                    .then_some(layout.installed_host),
                ca_installed: false,
            });
        };

        validate_receipt(&receipt, &layout)?;
        let mut complete = true;

        let host_bytes = read_regular_file_if_present(&layout.installed_host, u64::MAX)?;
        complete &= host_bytes
            .as_ref()
            .is_some_and(|bytes| sha256_hex(bytes) == receipt.native_host_sha256);
        complete &= paths_equivalent(&layout.installed_host, &receipt.native_host_path);

        let manifest_bytes =
            read_regular_file_if_present(&layout.manifest_path, MAX_MANIFEST_BYTES)?;
        complete &= manifest_bytes.as_ref().is_some_and(|bytes| {
            sha256_hex(bytes) == receipt.manifest_sha256
                && validate_host_manifest(bytes, &receipt.native_host_path, &receipt.extension_ids)
                    .is_ok()
        });
        complete &= layout.product_license.is_file() && layout.third_party_notices.is_file();
        complete &= registrations_match(&layout, &receipt)?;

        let mut ca_installed = false;
        if complete && layout.ca_bundle_path.is_file() {
            validate_ca_storage(&layout, false)?;
            let ca = invoke_ca_info(&layout.installed_host, &layout.data_dir)?;
            validate_ca_storage(&layout, false)?;
            validate_ca_info(&ca, &layout)?;
            ca_installed = ca.state == "installed"
                && ca.certificate_sha1 == receipt.certificate_sha1
                && ca.certificate_sha256 == receipt.certificate_sha256
                && trust_anchor_present(&layout, &ca, &receipt.trust_store)?;
        }

        Ok(InstallationStatus {
            installed: complete && ca_installed,
            version: Some(receipt.version),
            extension_ids: receipt.extension_ids,
            browsers: receipt.browsers,
            native_host_path: Some(receipt.native_host_path),
            ca_installed,
        })
    }

    /// Installs a new copy, or performs an idempotent repair when a receipt is
    /// already present.
    pub fn install(&self, request: InstallRequest) -> Result<OperationReport, SetupError> {
        self.apply(request, OperationKind::InstallOrRepair)
    }

    /// Explicit repair entry point for CLI/GUI callers. It also recovers a
    /// fail-closed partial installation for which no receipt was committed.
    pub fn repair(&self, request: InstallRequest) -> Result<OperationReport, SetupError> {
        self.apply(request, OperationKind::Repair)
    }

    pub fn uninstall(&self) -> Result<OperationReport, SetupError> {
        let layout = InstallLayout::from_environment()?;
        // Validate before making *any* mutation. A malicious or accidental
        // install-root override must never turn uninstall into a broad purge.
        ensure_safe_root(&layout.install_root, &layout.protected_roots)?;
        validate_existing_ancestors_no_redirect(&layout.install_root, "install-root ancestor")?;
        reject_symlink(&layout.install_root, "install root")?;

        let receipt = read_receipt(&layout)?;
        if let Some(receipt) = &receipt {
            validate_receipt(receipt, &layout)?;
        }
        let transaction = read_transaction(&layout)?;
        if let (Some(receipt), Some(transaction)) = (&receipt, &transaction)
            && receipt.trust_store != transaction.trust_store
        {
            return Err(operation(
                "receipt and pre-trust transaction disagree about the owned trust store",
            ));
        }

        let mut details = Vec::new();
        let ownership = collect_ownership(&layout, receipt.as_ref(), transaction.as_ref())?;
        remove_owned_registrations(&layout, &ownership, &mut details)?;
        remove_owned_legacy_extension_loaders(&layout, &mut details)?;
        if layout.install_root.exists() && receipt.is_none() && transaction.is_none() {
            return Err(operation(format!(
                "refusing recursive removal of {} without a valid ownership receipt or pre-trust transaction; the install root and trust state were left untouched after exact-registration cleanup",
                layout.install_root.display()
            )));
        }

        let mut sha1_fingerprints = receipt
            .as_ref()
            .map(|value| value.owned_certificate_sha1s.clone())
            .unwrap_or_default();
        let mut sha256_fingerprints = receipt
            .as_ref()
            .map(|value| value.owned_certificate_sha256s.clone())
            .unwrap_or_default();
        if let Some(transaction) = &transaction {
            for fingerprint in &transaction.owned_certificate_sha1s {
                push_unique(&mut sha1_fingerprints, fingerprint.clone());
            }
            for fingerprint in &transaction.owned_certificate_sha256s {
                push_unique(&mut sha256_fingerprints, fingerprint.clone());
            }
        }
        let trust_store = transaction
            .as_ref()
            .map(|value| &value.trust_store)
            .or_else(|| receipt.as_ref().map(|value| &value.trust_store));

        if trusted_installed_host(
            &self.payload,
            &layout,
            receipt.as_ref(),
            transaction.as_ref(),
        )? && layout.ca_bundle_path.is_file()
        {
            validate_ca_storage(&layout, false)?;
            let ca = invoke_ca_info(&layout.installed_host, &layout.data_dir)?;
            validate_ca_storage(&layout, false)?;
            validate_ca_info(&ca, &layout)?;
            push_unique(&mut sha1_fingerprints, ca.certificate_sha1);
            push_unique(&mut sha256_fingerprints, ca.certificate_sha256);
            invoke_native_utility(
                &layout.installed_host,
                &[
                    OsString::from("--data-dir"),
                    layout.data_dir.as_os_str().to_os_string(),
                    OsString::from("--clear-ca-installed"),
                ],
                "clear the local-CA installation marker",
            )?;
            details.push("Cleared the native host's local-CA installation marker.".to_owned());
        } else if layout.installed_host.exists() {
            details.push(
                "Skipped executing an installed native host whose ownership could not be verified."
                    .to_owned(),
            );
        }

        if let Some(trust_store) = trust_store {
            remove_trust_anchors(
                &layout,
                trust_store,
                &sha1_fingerprints,
                &sha256_fingerprints,
                &mut details,
            )?;
        } else if !sha1_fingerprints.is_empty() || !sha256_fingerprints.is_empty() {
            return Err(operation(
                "owned CA fingerprints exist without a validated trust-store record",
            ));
        }

        remove_install_root_recursively(
            &layout.install_root,
            &layout.protected_roots,
            receipt.is_some() || transaction.is_some(),
            &mut details,
        )?;

        let status = empty_status();
        Ok(OperationReport {
            summary:
                "Removed the HNS DANE Browser native host, trust anchor, registrations, and data."
                    .to_owned(),
            details,
            status,
        })
    }

    fn apply(
        &self,
        request: InstallRequest,
        operation_kind: OperationKind,
    ) -> Result<OperationReport, SetupError> {
        let request = normalize_request(request)?;
        let layout = InstallLayout::from_environment()?;
        ensure_safe_root(&layout.install_root, &layout.protected_roots)?;
        validate_existing_ancestors_no_redirect(&layout.install_root, "install-root ancestor")?;
        reject_symlink(&layout.install_root, "install root")?;

        let prior_receipt = read_receipt(&layout)?;
        if let Some(receipt) = &prior_receipt {
            validate_receipt(receipt, &layout)?;
        }
        let prior_transaction = read_transaction(&layout)?;
        if let (Some(receipt), Some(transaction)) = (&prior_receipt, &prior_transaction)
            && receipt.trust_store != transaction.trust_store
        {
            return Err(operation(
                "receipt and pre-trust transaction disagree about the owned trust store",
            ));
        }

        let payload = self.payload.read().map_err(|error| {
            let source = self
                .payload
                .source_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "embedded release payload".to_owned());
            operation(format!(
                "unable to read native-host payload ({source}): {error}"
            ))
        })?;
        if payload.is_empty() {
            return Err(operation("the native-host payload is empty"));
        }
        let native_host_sha256 = sha256_hex(&payload);

        prepare_install_directories(&layout)?;
        atomic_write(&layout.installed_host, &payload, FileMode::Executable)?;
        atomic_write(
            &layout.product_license,
            PRODUCT_LICENSE.as_bytes(),
            FileMode::Public,
        )?;
        atomic_write(
            &layout.third_party_notices,
            THIRD_PARTY_NOTICES.as_bytes(),
            FileMode::Public,
        )?;

        let canonical_host = fs::canonicalize(&layout.installed_host).map_err(|error| {
            operation(format!(
                "unable to resolve installed native host {}: {error}",
                layout.installed_host.display()
            ))
        })?;
        let manifest_bytes = invoke_host_manifest(&layout.installed_host, &request.extension_ids)?;
        validate_host_manifest(&manifest_bytes, &canonical_host, &request.extension_ids)?;
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        atomic_write(&layout.manifest_path, &manifest_bytes, FileMode::Private)?;

        let owned_manifest_sha256s = merge_owned_hashes(
            prior_receipt
                .as_ref()
                .map(|receipt| receipt.owned_manifest_sha256s.as_slice()),
            prior_transaction
                .as_ref()
                .map(|transaction| transaction.owned_manifest_sha256s.as_slice()),
            manifest_sha256.clone(),
        );
        let allow_legacy_manifest_migration =
            prior_receipt.is_none() && prior_transaction.is_none();

        let mut details = vec![
            format!(
                "Installed the version {VERSION} native host atomically at {} (SHA-256 {}).",
                layout.installed_host.display(),
                native_host_sha256
            ),
            format!(
                "Authorized extension ID{}: {}.",
                if request.extension_ids.len() == 1 {
                    ""
                } else {
                    "s"
                },
                request.extension_ids.join(", ")
            ),
        ];
        write_selected_registrations(
            &layout,
            &request.browsers,
            &manifest_bytes,
            &owned_manifest_sha256s,
            &canonical_host,
            allow_legacy_manifest_migration,
            &mut details,
        )?;

        validate_ca_storage(&layout, true)?;
        let ca = invoke_ca_info(&layout.installed_host, &layout.data_dir)?;
        validate_ca_storage(&layout, false)?;
        validate_ca_info(&ca, &layout)?;
        let trust_store = prior_transaction
            .as_ref()
            .map(|transaction| transaction.trust_store.clone())
            .or_else(|| {
                prior_receipt
                    .as_ref()
                    .map(|receipt| receipt.trust_store.clone())
            })
            .map(Ok)
            .unwrap_or_else(|| resolve_trust_store(&layout))?;
        validate_trust_store(&trust_store, &layout)?;
        let owned_certificate_sha1s = merge_owned_hashes(
            prior_receipt
                .as_ref()
                .map(|receipt| receipt.owned_certificate_sha1s.as_slice()),
            prior_transaction
                .as_ref()
                .map(|transaction| transaction.owned_certificate_sha1s.as_slice()),
            ca.certificate_sha1.clone(),
        );
        let owned_certificate_sha256s = merge_owned_hashes(
            prior_receipt
                .as_ref()
                .map(|receipt| receipt.owned_certificate_sha256s.as_slice()),
            prior_transaction
                .as_ref()
                .map(|transaction| transaction.owned_certificate_sha256s.as_slice()),
            ca.certificate_sha256.clone(),
        );
        let transaction = InstallationTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            product: NATIVE_HOST_NAME.to_owned(),
            version: VERSION.to_owned(),
            extension_ids: request.extension_ids.clone(),
            browsers: request.browsers.clone(),
            native_host_path: canonical_host.clone(),
            native_host_sha256: native_host_sha256.clone(),
            manifest_path: layout.manifest_path.clone(),
            manifest_sha256: manifest_sha256.clone(),
            owned_manifest_sha256s: owned_manifest_sha256s.clone(),
            certificate_path: ca.certificate_path.clone(),
            certificate_sha1: ca.certificate_sha1.clone(),
            certificate_sha256: ca.certificate_sha256.clone(),
            owned_certificate_sha1s: owned_certificate_sha1s.clone(),
            owned_certificate_sha256s: owned_certificate_sha256s.clone(),
            trust_store: trust_store.clone(),
        };
        write_transaction(&layout, &transaction)?;
        details.push(format!(
            "Committed a pre-trust ownership transaction at {}.",
            layout.transaction_path.display()
        ));
        let snapshot = install_header_snapshot_payload(
            &self.header_snapshot,
            &layout.installed_host,
            &layout.data_dir,
        )?;
        details.push(format!(
            "Verified and installed the bundled mainnet header snapshot through height {} (native status {}, best height {}).",
            HEADER_SNAPSHOT_TARGET_HEIGHT,
            snapshot.status,
            snapshot.best_height
        ));
        install_trust_anchor(&layout, &ca, &trust_store, &mut details)?;

        invoke_native_utility(
            &layout.installed_host,
            &[
                OsString::from("--data-dir"),
                layout.data_dir.as_os_str().to_os_string(),
                OsString::from("--mark-ca-installed"),
            ],
            "mark the local CA installed",
        )?;
        let marked_ca = invoke_ca_info(&layout.installed_host, &layout.data_dir)?;
        validate_ca_info(&marked_ca, &layout)?;
        if marked_ca.state != "installed"
            || marked_ca.certificate_sha1 != ca.certificate_sha1
            || marked_ca.certificate_sha256 != ca.certificate_sha256
        {
            return Err(operation(
                "native host did not confirm the installed local-CA marker",
            ));
        }
        details.push(format!(
            "Installed and marked the per-user local CA (SHA-256 {}).",
            ca.certificate_sha256
        ));

        let receipt = InstallationReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            product: NATIVE_HOST_NAME.to_owned(),
            version: VERSION.to_owned(),
            extension_ids: request.extension_ids.clone(),
            browsers: request.browsers.clone(),
            native_host_path: canonical_host.clone(),
            native_host_sha256,
            manifest_path: layout.manifest_path.clone(),
            manifest_sha256,
            owned_manifest_sha256s,
            certificate_path: ca.certificate_path.clone(),
            certificate_sha1: ca.certificate_sha1.clone(),
            certificate_sha256: ca.certificate_sha256.clone(),
            owned_certificate_sha1s,
            owned_certificate_sha256s,
            trust_store,
        };
        write_receipt(&layout, &receipt)?;
        details.push(format!(
            "Committed the ownership receipt atomically at {}.",
            layout.receipt_path.display()
        ));
        clear_transaction(&layout)?;
        details.push("Cleared the completed pre-trust transaction.".to_owned());

        remove_unselected_registrations(&layout, &receipt, &mut details)?;
        remove_stale_trust_anchors(&layout, &receipt, &mut details)?;
        remove_owned_legacy_extension_loaders(&layout, &mut details)?;

        let status = self.inspect()?;
        if !status.installed {
            return Err(operation(
                "post-install validation did not confirm a complete installation",
            ));
        }

        let repaired = prior_receipt.is_some() || matches!(operation_kind, OperationKind::Repair);
        Ok(OperationReport {
            summary: if repaired {
                format!(
                    "Repaired HNS DANE Browser {VERSION} for {}.",
                    browser_labels(&request.browsers)
                )
            } else {
                format!(
                    "Installed HNS DANE Browser {VERSION} for {}.",
                    browser_labels(&request.browsers)
                )
            },
            details,
            status,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum OperationKind {
    InstallOrRepair,
    Repair,
}

#[derive(Debug)]
struct NormalizedRequest {
    extension_ids: Vec<String>,
    browsers: BTreeSet<Browser>,
}

fn normalize_request(request: InstallRequest) -> Result<NormalizedRequest, SetupError> {
    if request.browsers.is_empty() {
        return Err(SetupError::NoBrowsers);
    }
    if request.extension_ids.is_empty() {
        return Err(operation("at least one Chromium extension ID is required"));
    }
    let mut ids = BTreeSet::new();
    for id in request.extension_ids {
        validate_extension_id(&id)?;
        ids.insert(id);
    }
    if ids.len() > MAX_EXTENSION_IDS {
        return Err(operation(format!(
            "at most {MAX_EXTENSION_IDS} Chromium extension IDs may be registered"
        )));
    }
    Ok(NormalizedRequest {
        extension_ids: ids.into_iter().collect(),
        browsers: request.browsers,
    })
}

#[derive(Debug, Clone)]
struct InstallLayout {
    install_root: PathBuf,
    data_dir: PathBuf,
    installed_host: PathBuf,
    manifest_path: PathBuf,
    receipt_path: PathBuf,
    transaction_path: PathBuf,
    product_license: PathBuf,
    third_party_notices: PathBuf,
    ca_bundle_path: PathBuf,
    ca_directory: PathBuf,
    certificate_path: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    config_home: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    profile_home: PathBuf,
    #[cfg(target_os = "linux")]
    user_data_home: PathBuf,
    protected_roots: Vec<PathBuf>,
}

impl InstallLayout {
    fn from_environment() -> Result<Self, SetupError> {
        #[cfg(target_os = "linux")]
        {
            let profile_home = required_environment_path("HOME")?;
            let config_home = optional_environment_path("XDG_CONFIG_HOME")?
                .unwrap_or_else(|| profile_home.join(".config"));
            let data_home = optional_environment_path("XDG_DATA_HOME")?
                .unwrap_or_else(|| profile_home.join(".local").join("share"));
            let install_root = data_home.join("hns-dane-browser").join("chromium");
            return Self::new(
                install_root,
                Some(config_home.clone()),
                profile_home.clone(),
                Some(data_home.clone()),
                vec![profile_home, config_home, data_home],
            );
        }

        #[cfg(target_os = "macos")]
        {
            let profile_home = required_environment_path("HOME")?;
            let config_home = profile_home.join("Library").join("Application Support");
            let install_root = config_home.join("HnsDaneBrowser").join("Chromium");
            return Self::new(
                install_root,
                Some(config_home.clone()),
                profile_home.clone(),
                None,
                vec![profile_home, config_home],
            );
        }

        #[cfg(target_os = "windows")]
        {
            let profile_home = required_environment_path("USERPROFILE")?;
            let local_app_data = required_environment_path("LOCALAPPDATA")?;
            let install_root = local_app_data.join("HnsDaneBrowser").join("Chromium");
            return Self::new(
                install_root,
                None,
                profile_home.clone(),
                None,
                vec![profile_home, local_app_data],
            );
        }

        #[allow(unreachable_code)]
        Err(operation(
            "this setup program supports Linux, macOS, and Windows only",
        ))
    }

    fn new(
        install_root: PathBuf,
        config_home: Option<PathBuf>,
        profile_home: PathBuf,
        user_data_home: Option<PathBuf>,
        protected_roots: Vec<PathBuf>,
    ) -> Result<Self, SetupError> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = &config_home;
        #[cfg(not(target_os = "linux"))]
        let _ = &profile_home;
        #[cfg(not(target_os = "linux"))]
        let _ = &user_data_home;
        let install_root = make_absolute(install_root)?;
        let data_dir = install_root.join("data");
        let ca_directory = data_dir.join("chromium-ca");
        let installed_host = install_root.join("bin").join(NATIVE_HOST_FILE_NAME);
        let manifest_path = install_root.join(format!("{NATIVE_HOST_NAME}.json"));
        let receipt_path = install_root.join(RECEIPT_FILE_NAME);
        let transaction_path = install_root.join(TRANSACTION_FILE_NAME);
        let license_directory = install_root.join("licenses");
        Ok(Self {
            ca_bundle_path: ca_directory.join("ca-bundle.json"),
            certificate_path: ca_directory.join("hns-dane-browser-local-ca.pem"),
            ca_directory,
            data_dir,
            installed_host,
            manifest_path,
            receipt_path,
            transaction_path,
            product_license: license_directory.join("LICENSE"),
            third_party_notices: license_directory.join("THIRD_PARTY_NOTICES.txt"),
            install_root,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            config_home,
            #[cfg(target_os = "linux")]
            profile_home,
            #[cfg(target_os = "linux")]
            user_data_home: user_data_home
                .ok_or_else(|| operation("Linux user data home is unavailable"))?,
            protected_roots,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallationReceipt {
    schema_version: u32,
    product: String,
    version: String,
    extension_ids: Vec<String>,
    browsers: BTreeSet<Browser>,
    native_host_path: PathBuf,
    native_host_sha256: String,
    manifest_path: PathBuf,
    manifest_sha256: String,
    owned_manifest_sha256s: Vec<String>,
    certificate_path: PathBuf,
    certificate_sha1: String,
    certificate_sha256: String,
    owned_certificate_sha1s: Vec<String>,
    owned_certificate_sha256s: Vec<String>,
    trust_store: TrustStoreReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum TrustStoreReceipt {
    LinuxNss { database_path: PathBuf },
    MacosLoginKeychain { keychain_path: PathBuf },
    WindowsUserRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallationTransaction {
    schema_version: u32,
    product: String,
    version: String,
    extension_ids: Vec<String>,
    browsers: BTreeSet<Browser>,
    native_host_path: PathBuf,
    native_host_sha256: String,
    manifest_path: PathBuf,
    manifest_sha256: String,
    owned_manifest_sha256s: Vec<String>,
    certificate_path: PathBuf,
    certificate_sha1: String,
    certificate_sha256: String,
    owned_certificate_sha1s: Vec<String>,
    owned_certificate_sha256s: Vec<String>,
    trust_store: TrustStoreReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeHostManifest {
    name: String,
    description: String,
    path: PathBuf,
    #[serde(rename = "type")]
    kind: String,
    allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaInfo {
    schema_version: u32,
    state: String,
    certificate_path: PathBuf,
    certificate_sha1: String,
    certificate_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeaderSnapshotInstallInfo {
    network: String,
    status: String,
    best_height: u32,
    error: Option<String>,
}

fn prepare_install_directories(layout: &InstallLayout) -> Result<(), SetupError> {
    ensure_directory(&layout.install_root, true)?;
    ensure_directory(&layout.install_root.join("bin"), true)?;
    ensure_directory(&layout.install_root.join("licenses"), true)?;
    ensure_directory(&layout.data_dir, true)?;
    Ok(())
}

fn validate_ca_storage(layout: &InstallLayout, create: bool) -> Result<(), SetupError> {
    if layout.ca_directory.parent() != Some(layout.data_dir.as_path())
        || layout.ca_bundle_path.parent() != Some(layout.ca_directory.as_path())
        || layout.certificate_path.parent() != Some(layout.ca_directory.as_path())
    {
        return Err(operation(
            "local-CA paths are not lexically contained by the install data directory",
        ));
    }

    validate_existing_ancestors_no_redirect(&layout.data_dir, "local-CA data ancestor")?;
    validate_existing_ancestors_no_redirect(&layout.ca_directory, "local-CA directory ancestor")?;
    if create {
        ensure_directory(&layout.data_dir, true)?;
        ensure_directory(&layout.ca_directory, true)?;
    } else if !layout.data_dir.is_dir() || !layout.ca_directory.is_dir() {
        return Err(operation(
            "local-CA data directory is missing or is not a directory",
        ));
    }
    reject_symlink(&layout.data_dir, "local-CA data directory")?;
    reject_symlink(&layout.ca_directory, "local-CA directory")?;

    let canonical_data = fs::canonicalize(&layout.data_dir).map_err(|error| {
        operation(format!(
            "unable to resolve local-CA data directory {}: {error}",
            layout.data_dir.display()
        ))
    })?;
    let canonical_ca = fs::canonicalize(&layout.ca_directory).map_err(|error| {
        operation(format!(
            "unable to resolve local-CA directory {}: {error}",
            layout.ca_directory.display()
        ))
    })?;
    if canonical_ca.parent() != Some(canonical_data.as_path()) {
        return Err(operation(
            "resolved local-CA directory escapes the install data directory",
        ));
    }

    for path in [&layout.ca_bundle_path, &layout.certificate_path] {
        if !path.exists() {
            continue;
        }
        reject_symlink(path, "local-CA file")?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            operation(format!(
                "unable to inspect local-CA file {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(operation(format!(
                "local-CA path is not a regular file: {}",
                path.display()
            )));
        }
        let canonical = fs::canonicalize(path).map_err(|error| {
            operation(format!(
                "unable to resolve local-CA file {}: {error}",
                path.display()
            ))
        })?;
        if canonical.parent() != Some(canonical_ca.as_path()) {
            return Err(operation(format!(
                "resolved local-CA file escapes its owned directory: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_receipt(layout: &InstallLayout) -> Result<Option<InstallationReceipt>, SetupError> {
    let Some(bytes) = read_regular_file_if_present(&layout.receipt_path, MAX_JSON_BYTES)? else {
        return Ok(None);
    };
    let receipt: InstallationReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        operation(format!(
            "invalid installation receipt {}: {error}",
            layout.receipt_path.display()
        ))
    })?;
    validate_receipt(&receipt, layout)?;
    Ok(Some(receipt))
}

fn validate_receipt(
    receipt: &InstallationReceipt,
    layout: &InstallLayout,
) -> Result<(), SetupError> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(operation(format!(
            "unsupported installation receipt schema {}",
            receipt.schema_version
        )));
    }
    if receipt.product != NATIVE_HOST_NAME {
        return Err(operation(
            "installation receipt has the wrong product identity",
        ));
    }
    if receipt.version.is_empty() || receipt.version.len() > 128 {
        return Err(operation("installation receipt has an invalid version"));
    }
    if receipt.extension_ids.is_empty() || receipt.extension_ids.len() > MAX_EXTENSION_IDS {
        return Err(operation(
            "installation receipt has an invalid extension-ID count",
        ));
    }
    let mut normalized_ids = receipt.extension_ids.clone();
    for id in &normalized_ids {
        validate_extension_id(id)?;
    }
    normalized_ids.sort();
    normalized_ids.dedup();
    if normalized_ids != receipt.extension_ids {
        return Err(operation(
            "installation receipt extension IDs are not canonical and unique",
        ));
    }
    if receipt.browsers.is_empty() {
        return Err(operation("installation receipt selects no browsers"));
    }
    if !paths_equivalent_or_lexical(&receipt.native_host_path, &layout.installed_host)
        || !paths_equivalent_or_lexical(&receipt.manifest_path, &layout.manifest_path)
        || !paths_equivalent_or_lexical(&receipt.certificate_path, &layout.certificate_path)
    {
        return Err(operation(
            "installation receipt paths do not belong to this per-user install root",
        ));
    }
    if !is_lower_hex(&receipt.native_host_sha256, 64)
        || !is_lower_hex(&receipt.manifest_sha256, 64)
        || !is_lower_hex(&receipt.certificate_sha1, 40)
        || !is_lower_hex(&receipt.certificate_sha256, 64)
    {
        return Err(operation(
            "installation receipt contains an invalid fingerprint",
        ));
    }
    validate_hash_history(
        &receipt.owned_manifest_sha256s,
        64,
        &receipt.manifest_sha256,
        "native-host manifest",
    )?;
    validate_hash_history(
        &receipt.owned_certificate_sha1s,
        40,
        &receipt.certificate_sha1,
        "certificate SHA-1",
    )?;
    validate_hash_history(
        &receipt.owned_certificate_sha256s,
        64,
        &receipt.certificate_sha256,
        "certificate SHA-256",
    )?;
    validate_trust_store(&receipt.trust_store, layout)?;
    Ok(())
}

fn validate_trust_store(
    trust_store: &TrustStoreReceipt,
    _layout: &InstallLayout,
) -> Result<(), SetupError> {
    #[cfg(target_os = "linux")]
    {
        let TrustStoreReceipt::LinuxNss { database_path } = trust_store else {
            return Err(operation(
                "ownership record selected a non-Linux trust store",
            ));
        };
        return validate_linux_nss_database(_layout, database_path);
    }

    #[cfg(target_os = "macos")]
    {
        let TrustStoreReceipt::MacosLoginKeychain { keychain_path } = trust_store else {
            return Err(operation(
                "ownership record selected a non-macOS trust store",
            ));
        };
        if !keychain_path.is_absolute()
            || keychain_path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(operation(
                "ownership record contains an unsafe login-keychain path",
            ));
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        if !matches!(trust_store, TrustStoreReceipt::WindowsUserRoot) {
            return Err(operation(
                "ownership record selected a non-Windows trust store",
            ));
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(operation("unsupported trust-store platform"))
}

fn read_transaction(layout: &InstallLayout) -> Result<Option<InstallationTransaction>, SetupError> {
    let Some(bytes) = read_regular_file_if_present(&layout.transaction_path, MAX_JSON_BYTES)?
    else {
        return Ok(None);
    };
    let transaction: InstallationTransaction = serde_json::from_slice(&bytes).map_err(|error| {
        operation(format!(
            "invalid installation transaction {}: {error}",
            layout.transaction_path.display()
        ))
    })?;
    validate_transaction(&transaction, layout)?;
    Ok(Some(transaction))
}

fn validate_transaction(
    transaction: &InstallationTransaction,
    layout: &InstallLayout,
) -> Result<(), SetupError> {
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.product != NATIVE_HOST_NAME
        || transaction.version.is_empty()
        || transaction.version.len() > 128
        || transaction.extension_ids.is_empty()
        || transaction.extension_ids.len() > MAX_EXTENSION_IDS
        || transaction.browsers.is_empty()
    {
        return Err(operation(
            "installation transaction has invalid identity metadata",
        ));
    }
    let mut normalized_ids = transaction.extension_ids.clone();
    for id in &normalized_ids {
        validate_extension_id(id)?;
    }
    normalized_ids.sort();
    normalized_ids.dedup();
    if normalized_ids != transaction.extension_ids {
        return Err(operation(
            "installation transaction extension IDs are not canonical and unique",
        ));
    }
    if !paths_equivalent_or_lexical(&transaction.native_host_path, &layout.installed_host)
        || !paths_equivalent_or_lexical(&transaction.manifest_path, &layout.manifest_path)
        || !paths_equivalent_or_lexical(&transaction.certificate_path, &layout.certificate_path)
        || !is_lower_hex(&transaction.native_host_sha256, 64)
        || !is_lower_hex(&transaction.manifest_sha256, 64)
        || !is_lower_hex(&transaction.certificate_sha1, 40)
        || !is_lower_hex(&transaction.certificate_sha256, 64)
    {
        return Err(operation(
            "installation transaction contains unsafe paths or fingerprints",
        ));
    }
    validate_hash_history(
        &transaction.owned_manifest_sha256s,
        64,
        &transaction.manifest_sha256,
        "native-host manifest",
    )?;
    validate_hash_history(
        &transaction.owned_certificate_sha1s,
        40,
        &transaction.certificate_sha1,
        "certificate SHA-1",
    )?;
    validate_hash_history(
        &transaction.owned_certificate_sha256s,
        64,
        &transaction.certificate_sha256,
        "certificate SHA-256",
    )?;
    validate_trust_store(&transaction.trust_store, layout)
}

fn write_transaction(
    layout: &InstallLayout,
    transaction: &InstallationTransaction,
) -> Result<(), SetupError> {
    let mut bytes = serde_json::to_vec_pretty(transaction)?;
    bytes.push(b'\n');
    atomic_write(&layout.transaction_path, &bytes, FileMode::Private)
}

fn clear_transaction(layout: &InstallLayout) -> Result<(), SetupError> {
    match fs::remove_file(&layout.transaction_path) {
        Ok(()) => {
            if let Some(parent) = layout.transaction_path.parent() {
                sync_parent_directory(parent).map_err(|error| {
                    operation(format!(
                        "unable to sync transaction removal in {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(operation(format!(
            "unable to remove completed installation transaction {}: {error}",
            layout.transaction_path.display()
        ))),
    }
}

fn validate_hash_history(
    values: &[String],
    length: usize,
    current: &str,
    label: &str,
) -> Result<(), SetupError> {
    if values.is_empty()
        || !values.iter().all(|value| is_lower_hex(value, length))
        || !values.iter().any(|value| value == current)
    {
        return Err(operation(format!(
            "ownership record has invalid {label} history"
        )));
    }
    let mut unique = values.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != values.len() {
        return Err(operation(format!(
            "ownership record has duplicate {label} history"
        )));
    }
    Ok(())
}

fn write_receipt(layout: &InstallLayout, receipt: &InstallationReceipt) -> Result<(), SetupError> {
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    atomic_write(&layout.receipt_path, &bytes, FileMode::Private)
}

fn invoke_host_manifest(host: &Path, extension_ids: &[String]) -> Result<Vec<u8>, SetupError> {
    let mut arguments = vec![OsString::from("--print-host-manifest")];
    for extension_id in extension_ids {
        arguments.push(OsString::from("--extension-id"));
        arguments.push(OsString::from(extension_id));
    }
    let output = invoke_native_utility(host, &arguments, "produce its registration manifest")?;
    if output.stdout.is_empty() || output.stdout.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(operation(
            "native host produced an empty or oversized registration manifest",
        ));
    }
    Ok(output.stdout)
}

fn invoke_ca_info(host: &Path, data_dir: &Path) -> Result<CaInfo, SetupError> {
    let output = invoke_native_utility(
        host,
        &[
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_os_string(),
            OsString::from("--ca-info"),
        ],
        "report local-CA metadata",
    )?;
    if output.stdout.is_empty() || output.stdout.len() as u64 > MAX_JSON_BYTES {
        return Err(operation(
            "native host produced empty or oversized local-CA metadata",
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        operation(format!(
            "native host returned invalid local-CA JSON: {error}"
        ))
    })
}

fn install_header_snapshot_payload(
    payload: &HeaderSnapshotPayload,
    host: &Path,
    data_dir: &Path,
) -> Result<HeaderSnapshotInstallInfo, SetupError> {
    let compressed = payload.read().map_err(|error| {
        let source = payload
            .source_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "embedded release snapshot".to_owned());
        operation(format!(
            "unable to read bundled header snapshot ({source}): {error}"
        ))
    })?;
    install_header_snapshot_bytes(&compressed, host, data_dir, BUNDLED_HEADER_SNAPSHOT)
}

fn install_header_snapshot_bytes(
    compressed: &[u8],
    host: &Path,
    data_dir: &Path,
    integrity: SnapshotIntegrity<'_>,
) -> Result<HeaderSnapshotInstallInfo, SetupError> {
    let compressed_bytes = u64::try_from(compressed.len())
        .map_err(|_| operation("bundled header snapshot length does not fit in u64"))?;
    if compressed_bytes != integrity.compressed_bytes {
        return Err(operation(format!(
            "bundled header snapshot compressed size mismatch: got {compressed_bytes}, expected {}",
            integrity.compressed_bytes
        )));
    }
    let compressed_sha256 = sha256_hex(compressed);
    if compressed_sha256 != integrity.compressed_sha256 {
        return Err(operation(format!(
            "bundled header snapshot compressed SHA-256 mismatch: got {compressed_sha256}, expected {}",
            integrity.compressed_sha256
        )));
    }

    let (temporary_path, temporary_file) = create_temporary_snapshot(data_dir)?;
    let install_result = (|| {
        decompress_header_snapshot(compressed, temporary_file, integrity)?;
        invoke_header_snapshot_install(host, data_dir, &temporary_path, integrity.target_height)
    })();
    let cleanup_result = fs::remove_file(&temporary_path);

    match (install_result, cleanup_result) {
        (Ok(status), Ok(())) => Ok(status),
        (Ok(_), Err(error)) => Err(operation(format!(
            "unable to remove temporary header snapshot {}: {error}",
            temporary_path.display()
        ))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(operation(format!(
            "{error}; additionally unable to remove temporary header snapshot {}: {cleanup_error}",
            temporary_path.display()
        ))),
    }
}

fn create_temporary_snapshot(data_dir: &Path) -> Result<(PathBuf, File), SetupError> {
    validate_existing_ancestors_no_redirect(data_dir, "header-snapshot data ancestor")?;
    ensure_directory(data_dir, true)?;
    validate_existing_ancestors_no_redirect(data_dir, "header-snapshot data ancestor")?;
    reject_symlink(data_dir, "header-snapshot data directory")?;

    for _ in 0..100 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = data_dir.join(format!(
            ".hns-headers-{}-{}.snapshot.tmp",
            std::process::id(),
            sequence
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                return Ok((candidate, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(operation(format!(
                    "unable to create temporary header snapshot in {}: {error}",
                    data_dir.display()
                )));
            }
        }
    }

    Err(operation(format!(
        "unable to allocate a unique temporary header snapshot in {}",
        data_dir.display()
    )))
}

fn decompress_header_snapshot(
    compressed: &[u8],
    mut destination: File,
    integrity: SnapshotIntegrity<'_>,
) -> Result<(), SetupError> {
    let mut decoder = GzDecoder::new(compressed);
    let mut hasher = Sha256::new();
    let mut uncompressed_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = decoder.read(&mut buffer).map_err(|error| {
            operation(format!(
                "unable to decompress bundled header snapshot: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        let next_size = uncompressed_bytes
            .checked_add(read as u64)
            .ok_or_else(|| operation("bundled header snapshot decompressed size overflow"))?;
        if next_size > integrity.uncompressed_bytes {
            return Err(operation(format!(
                "bundled header snapshot decompressed size exceeds expected {} bytes",
                integrity.uncompressed_bytes
            )));
        }
        destination.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        uncompressed_bytes = next_size;
    }

    if uncompressed_bytes != integrity.uncompressed_bytes {
        return Err(operation(format!(
            "bundled header snapshot decompressed size mismatch: got {uncompressed_bytes}, expected {}",
            integrity.uncompressed_bytes
        )));
    }
    let uncompressed_sha256 = lower_hex(&hasher.finalize());
    if uncompressed_sha256 != integrity.uncompressed_sha256 {
        return Err(operation(format!(
            "bundled header snapshot decompressed SHA-256 mismatch: got {uncompressed_sha256}, expected {}",
            integrity.uncompressed_sha256
        )));
    }
    destination.sync_all().map_err(|error| {
        operation(format!(
            "unable to flush temporary header snapshot: {error}"
        ))
    })?;
    Ok(())
}

fn invoke_header_snapshot_install(
    host: &Path,
    data_dir: &Path,
    snapshot_path: &Path,
    target_height: u32,
) -> Result<HeaderSnapshotInstallInfo, SetupError> {
    let output = invoke_native_utility(
        host,
        &[
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_os_string(),
            OsString::from("--network"),
            OsString::from("mainnet"),
            OsString::from("--install-header-snapshot"),
            snapshot_path.as_os_str().to_os_string(),
        ],
        "install the bundled mainnet header snapshot",
    )?;
    if output.stdout.is_empty() || output.stdout.len() as u64 > MAX_JSON_BYTES {
        return Err(operation(
            "native host produced empty or oversized header-snapshot metadata",
        ));
    }
    let status: HeaderSnapshotInstallInfo =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            operation(format!(
                "native host returned invalid header-snapshot JSON: {error}"
            ))
        })?;
    if status.network != "mainnet"
        || !matches!(
            status.status.as_str(),
            "snapshot_imported" | "snapshot_present"
        )
        || status.best_height < target_height
        || status.error.is_some()
    {
        return Err(operation(format!(
            "native host did not confirm the mainnet header snapshot through height {target_height}"
        )));
    }
    Ok(status)
}

fn invoke_native_utility(
    host: &Path,
    arguments: &[OsString],
    purpose: &str,
) -> Result<Output, SetupError> {
    let output = Command::new(host)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            operation(format!(
                "unable to invoke native host {} to {purpose}: {error}",
                host.display()
            ))
        })?;
    if !output.status.success() {
        return Err(operation(format!(
            "native host failed to {purpose} ({}): {}",
            output.status,
            command_diagnostic(&output)
        )));
    }
    Ok(output)
}

fn validate_host_manifest(
    bytes: &[u8],
    expected_host: &Path,
    extension_ids: &[String],
) -> Result<(), SetupError> {
    let manifest: NativeHostManifest = serde_json::from_slice(bytes).map_err(|error| {
        operation(format!(
            "native host returned an invalid registration manifest: {error}"
        ))
    })?;
    let expected_origins = extension_ids
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect::<Vec<_>>();
    if manifest.name != NATIVE_HOST_NAME
        || manifest.description.is_empty()
        || manifest.kind != "stdio"
        || !paths_equivalent_or_lexical(&manifest.path, expected_host)
        || manifest.allowed_origins != expected_origins
    {
        return Err(operation(
            "native host registration manifest did not exactly match the requested identity",
        ));
    }
    Ok(())
}

fn validate_any_owned_host_manifest(bytes: &[u8], expected_host: &Path) -> Result<(), SetupError> {
    let manifest: NativeHostManifest = serde_json::from_slice(bytes)
        .map_err(|_| operation("registration is not a valid native-host manifest"))?;
    if manifest.name != NATIVE_HOST_NAME
        || manifest.description.is_empty()
        || manifest.kind != "stdio"
        || !paths_equivalent_or_lexical(&manifest.path, expected_host)
        || manifest.allowed_origins.is_empty()
        || manifest.allowed_origins.len() > MAX_EXTENSION_IDS
    {
        return Err(operation(
            "registration does not exactly identify this native host",
        ));
    }
    let mut ids = BTreeSet::new();
    for origin in &manifest.allowed_origins {
        let Some(id) = origin
            .strip_prefix("chrome-extension://")
            .and_then(|value| value.strip_suffix('/'))
        else {
            return Err(operation(
                "registration contains a non-extension allowed origin",
            ));
        };
        validate_extension_id(id)?;
        if !ids.insert(id) {
            return Err(operation("registration contains duplicate allowed origins"));
        }
    }
    Ok(())
}

fn validate_legacy_owned_host_manifest(
    bytes: &[u8],
    expected_host: &Path,
) -> Result<(), SetupError> {
    validate_any_owned_host_manifest(bytes, expected_host)?;
    let manifest: NativeHostManifest = serde_json::from_slice(bytes)
        .map_err(|_| operation("legacy registration is not a valid native-host manifest"))?;
    let canonical_origin = format!("chrome-extension://{CANONICAL_EXTENSION_ID}/");
    if manifest.description != "HNS DANE Browser Rust native host"
        || !manifest.allowed_origins.contains(&canonical_origin)
    {
        return Err(operation(
            "registration does not exactly match the legacy product identity",
        ));
    }
    Ok(())
}

fn validate_ca_info(ca: &CaInfo, layout: &InstallLayout) -> Result<(), SetupError> {
    if ca.schema_version != LOCAL_CA_SCHEMA_VERSION
        || !matches!(ca.state.as_str(), "installed" | "needsInstallation")
        || !is_lower_hex(&ca.certificate_sha1, 40)
        || !is_lower_hex(&ca.certificate_sha256, 64)
        || !paths_equivalent_or_lexical(&ca.certificate_path, &layout.certificate_path)
        || !ca.certificate_path.is_file()
    {
        return Err(operation("native host returned invalid local-CA metadata"));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn manifest_paths(
    layout: &InstallLayout,
    browsers: &BTreeSet<Browser>,
) -> Result<BTreeSet<PathBuf>, SetupError> {
    let config_home = layout
        .config_home
        .as_ref()
        .ok_or_else(|| operation("browser configuration home is unavailable"))?;
    let mut paths = BTreeSet::new();
    for browser in browsers {
        for relative in manifest_relative_directories(current_unix_platform(), *browser) {
            paths.insert(
                config_home
                    .join(relative)
                    .join("NativeMessagingHosts")
                    .join(format!("{NATIVE_HOST_NAME}.json")),
            );
        }
    }
    Ok(paths)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn all_manifest_paths(layout: &InstallLayout) -> Result<BTreeSet<PathBuf>, SetupError> {
    manifest_paths(layout, &Browser::ALL.into_iter().collect())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyExternalExtensionRegistration {
    external_crx: PathBuf,
    external_version: String,
}

#[cfg(target_os = "linux")]
fn remove_owned_legacy_extension_loaders(
    layout: &InstallLayout,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    let Some(config_home) = layout.config_home.as_ref() else {
        return Ok(());
    };
    let extension_root = layout.install_root.join("extension");

    let mut relative_directories = BTreeSet::new();
    for browser in Browser::ALL {
        relative_directories.extend(
            manifest_relative_directories(UnixPlatform::Linux, browser)
                .iter()
                .copied(),
        );
    }
    for relative in relative_directories {
        let registration = config_home
            .join(relative)
            .join("External Extensions")
            .join(format!("{CANONICAL_EXTENSION_ID}.json"));
        let Some(bytes) = read_regular_file_if_present(&registration, MAX_JSON_BYTES)? else {
            continue;
        };
        if !legacy_external_registration_is_owned(&bytes, &extension_root) {
            details.push(format!(
                "Left modified or foreign legacy extension registration untouched at {}.",
                registration.display()
            ));
            continue;
        }
        validate_existing_ancestors_no_redirect(
            &registration,
            "legacy external-extension registration ancestor",
        )?;
        reject_symlink(&registration, "legacy external-extension registration")?;
        fs::remove_file(&registration).map_err(|error| {
            operation(format!(
                "unable to remove owned legacy extension registration {}: {error}",
                registration.display()
            ))
        })?;
        details.push(format!(
            "Removed owned legacy external-extension registration {}.",
            registration.display()
        ));
        if let Some(parent) = registration.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    for (wrapper_name, browser_binary) in [
        ("chromium", "/usr/bin/chromium"),
        ("google-chrome", "/usr/bin/google-chrome"),
        ("google-chrome-stable", "/usr/bin/google-chrome-stable"),
        ("microsoft-edge", "/usr/bin/microsoft-edge"),
        ("brave-browser", "/usr/bin/brave-browser"),
        ("vivaldi", "/usr/bin/vivaldi"),
        ("opera", "/usr/bin/opera"),
    ] {
        let wrapper = layout
            .profile_home
            .join(".local")
            .join("bin")
            .join(wrapper_name);
        let Some(bytes) = read_regular_file_if_present(&wrapper, 16 * 1024)? else {
            continue;
        };
        if !legacy_browser_wrapper_is_owned(&bytes, browser_binary, &extension_root) {
            continue;
        }
        validate_existing_ancestors_no_redirect(&wrapper, "legacy browser wrapper ancestor")?;
        reject_symlink(&wrapper, "legacy browser wrapper")?;
        fs::remove_file(&wrapper).map_err(|error| {
            operation(format!(
                "unable to remove owned legacy browser wrapper {}: {error}",
                wrapper.display()
            ))
        })?;
        details.push(format!(
            "Removed owned legacy browser launch wrapper {}.",
            wrapper.display()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_owned_legacy_extension_loaders(
    _layout: &InstallLayout,
    _details: &mut Vec<String>,
) -> Result<(), SetupError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn legacy_external_registration_is_owned(bytes: &[u8], extension_root: &Path) -> bool {
    let Ok(registration) = serde_json::from_slice::<LegacyExternalExtensionRegistration>(bytes)
    else {
        return false;
    };
    registration.external_version.len() <= 32
        && !registration.external_version.is_empty()
        && registration
            .external_version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && legacy_extension_artifact(&registration.external_crx, extension_root, ".crx")
}

#[cfg(target_os = "linux")]
fn legacy_browser_wrapper_is_owned(
    bytes: &[u8],
    browser_binary: &str,
    extension_root: &Path,
) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    let lines = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 5
        || lines[0] != "#!/bin/sh"
        || lines[1] != format!("exec {browser_binary} \\")
        || lines[2] != "--disable-renderer-accessibility \\"
        || lines[4] != "\"$@\""
    {
        return false;
    }
    let Some(path) = lines[3]
        .strip_prefix("--load-extension=")
        .and_then(|line| line.strip_suffix(" \\"))
    else {
        return false;
    };
    legacy_extension_artifact(Path::new(path), extension_root, "")
}

#[cfg(target_os = "linux")]
fn legacy_extension_artifact(path: &Path, extension_root: &Path, required_suffix: &str) -> bool {
    if !path.is_absolute()
        || path.parent() != Some(extension_root)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name.starts_with("source-")
        && name.len() > "source-".len() + required_suffix.len()
        && name.ends_with(required_suffix)
        && name
            .strip_prefix("source-")
            .and_then(|value| value.strip_suffix(required_suffix))
            .is_some_and(|version| {
                version.len() <= 32
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos", test))]
enum UnixPlatform {
    Linux,
    Macos,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_unix_platform() -> UnixPlatform {
    if cfg!(target_os = "macos") {
        UnixPlatform::Macos
    } else {
        UnixPlatform::Linux
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn manifest_relative_directories(
    platform: UnixPlatform,
    browser: Browser,
) -> &'static [&'static str] {
    match (platform, browser) {
        (UnixPlatform::Linux, Browser::Chrome) => &["google-chrome"],
        (UnixPlatform::Linux, Browser::Chromium) => &["chromium"],
        (UnixPlatform::Linux, Browser::Edge) => &["microsoft-edge"],
        (UnixPlatform::Linux, Browser::Brave) => &["BraveSoftware/Brave-Browser"],
        (UnixPlatform::Linux, Browser::Vivaldi) => &["vivaldi"],
        (UnixPlatform::Linux, Browser::Opera) => &["opera", "google-chrome"],
        (UnixPlatform::Macos, Browser::Chrome) => &["Google/Chrome"],
        (UnixPlatform::Macos, Browser::Chromium) => &["Chromium"],
        (UnixPlatform::Macos, Browser::Edge) => &["Microsoft Edge"],
        (UnixPlatform::Macos, Browser::Brave) => &["BraveSoftware/Brave-Browser"],
        (UnixPlatform::Macos, Browser::Vivaldi) => &["Vivaldi"],
        (UnixPlatform::Macos, Browser::Opera) => &["com.operasoftware.Opera", "Google/Chrome"],
    }
}

#[cfg(target_os = "windows")]
fn registry_keys(browsers: &BTreeSet<Browser>) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for browser in browsers {
        let roots: &[&str] = match browser {
            Browser::Chrome => &[r"HKCU\Software\Google\Chrome\NativeMessagingHosts"],
            Browser::Chromium => &[r"HKCU\Software\Chromium\NativeMessagingHosts"],
            Browser::Edge => &[r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts"],
            Browser::Brave => &[
                r"HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
                r"HKCU\Software\Google\Chrome\NativeMessagingHosts",
            ],
            Browser::Vivaldi => &[
                r"HKCU\Software\Vivaldi\NativeMessagingHosts",
                r"HKCU\Software\Google\Chrome\NativeMessagingHosts",
            ],
            // Opera publishes the Google Chrome native-messaging contract.
            Browser::Opera => &[r"HKCU\Software\Google\Chrome\NativeMessagingHosts"],
        };
        for root in roots {
            keys.insert(format!(r"{root}\{NATIVE_HOST_NAME}"));
        }
    }
    keys
}

#[cfg(target_os = "windows")]
fn all_registry_keys() -> BTreeSet<String> {
    registry_keys(&Browser::ALL.into_iter().collect())
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsRegistryView {
    Registry32,
    Registry64,
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_REGISTRY_LOOKUP_ORDER: [WindowsRegistryView; 2] = [
    WindowsRegistryView::Registry32,
    WindowsRegistryView::Registry64,
];

#[cfg(any(target_os = "windows", test))]
impl WindowsRegistryView {
    const fn reg_argument(self) -> &'static str {
        match self {
            Self::Registry32 => "/reg:32",
            Self::Registry64 => "/reg:64",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Registry32 => "32-bit",
            Self::Registry64 => "64-bit",
        }
    }
}

fn write_selected_registrations(
    layout: &InstallLayout,
    browsers: &BTreeSet<Browser>,
    manifest_bytes: &[u8],
    owned_manifest_hashes: &[String],
    canonical_host: &Path,
    allow_legacy_manifest_migration: bool,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    #[cfg(target_os = "windows")]
    let _ = (
        manifest_bytes,
        owned_manifest_hashes,
        canonical_host,
        allow_legacy_manifest_migration,
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        for path in manifest_paths(layout, browsers)? {
            validate_existing_ancestors_no_redirect(&path, "native-messaging manifest ancestor")?;
            if let Some(existing) = read_regular_file_if_present(&path, MAX_MANIFEST_BYTES)? {
                let exactly_owned = owned_manifest_hashes.contains(&sha256_hex(&existing))
                    && validate_any_owned_host_manifest(&existing, canonical_host).is_ok();
                let migratable_legacy = allow_legacy_manifest_migration
                    && validate_legacy_owned_host_manifest(&existing, canonical_host).is_ok();
                if !exactly_owned && !migratable_legacy {
                    return Err(operation(format!(
                        "refusing to replace native-messaging manifest not exactly owned by this installation: {}",
                        path.display()
                    )));
                }
                if migratable_legacy && !exactly_owned {
                    details.push(format!(
                        "Migrated exact legacy native-messaging registration at {}.",
                        path.display()
                    ));
                }
            }
            let parent = path
                .parent()
                .ok_or_else(|| operation("native-messaging manifest has no parent directory"))?;
            ensure_directory(parent, true)?;
            validate_existing_ancestors_no_redirect(&path, "native-messaging manifest ancestor")?;
            atomic_write(&path, manifest_bytes, FileMode::Private)?;
            details.push(format!(
                "Registered native messaging at {}.",
                path.display()
            ));
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let registry = windows_system_tool("reg.exe")?;
        let manifest_value = path_to_registry_string(&layout.manifest_path)?;
        let keys = registry_keys(browsers);

        // Preflight every view before changing either one. Chromium checks the
        // 32-bit view first, so a foreign value there must never be masked by
        // writing only the 64-bit view.
        for key in &keys {
            for view in WINDOWS_REGISTRY_LOOKUP_ORDER {
                if let Some(existing) = query_registry_default(&registry, key, view)?
                    && !windows_path_strings_equal(&existing, &manifest_value)
                {
                    return Err(operation(format!(
                        "refusing to replace native-messaging registry value not owned by this installation: {key} ({})",
                        view.label()
                    )));
                }
            }
        }

        for key in keys {
            for view in WINDOWS_REGISTRY_LOOKUP_ORDER {
                require_command_success(
                    &registry,
                    &[
                        OsString::from("ADD"),
                        OsString::from(&key),
                        OsString::from("/ve"),
                        OsString::from("/t"),
                        OsString::from("REG_SZ"),
                        OsString::from("/d"),
                        OsString::from(&manifest_value),
                        OsString::from("/f"),
                        OsString::from(view.reg_argument()),
                    ],
                    "write the per-user native-messaging registry value",
                )?;
                details.push(format!(
                    "Registered native messaging in {key} ({} view).",
                    view.label()
                ));
            }
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(operation("unsupported registration platform"))
}

fn remove_unselected_registrations(
    layout: &InstallLayout,
    receipt: &InstallationReceipt,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let selected = manifest_paths(layout, &receipt.browsers)?;
        for path in all_manifest_paths(layout)? {
            if selected.contains(&path) {
                continue;
            }
            remove_owned_manifest_file(
                &path,
                &receipt.owned_manifest_sha256s,
                &receipt.native_host_path,
                details,
            )?;
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let selected = registry_keys(&receipt.browsers);
        let registry = windows_system_tool("reg.exe")?;
        let expected = path_to_registry_string(&layout.manifest_path)?;
        for key in all_registry_keys() {
            if selected.contains(&key) {
                continue;
            }
            for view in WINDOWS_REGISTRY_LOOKUP_ORDER {
                remove_owned_registry_key(&registry, &key, &expected, view, details)?;
            }
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[derive(Debug)]
#[cfg_attr(target_os = "windows", allow(dead_code))]
struct RegistrationOwnership {
    manifest_hashes: Vec<String>,
    native_host_path: Option<PathBuf>,
    #[cfg(target_os = "windows")]
    windows_manifest_value: Option<String>,
}

fn collect_ownership(
    layout: &InstallLayout,
    receipt: Option<&InstallationReceipt>,
    transaction: Option<&InstallationTransaction>,
) -> Result<RegistrationOwnership, SetupError> {
    let mut manifest_hashes = receipt
        .map(|value| value.owned_manifest_sha256s.clone())
        .unwrap_or_default();
    if let Some(transaction) = transaction {
        for hash in &transaction.owned_manifest_sha256s {
            push_unique(&mut manifest_hashes, hash.clone());
        }
    }
    let mut native_host_path = transaction
        .map(|value| value.native_host_path.clone())
        .or_else(|| receipt.map(|value| value.native_host_path.clone()));
    let mut master_manifest_owned = false;

    if let Some(bytes) = read_regular_file_if_present(&layout.manifest_path, MAX_MANIFEST_BYTES)? {
        let candidate_host = native_host_path.clone().or_else(|| {
            fs::canonicalize(&layout.installed_host)
                .ok()
                .or_else(|| Some(layout.installed_host.clone()))
        });
        if let Some(candidate_host) = candidate_host
            && validate_any_owned_host_manifest(&bytes, &candidate_host).is_ok()
        {
            push_unique(&mut manifest_hashes, sha256_hex(&bytes));
            native_host_path.get_or_insert(candidate_host);
            master_manifest_owned = true;
        }
    }

    #[cfg(target_os = "windows")]
    let windows_manifest_value =
        if receipt.is_some() || transaction.is_some() || master_manifest_owned {
            Some(path_to_registry_string(&layout.manifest_path)?)
        } else {
            None
        };
    #[cfg(not(target_os = "windows"))]
    let _ = master_manifest_owned;

    Ok(RegistrationOwnership {
        manifest_hashes,
        native_host_path,
        #[cfg(target_os = "windows")]
        windows_manifest_value,
    })
}

fn remove_owned_registrations(
    _layout: &InstallLayout,
    ownership: &RegistrationOwnership,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let Some(native_host_path) = &ownership.native_host_path else {
            details.push(
                "No verified manifest ownership record was available; browser manifests were left untouched."
                    .to_owned(),
            );
            return Ok(());
        };
        for path in all_manifest_paths(_layout)? {
            remove_owned_manifest_file(
                &path,
                &ownership.manifest_hashes,
                native_host_path,
                details,
            )?;
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let registry = windows_system_tool("reg.exe")?;
        let Some(expected) = &ownership.windows_manifest_value else {
            return Ok(());
        };
        for key in all_registry_keys() {
            for view in WINDOWS_REGISTRY_LOOKUP_ORDER {
                remove_owned_registry_key(&registry, &key, expected, view, details)?;
            }
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_owned_manifest_file(
    path: &Path,
    owned_hashes: &[String],
    native_host_path: &Path,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    validate_existing_ancestors_no_redirect(path, "native-messaging manifest ancestor")?;
    let Some(bytes) = read_regular_file_if_present(path, MAX_MANIFEST_BYTES)? else {
        return Ok(());
    };
    let owned = owned_hashes.contains(&sha256_hex(&bytes))
        && validate_any_owned_host_manifest(&bytes, native_host_path).is_ok();
    if !owned {
        details.push(format!(
            "Left modified or foreign browser registration untouched at {}.",
            path.display()
        ));
        return Ok(());
    }
    validate_existing_ancestors_no_redirect(path, "native-messaging manifest ancestor")?;
    reject_symlink(path, "native-messaging manifest")?;
    fs::remove_file(path).map_err(|error| {
        operation(format!(
            "unable to remove owned browser registration {}: {error}",
            path.display()
        ))
    })?;
    details.push(format!(
        "Removed owned browser registration {}.",
        path.display()
    ));
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir(parent);
    }
    Ok(())
}

fn registrations_match(
    layout: &InstallLayout,
    receipt: &InstallationReceipt,
) -> Result<bool, SetupError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        for path in manifest_paths(layout, &receipt.browsers)? {
            let Some(bytes) = read_regular_file_if_present(&path, MAX_MANIFEST_BYTES)? else {
                return Ok(false);
            };
            if sha256_hex(&bytes) != receipt.manifest_sha256
                || validate_host_manifest(&bytes, &receipt.native_host_path, &receipt.extension_ids)
                    .is_err()
            {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    #[cfg(target_os = "windows")]
    {
        let registry = windows_system_tool("reg.exe")?;
        let expected = path_to_registry_string(&layout.manifest_path)?;
        for key in registry_keys(&receipt.browsers) {
            for view in WINDOWS_REGISTRY_LOOKUP_ORDER {
                let Some(value) = query_registry_default(&registry, &key, view)? else {
                    return Ok(false);
                };
                if !windows_path_strings_equal(&value, &expected) {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }

    #[allow(unreachable_code)]
    Ok(false)
}

#[cfg(target_os = "windows")]
fn query_registry_default(
    registry: &Path,
    key: &str,
    view: WindowsRegistryView,
) -> Result<Option<String>, SetupError> {
    let output = run_command(
        registry,
        &[
            OsString::from("QUERY"),
            OsString::from(key),
            OsString::from("/ve"),
            OsString::from(view.reg_argument()),
        ],
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        for kind in ["REG_SZ", "REG_EXPAND_SZ"] {
            if let Some(index) = line.find(kind) {
                let value = line[index + kind.len()..].trim();
                if !value.is_empty() {
                    return Ok(Some(value.to_owned()));
                }
            }
        }
    }
    Err(operation(format!(
        "reg.exe returned an unreadable default value for {key} ({} view)",
        view.label()
    )))
}

#[cfg(target_os = "windows")]
fn remove_owned_registry_key(
    registry: &Path,
    key: &str,
    expected_manifest: &str,
    view: WindowsRegistryView,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    let Some(value) = query_registry_default(registry, key, view)? else {
        return Ok(());
    };
    if !windows_path_strings_equal(&value, expected_manifest) {
        details.push(format!(
            "Left foreign native-messaging registry value untouched at {key} ({} view).",
            view.label()
        ));
        return Ok(());
    }
    require_command_success(
        registry,
        &[
            OsString::from("DELETE"),
            OsString::from(key),
            OsString::from("/f"),
            OsString::from(view.reg_argument()),
        ],
        "remove an owned per-user native-messaging registry key",
    )?;
    details.push(format!(
        "Removed owned native-messaging registry key {key} ({} view).",
        view.label()
    ));
    Ok(())
}

#[cfg(target_os = "windows")]
fn path_to_registry_string(path: &Path) -> Result<String, SetupError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| operation("Windows registry path is not valid Unicode"))
}

#[cfg(target_os = "windows")]
fn windows_path_strings_equal(left: &str, right: &str) -> bool {
    left.replace('/', "\\")
        .eq_ignore_ascii_case(&right.replace('/', "\\"))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct CertutilChoice {
    path: PathBuf,
    library_directory: Option<PathBuf>,
    source: &'static str,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledCertutilCandidate {
    path: PathBuf,
    library_directory: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn select_linux_certutil() -> Result<CertutilChoice, SetupError> {
    let setup = env::current_exe()
        .map_err(|error| operation(format!("unable to locate setup executable: {error}")))?;
    #[cfg(feature = "embedded-host")]
    {
        select_bundled_linux_certutil(&setup)?.ok_or_else(|| {
            operation(
                "the embedded-host setup release is missing its package-local libexec/certutil helper",
            )
        })
    }
    #[cfg(not(feature = "embedded-host"))]
    {
        select_linux_certutil_from(
            &setup,
            env::var_os("HNS_SETUP_CERTUTIL"),
            env::var_os("HNS_SETUP_CERTUTIL_LIB_DIR"),
            env::var_os("PATH").as_deref(),
        )
    }
}

#[cfg(all(target_os = "linux", any(not(feature = "embedded-host"), test)))]
fn select_linux_certutil_from(
    setup: &Path,
    explicit: Option<OsString>,
    explicit_library_directory: Option<OsString>,
    search_path: Option<&std::ffi::OsStr>,
) -> Result<CertutilChoice, SetupError> {
    if let Some(explicit) = explicit {
        if explicit.is_empty() {
            return Err(operation("HNS_SETUP_CERTUTIL is empty"));
        }
        let path = validate_executable_path(make_absolute(PathBuf::from(explicit))?)?;
        let library_directory = explicit_library_directory
            .map(PathBuf::from)
            .map(make_absolute)
            .transpose()?
            .map(validate_library_directory)
            .transpose()?;
        return Ok(CertutilChoice {
            path,
            library_directory,
            source: "explicit HNS_SETUP_CERTUTIL",
        });
    }
    if explicit_library_directory.is_some() {
        return Err(operation(
            "HNS_SETUP_CERTUTIL_LIB_DIR requires HNS_SETUP_CERTUTIL",
        ));
    }

    if let Some(bundled) = select_bundled_linux_certutil(setup)? {
        return Ok(bundled);
    }

    let path = find_executable_on_path("certutil", search_path)?.ok_or_else(|| {
        operation(
            "certutil is unavailable; the Linux release must bundle tools/certutil (HNS_SETUP_CERTUTIL may be used for tests/development)",
        )
    })?;
    Ok(CertutilChoice {
        path,
        library_directory: None,
        source: "system PATH fallback for development/manual builds",
    })
}

#[cfg(target_os = "linux")]
fn select_bundled_linux_certutil(setup: &Path) -> Result<Option<CertutilChoice>, SetupError> {
    for candidate in bundled_certutil_candidates(setup)? {
        if candidate.path.exists() {
            return Ok(Some(CertutilChoice {
                path: validate_executable_path(candidate.path)?,
                library_directory: candidate
                    .library_directory
                    .map(validate_library_directory)
                    .transpose()?,
                source: "bundled setup helper",
            }));
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn bundled_certutil_candidates(
    setup_executable: &Path,
) -> Result<[BundledCertutilCandidate; 2], SetupError> {
    let setup_directory = setup_executable
        .parent()
        .ok_or_else(|| operation("setup executable has no parent directory"))?;
    let package_directory = setup_directory.parent().unwrap_or(setup_directory);
    Ok([
        BundledCertutilCandidate {
            path: setup_directory.join("tools").join("certutil"),
            library_directory: Some(setup_directory.join("tools").join("lib")),
        },
        BundledCertutilCandidate {
            path: package_directory.join("libexec").join("certutil"),
            // The AppDir wrapper invokes its bundled dynamic loader itself.
            // Injecting LD_LIBRARY_PATH before /bin/sh starts could preload the
            // packaged libc into the system shell.
            library_directory: None,
        },
    ])
}

#[cfg(target_os = "linux")]
fn linux_nss_database_candidates(layout: &InstallLayout) -> Result<(PathBuf, PathBuf), SetupError> {
    Ok((
        make_absolute(layout.profile_home.join(".pki").join("nssdb"))?,
        make_absolute(layout.user_data_home.join("pki").join("nssdb"))?,
    ))
}

#[cfg(target_os = "linux")]
fn validate_linux_nss_database(layout: &InstallLayout, database: &Path) -> Result<(), SetupError> {
    let (legacy, modern) = linux_nss_database_candidates(layout)?;
    if !path_keys_equal(database, &legacy) && !path_keys_equal(database, &modern) {
        return Err(operation(format!(
            "refusing unrecorded Chromium NSS database path: {}",
            database.display()
        )));
    }
    validate_existing_ancestors_no_redirect(database, "per-user NSS ancestor")?;
    reject_symlink(database, "per-user NSS database")?;
    if database.exists() && !database.is_dir() {
        return Err(operation(format!(
            "per-user NSS database is not a directory: {}",
            database.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_trust_store(layout: &InstallLayout) -> Result<TrustStoreReceipt, SetupError> {
    let (legacy, modern) = linux_nss_database_candidates(layout)?;
    let database = if legacy.exists() { legacy } else { modern };
    validate_linux_nss_database(layout, &database)?;
    Ok(TrustStoreReceipt::LinuxNss {
        database_path: database,
    })
}

#[cfg(target_os = "macos")]
fn resolve_trust_store(_layout: &InstallLayout) -> Result<TrustStoreReceipt, SetupError> {
    Ok(TrustStoreReceipt::MacosLoginKeychain {
        keychain_path: resolve_macos_login_keychain()?,
    })
}

#[cfg(target_os = "windows")]
fn resolve_trust_store(_layout: &InstallLayout) -> Result<TrustStoreReceipt, SetupError> {
    Ok(TrustStoreReceipt::WindowsUserRoot)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn resolve_trust_store(_layout: &InstallLayout) -> Result<TrustStoreReceipt, SetupError> {
    Err(operation("unsupported trust-store platform"))
}

#[cfg(target_os = "linux")]
fn install_trust_anchor(
    layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    let certutil = select_linux_certutil()?;
    let TrustStoreReceipt::LinuxNss { database_path } = trust_store else {
        return Err(operation(
            "installation receipt selected a non-Linux trust store",
        ));
    };
    let database = database_path.clone();
    validate_linux_nss_database(layout, &database)?;
    ensure_directory(&database, true)?;
    validate_linux_nss_database(layout, &database)?;
    let database_argument = prefixed_os_string("sql:", &database);
    let mut listing = run_certutil(
        &certutil,
        &[
            OsString::from("-d"),
            database_argument.clone(),
            OsString::from("-L"),
        ],
    )?;
    if !listing.status.success() {
        let mut entries = fs::read_dir(&database).map_err(|error| {
            operation(format!(
                "unable to inspect NSS database directory {}: {error}",
                database.display()
            ))
        })?;
        let database_is_empty = entries
            .next()
            .transpose()
            .map_err(|error| {
                operation(format!(
                    "unable to enumerate NSS database directory {}: {error}",
                    database.display()
                ))
            })?
            .is_none();
        if !database_is_empty {
            return Err(certutil_command_failure(
                &certutil,
                &listing,
                "enumerate the existing per-user Chromium NSS database",
            ));
        }
        require_certutil_success(
            &certutil,
            &[
                OsString::from("-d"),
                database_argument.clone(),
                OsString::from("-N"),
                OsString::from("--empty-password"),
            ],
            "initialize the per-user Chromium NSS database",
        )?;
        listing = require_certutil_success(
            &certutil,
            &[
                OsString::from("-d"),
                database_argument.clone(),
                OsString::from("-L"),
            ],
            "read the initialized per-user Chromium NSS database",
        )?;
    }
    let nickname = ca_nickname(&ca.certificate_sha256);
    if nss_listing_contains_nickname(&listing.stdout, &nickname) {
        let existing_der = export_nss_certificate(&certutil, &database_argument, &nickname)?;
        if sha256_hex(&existing_der) != ca.certificate_sha256 {
            return Err(operation(format!(
                "refusing to replace NSS nickname {nickname}: its exact certificate fingerprint is foreign"
            )));
        }
        require_certutil_success(
            &certutil,
            &[
                OsString::from("-d"),
                database_argument.clone(),
                OsString::from("-D"),
                OsString::from("-n"),
                OsString::from(&nickname),
            ],
            "remove the previous exact NSS trust entry",
        )?;
    }
    require_certutil_success(
        &certutil,
        &[
            OsString::from("-d"),
            database_argument.clone(),
            OsString::from("-A"),
            OsString::from("-t"),
            OsString::from("C,,"),
            OsString::from("-n"),
            OsString::from(&nickname),
            OsString::from("-i"),
            ca.certificate_path.as_os_str().to_os_string(),
        ],
        "install the local CA in the per-user Chromium NSS database",
    )?;
    if !linux_nss_entry_is_effectively_trusted(
        &certutil,
        &database_argument,
        &nickname,
        &ca.certificate_sha256,
    )? {
        return Err(operation(
            "the installed NSS certificate was not the exact effective SSL CA trust entry",
        ));
    }
    let library_detail = certutil
        .library_directory
        .as_ref()
        .map(|path| format!(" with package-local libraries from {}", path.display()))
        .unwrap_or_default();
    details.push(format!(
        "Used {} at {}{} for the per-user NSS trust store {}.",
        certutil.source,
        certutil.path.display(),
        library_detail,
        database.display()
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_trust_anchor(
    layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    let security = PathBuf::from("/usr/bin/security");
    let TrustStoreReceipt::MacosLoginKeychain { keychain_path } = trust_store else {
        return Err(operation(
            "installation receipt selected a non-macOS trust store",
        ));
    };
    let keychain = keychain_path;
    let output = require_command_success(
        &security,
        &[
            OsString::from("find-certificate"),
            OsString::from("-a"),
            OsString::from("-Z"),
            keychain.as_os_str().to_os_string(),
        ],
        "enumerate the login keychain before trust installation",
    )?;
    if output_contains_fingerprint(&output.stdout, &ca.certificate_sha1) {
        require_command_success(
            &security,
            &[
                OsString::from("delete-certificate"),
                OsString::from("-t"),
                OsString::from("-Z"),
                OsString::from(&ca.certificate_sha1),
                keychain.as_os_str().to_os_string(),
            ],
            "remove the previous exact certificate from the login keychain",
        )?;
    }
    require_command_success(
        &security,
        &[
            OsString::from("add-trusted-cert"),
            OsString::from("-r"),
            OsString::from("trustRoot"),
            OsString::from("-k"),
            keychain.as_os_str().to_os_string(),
            ca.certificate_path.as_os_str().to_os_string(),
        ],
        "install the local CA in the login keychain",
    )?;
    if !trust_anchor_present(layout, ca, trust_store)? {
        return Err(operation(
            "macOS did not confirm effective SSL trust in the actual login keychain",
        ));
    }
    details.push(format!(
        "Used /usr/bin/security for the per-user login keychain {}.",
        keychain.display()
    ));
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_trust_anchor(
    layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    if !matches!(trust_store, TrustStoreReceipt::WindowsUserRoot) {
        return Err(operation(
            "installation receipt selected a non-Windows trust store",
        ));
    }
    let certutil = windows_system_tool("certutil.exe")?;
    let _ = run_command(
        &certutil,
        &[
            OsString::from("-user"),
            OsString::from("-delstore"),
            OsString::from("Root"),
            OsString::from(&ca.certificate_sha1),
        ],
    )?;
    require_command_success(
        &certutil,
        &[
            OsString::from("-user"),
            OsString::from("-addstore"),
            OsString::from("Root"),
            ca.certificate_path.as_os_str().to_os_string(),
        ],
        "install the local CA in the per-user Windows Root store",
    )?;
    require_command_success(
        &certutil,
        &[
            OsString::from("-user"),
            OsString::from("-store"),
            OsString::from("Root"),
            OsString::from(&ca.certificate_sha1),
        ],
        "verify the local CA in the per-user Windows Root store",
    )?;
    if !trust_anchor_present(layout, ca, trust_store)? {
        return Err(operation(
            "Windows did not confirm the certificate in the per-user Root store",
        ));
    }
    details.push(format!(
        "Used the Windows component {} for the per-user Root store.",
        certutil.display()
    ));
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn install_trust_anchor(
    _layout: &InstallLayout,
    _ca: &CaInfo,
    _trust_store: &TrustStoreReceipt,
    _details: &mut Vec<String>,
) -> Result<(), SetupError> {
    Err(operation("unsupported trust-store platform"))
}

#[cfg(target_os = "linux")]
fn trust_anchor_present(
    layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
) -> Result<bool, SetupError> {
    let TrustStoreReceipt::LinuxNss { database_path } = trust_store else {
        return Ok(false);
    };
    let database = database_path;
    validate_linux_nss_database(layout, database)?;
    if !database.is_dir() {
        return Ok(false);
    }
    let certutil = select_linux_certutil()?;
    linux_nss_entry_is_effectively_trusted(
        &certutil,
        &prefixed_os_string("sql:", database),
        &ca_nickname(&ca.certificate_sha256),
        &ca.certificate_sha256,
    )
}

#[cfg(target_os = "macos")]
fn trust_anchor_present(
    _layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
) -> Result<bool, SetupError> {
    let TrustStoreReceipt::MacosLoginKeychain { keychain_path } = trust_store else {
        return Ok(false);
    };
    let actual = resolve_macos_login_keychain()?;
    if !paths_equivalent_or_lexical(&actual, keychain_path) {
        return Ok(false);
    }
    let security = Path::new("/usr/bin/security");
    let output = require_command_success(
        security,
        &[
            OsString::from("find-certificate"),
            OsString::from("-a"),
            OsString::from("-Z"),
            keychain_path.as_os_str().to_os_string(),
        ],
        "enumerate the login keychain while checking trust",
    )?;
    if !output_contains_fingerprint(&output.stdout, &ca.certificate_sha1) {
        return Ok(false);
    }
    let verification = run_command(
        security,
        &[
            OsString::from("verify-cert"),
            OsString::from("-c"),
            ca.certificate_path.as_os_str().to_os_string(),
            OsString::from("-k"),
            keychain_path.as_os_str().to_os_string(),
            OsString::from("-p"),
            OsString::from("ssl"),
            OsString::from("-l"),
            OsString::from("-L"),
        ],
    )?;
    Ok(verification.status.success())
}

#[cfg(target_os = "windows")]
fn trust_anchor_present(
    _layout: &InstallLayout,
    ca: &CaInfo,
    trust_store: &TrustStoreReceipt,
) -> Result<bool, SetupError> {
    if !matches!(trust_store, TrustStoreReceipt::WindowsUserRoot) {
        return Ok(false);
    }
    let output = require_command_success(
        &windows_system_tool("certutil.exe")?,
        &[
            OsString::from("-user"),
            OsString::from("-store"),
            OsString::from("Root"),
        ],
        "enumerate the per-user Windows Root store while checking trust",
    )?;
    Ok(output_contains_fingerprint(
        &output.stdout,
        &ca.certificate_sha1,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn trust_anchor_present(
    _layout: &InstallLayout,
    _ca: &CaInfo,
    _trust_store: &TrustStoreReceipt,
) -> Result<bool, SetupError> {
    Ok(false)
}

fn remove_stale_trust_anchors(
    layout: &InstallLayout,
    receipt: &InstallationReceipt,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    let sha1 = receipt
        .owned_certificate_sha1s
        .iter()
        .filter(|value| *value != &receipt.certificate_sha1)
        .cloned()
        .collect::<Vec<_>>();
    let sha256 = receipt
        .owned_certificate_sha256s
        .iter()
        .filter(|value| *value != &receipt.certificate_sha256)
        .cloned()
        .collect::<Vec<_>>();
    remove_trust_anchors(layout, &receipt.trust_store, &sha1, &sha256, details)
}

#[cfg(target_os = "linux")]
fn remove_trust_anchors(
    layout: &InstallLayout,
    trust_store: &TrustStoreReceipt,
    _sha1_fingerprints: &[String],
    sha256_fingerprints: &[String],
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    if sha256_fingerprints.is_empty() {
        return Ok(());
    }
    let TrustStoreReceipt::LinuxNss { database_path } = trust_store else {
        return Err(operation(
            "ownership record selected a non-Linux trust store",
        ));
    };
    let database = database_path;
    validate_linux_nss_database(layout, database)?;
    if !database.is_dir() {
        details.push(format!(
            "The per-user NSS database {} was absent.",
            database.display()
        ));
        return Ok(());
    }
    let certutil = select_linux_certutil()?;
    let database_argument = prefixed_os_string("sql:", database);
    let mut listing = require_certutil_success(
        &certutil,
        &[
            OsString::from("-d"),
            database_argument.clone(),
            OsString::from("-L"),
        ],
        "inspect the per-user Chromium NSS database before removal",
    )?;
    for fingerprint in sha256_fingerprints {
        if !is_lower_hex(fingerprint, 64) {
            return Err(operation(
                "refusing to remove an NSS entry with an invalid recorded fingerprint",
            ));
        }
        let nickname = ca_nickname(fingerprint);
        if nss_listing_contains_nickname(&listing.stdout, &nickname) {
            let existing_der = export_nss_certificate(&certutil, &database_argument, &nickname)?;
            if sha256_hex(&existing_der) != *fingerprint {
                details.push(format!(
                    "Left NSS nickname {nickname} untouched because its exact certificate fingerprint is foreign."
                ));
                continue;
            }
            require_certutil_success(
                &certutil,
                &[
                    OsString::from("-d"),
                    database_argument.clone(),
                    OsString::from("-D"),
                    OsString::from("-n"),
                    OsString::from(&nickname),
                ],
                "remove the exact recorded CA from the per-user NSS database",
            )?;
            listing = require_certutil_success(
                &certutil,
                &[
                    OsString::from("-d"),
                    database_argument.clone(),
                    OsString::from("-L"),
                ],
                "enumerate the per-user NSS database after removal",
            )?;
            if nss_listing_contains_nickname(&listing.stdout, &nickname) {
                let remaining = export_nss_certificate(&certutil, &database_argument, &nickname)?;
                if sha256_hex(&remaining) == *fingerprint {
                    return Err(operation(format!(
                        "exact NSS trust entry {nickname} remained after removal"
                    )));
                }
                details.push(format!(
                    "A foreign NSS certificate now occupies nickname {nickname}; it was left untouched."
                ));
            }
            details.push(format!(
                "Removed exact NSS trust entry {nickname} using {} at {}.",
                certutil.source,
                certutil.path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_trust_anchors(
    _layout: &InstallLayout,
    trust_store: &TrustStoreReceipt,
    sha1_fingerprints: &[String],
    _sha256_fingerprints: &[String],
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    if sha1_fingerprints.is_empty() {
        return Ok(());
    }
    let security = PathBuf::from("/usr/bin/security");
    let TrustStoreReceipt::MacosLoginKeychain { keychain_path } = trust_store else {
        return Err(operation(
            "ownership record selected a non-macOS trust store",
        ));
    };
    let keychain = keychain_path;
    let actual = resolve_macos_login_keychain()?;
    if !paths_equivalent_or_lexical(&actual, keychain) {
        return Err(operation(
            "recorded login keychain is no longer the user's actual login keychain",
        ));
    }
    let mut listing = require_command_success(
        &security,
        &[
            OsString::from("find-certificate"),
            OsString::from("-a"),
            OsString::from("-Z"),
            keychain.as_os_str().to_os_string(),
        ],
        "enumerate the login keychain before trust removal",
    )?;
    for fingerprint in sha1_fingerprints {
        if !is_lower_hex(fingerprint, 40) {
            return Err(operation(
                "refusing to remove a keychain entry with an invalid recorded fingerprint",
            ));
        }
        if output_contains_fingerprint(&listing.stdout, fingerprint) {
            require_command_success(
                &security,
                &[
                    OsString::from("delete-certificate"),
                    OsString::from("-t"),
                    OsString::from("-Z"),
                    OsString::from(fingerprint),
                    keychain.as_os_str().to_os_string(),
                ],
                "remove the exact recorded CA from the login keychain",
            )?;
            details.push(format!(
                "Removed exact login-keychain trust entry {fingerprint}."
            ));
            listing = require_command_success(
                &security,
                &[
                    OsString::from("find-certificate"),
                    OsString::from("-a"),
                    OsString::from("-Z"),
                    keychain.as_os_str().to_os_string(),
                ],
                "enumerate the login keychain after trust removal",
            )?;
            if output_contains_fingerprint(&listing.stdout, fingerprint) {
                return Err(operation(format!(
                    "exact login-keychain certificate {fingerprint} remained after removal"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_trust_anchors(
    _layout: &InstallLayout,
    trust_store: &TrustStoreReceipt,
    sha1_fingerprints: &[String],
    _sha256_fingerprints: &[String],
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    if !matches!(trust_store, TrustStoreReceipt::WindowsUserRoot) {
        return Err(operation(
            "ownership record selected a non-Windows trust store",
        ));
    }
    if sha1_fingerprints.is_empty() {
        return Ok(());
    }
    let certutil = windows_system_tool("certutil.exe")?;
    for fingerprint in sha1_fingerprints {
        if !is_lower_hex(fingerprint, 40) {
            return Err(operation(
                "refusing to remove a Windows certificate with an invalid recorded fingerprint",
            ));
        }
        let listing = require_command_success(
            &certutil,
            &[
                OsString::from("-user"),
                OsString::from("-store"),
                OsString::from("Root"),
            ],
            "enumerate the per-user Windows Root store before removal",
        )?;
        if output_contains_fingerprint(&listing.stdout, fingerprint) {
            require_command_success(
                &certutil,
                &[
                    OsString::from("-user"),
                    OsString::from("-delstore"),
                    OsString::from("Root"),
                    OsString::from(fingerprint),
                ],
                "remove the exact recorded CA from the per-user Windows Root store",
            )?;
            let remaining = require_command_success(
                &certutil,
                &[
                    OsString::from("-user"),
                    OsString::from("-store"),
                    OsString::from("Root"),
                ],
                "enumerate the per-user Windows Root store after removal",
            )?;
            if output_contains_fingerprint(&remaining.stdout, fingerprint) {
                return Err(operation(format!(
                    "exact per-user Windows Root certificate {fingerprint} remained after removal"
                )));
            }
            details.push(format!(
                "Removed exact per-user Windows Root certificate {fingerprint}."
            ));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn remove_trust_anchors(
    _layout: &InstallLayout,
    _trust_store: &TrustStoreReceipt,
    _sha1_fingerprints: &[String],
    _sha256_fingerprints: &[String],
    _details: &mut Vec<String>,
) -> Result<(), SetupError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn ca_nickname(certificate_sha256: &str) -> String {
    format!("{CA_COMMON_NAME} ({})", &certificate_sha256[..12])
}

#[cfg(target_os = "linux")]
fn linux_nss_entry_is_effectively_trusted(
    certutil: &CertutilChoice,
    database_argument: &OsString,
    nickname: &str,
    expected_sha256: &str,
) -> Result<bool, SetupError> {
    let listing = require_certutil_success(
        certutil,
        &[
            OsString::from("-d"),
            database_argument.clone(),
            OsString::from("-L"),
        ],
        "enumerate the per-user Chromium NSS database",
    )?;
    if !nss_listing_contains_nickname(&listing.stdout, nickname) {
        return Ok(false);
    }
    let der = export_nss_certificate(certutil, database_argument, nickname)?;
    Ok(sha256_hex(&der) == expected_sha256
        && nss_listing_has_ssl_ca_trust(&listing.stdout, nickname))
}

#[cfg(any(target_os = "linux", test))]
fn nss_listing_contains_nickname(bytes: &[u8], nickname: &str) -> bool {
    nss_listing_trust_attributes(bytes, nickname).is_some()
}

#[cfg(any(target_os = "linux", test))]
fn nss_listing_has_ssl_ca_trust(bytes: &[u8], nickname: &str) -> bool {
    nss_listing_trust_attributes(bytes, nickname).as_deref() == Some("C,,")
}

#[cfg(any(target_os = "linux", test))]
fn nss_listing_trust_attributes(bytes: &[u8], nickname: &str) -> Option<String> {
    String::from_utf8_lossy(bytes).lines().find_map(|line| {
        let suffix = line.trim_start().strip_prefix(nickname)?;
        if !suffix.starts_with(char::is_whitespace) {
            return None;
        }
        suffix.split_whitespace().next().map(ToOwned::to_owned)
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn output_contains_fingerprint(bytes: &[u8], fingerprint: &str) -> bool {
    String::from_utf8_lossy(bytes)
        .to_ascii_lowercase()
        .contains(&fingerprint.to_ascii_lowercase())
}

#[cfg(target_os = "macos")]
fn resolve_macos_login_keychain() -> Result<PathBuf, SetupError> {
    let output = require_command_success(
        Path::new("/usr/bin/security"),
        &[OsString::from("login-keychain")],
        "resolve the user's actual login keychain",
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(operation(
            "security login-keychain returned an ambiguous keychain path",
        ));
    }
    let value = lines[0]
        .strip_prefix('"')
        .and_then(|line| line.strip_suffix('"'));
    let value = value.unwrap_or(lines[0]);
    if value.is_empty() || value.contains('"') {
        return Err(operation(
            "security login-keychain returned an invalid keychain path",
        ));
    }
    let keychain = make_absolute(PathBuf::from(value))?;
    validate_existing_ancestors_no_redirect(&keychain, "login-keychain ancestor")?;
    reject_symlink(&keychain, "login keychain")?;
    if !keychain.is_file() {
        return Err(operation(format!(
            "actual login keychain is not a regular file: {}",
            keychain.display()
        )));
    }
    Ok(keychain)
}

#[cfg(target_os = "windows")]
fn windows_system_tool(file_name: &str) -> Result<PathBuf, SetupError> {
    let system_root = required_environment_path("SystemRoot")?;
    let path = system_root.join("System32").join(file_name);
    if !path.is_file() {
        return Err(operation(format!(
            "required Windows component is missing: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn trusted_installed_host(
    payload: &NativePayload,
    layout: &InstallLayout,
    receipt: Option<&InstallationReceipt>,
    transaction: Option<&InstallationTransaction>,
) -> Result<bool, SetupError> {
    let Some(bytes) = read_regular_file_if_present(&layout.installed_host, u64::MAX)? else {
        return Ok(false);
    };
    let installed_hash = sha256_hex(&bytes);
    if let Some(transaction) = transaction {
        return Ok(installed_hash == transaction.native_host_sha256
            && paths_equivalent(&layout.installed_host, &transaction.native_host_path));
    }
    if let Some(receipt) = receipt {
        return Ok(installed_hash == receipt.native_host_sha256
            && paths_equivalent(&layout.installed_host, &receipt.native_host_path));
    }
    let expected = match payload.read() {
        Ok(bytes) if !bytes.is_empty() => sha256_hex(&bytes),
        _ => return Ok(false),
    };
    Ok(installed_hash == expected)
}

fn ensure_safe_root(root: &Path, protected_roots: &[PathBuf]) -> Result<(), SetupError> {
    if !root.is_absolute()
        || root.parent().is_none()
        || root.to_string_lossy().len() < 16
        || root
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count()
            < 3
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || protected_roots
            .iter()
            .any(|protected| paths_equivalent_or_lexical(root, protected))
        || !has_exact_product_suffix(root)
    {
        return Err(operation(format!(
            "refusing unsafe per-user install root: {}",
            root.display()
        )));
    }
    Ok(())
}

fn remove_install_root_recursively(
    install_root: &Path,
    protected_roots: &[PathBuf],
    has_valid_ownership_record: bool,
    details: &mut Vec<String>,
) -> Result<(), SetupError> {
    if !install_root.exists() {
        details.push("The per-user install root was already absent.".to_owned());
        return Ok(());
    }
    if !has_valid_ownership_record {
        return Err(operation(format!(
            "refusing recursive removal of {} without a valid ownership receipt or pre-trust transaction",
            install_root.display()
        )));
    }

    // Recheck immediately before recursive deletion to narrow the filesystem
    // race and reject a root replaced by a symlink after receipt validation.
    ensure_safe_root(install_root, protected_roots)?;
    validate_existing_ancestors_no_redirect(install_root, "install-root ancestor")?;
    reject_symlink(install_root, "install root")?;
    let metadata = fs::symlink_metadata(install_root).map_err(|error| {
        operation(format!(
            "unable to inspect install root {}: {error}",
            install_root.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(operation(format!(
            "refusing to purge non-directory install root: {}",
            install_root.display()
        )));
    }
    fs::remove_dir_all(install_root).map_err(|error| {
        operation(format!(
            "unable to remove install root {}: {error}",
            install_root.display()
        ))
    })?;
    details.push(format!(
        "Removed native host, runtime data, licenses, and receipt from {}.",
        install_root.display()
    ));
    Ok(())
}

fn has_exact_product_suffix(root: &Path) -> bool {
    let Some(product_directory) = root.parent().and_then(Path::file_name) else {
        return false;
    };
    let Some(platform_directory) = root.file_name() else {
        return false;
    };
    let (expected_product, expected_platform) = expected_product_suffix();
    #[cfg(target_os = "windows")]
    {
        product_directory
            .to_string_lossy()
            .eq_ignore_ascii_case(expected_product)
            && platform_directory
                .to_string_lossy()
                .eq_ignore_ascii_case(expected_platform)
    }
    #[cfg(not(target_os = "windows"))]
    {
        product_directory == expected_product && platform_directory == expected_platform
    }
}

#[cfg(target_os = "linux")]
fn expected_product_suffix() -> (&'static str, &'static str) {
    ("hns-dane-browser", "chromium")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn expected_product_suffix() -> (&'static str, &'static str) {
    ("HnsDaneBrowser", "Chromium")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn expected_product_suffix() -> (&'static str, &'static str) {
    ("unsupported", "unsupported")
}

fn ensure_directory(path: &Path, private: bool) -> Result<(), SetupError> {
    if path.exists() {
        reject_symlink(path, "directory")?;
        if !path.is_dir() {
            return Err(operation(format!(
                "required directory path is not a directory: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path).map_err(|error| {
            operation(format!(
                "unable to create directory {}: {error}",
                path.display()
            ))
        })?;
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            operation(format!(
                "unable to secure directory {}: {error}",
                path.display()
            ))
        })?;
    }
    let _ = private;
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), SetupError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_redirect(&metadata) => Err(operation(format!(
            "refusing {label} symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(operation(format!(
            "unable to inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

fn validate_existing_ancestors_no_redirect(path: &Path, label: &str) -> Result<(), SetupError> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata_is_redirect(&metadata) => {
                return Err(operation(format!(
                    "refusing {label} redirect at {}",
                    ancestor.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(operation(format!(
                    "unable to inspect {label} {}: {error}",
                    ancestor.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn metadata_is_redirect(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn metadata_is_redirect(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[derive(Debug, Clone, Copy)]
enum FileMode {
    Executable,
    Private,
    Public,
}

fn atomic_write(path: &Path, bytes: &[u8], mode: FileMode) -> Result<(), SetupError> {
    let parent = path
        .parent()
        .ok_or_else(|| operation(format!("file has no parent directory: {}", path.display())))?;
    validate_existing_ancestors_no_redirect(parent, "destination-file ancestor")?;
    ensure_directory(parent, true)?;
    validate_existing_ancestors_no_redirect(parent, "destination-file ancestor")?;
    reject_symlink(path, "destination file")?;

    let file_name = path
        .file_name()
        .ok_or_else(|| operation(format!("file has no name: {}", path.display())))?;
    let mut temporary = None;
    for _ in 0..100 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut name = OsString::from(".");
        name.push(file_name);
        name.push(format!(".tmp-{}-{sequence}", std::process::id()));
        let candidate = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(operation(format!(
                    "unable to create temporary file beside {}: {error}",
                    path.display()
                )));
            }
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        operation(format!(
            "unable to allocate a unique temporary file beside {}",
            path.display()
        ))
    })?;

    let result = (|| {
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unix_mode = match mode {
                FileMode::Executable => 0o700,
                FileMode::Private => 0o600,
                FileMode::Public => 0o644,
            };
            file.set_permissions(fs::Permissions::from_mode(unix_mode))?;
        }
        let _ = mode;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary_path, path)?;
        sync_parent_directory(parent)?;
        Ok::<(), std::io::Error>(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&temporary_path);
        return Err(operation(format!(
            "unable to atomically write {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(target_os = "windows")]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both pointers refer to live, NUL-terminated UTF-16 buffers for
    // the duration of the call, and the flags contain no pointer-bearing data.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

fn read_regular_file_if_present(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>, SetupError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(operation(format!(
                "unable to inspect file {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(operation(format!(
            "refusing non-regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(operation(format!(
            "file exceeds the permitted size: {}",
            path.display()
        )));
    }
    let file = File::open(path)
        .map_err(|error| operation(format!("unable to open file {}: {error}", path.display())))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len().min(1024 * 1024)).unwrap_or(1024 * 1024));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| operation(format!("unable to read file {}: {error}", path.display())))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(operation(format!(
            "file grew beyond the permitted size while reading: {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_command(program: &Path, arguments: &[OsString]) -> Result<Output, SetupError> {
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| operation(format!("unable to execute {}: {error}", program.display())))
}

#[cfg(target_os = "linux")]
fn run_certutil(certutil: &CertutilChoice, arguments: &[OsString]) -> Result<Output, SetupError> {
    let mut command = Command::new(&certutil.path);
    command.args(arguments).stdin(Stdio::null());
    if let Some(library_directory) = &certutil.library_directory {
        command.env(
            "LD_LIBRARY_PATH",
            certutil_library_search_path(library_directory),
        );
    } else {
        // Loader-owning wrappers and system helpers must not inherit the GUI
        // runtime's library path. In particular, /bin/sh must start against
        // the system libc before an AppDir wrapper selects its own loader.
        command.env_remove("LD_LIBRARY_PATH");
    }
    command.output().map_err(|error| {
        operation(format!(
            "unable to execute {}: {error}",
            certutil.path.display()
        ))
    })
}

#[cfg(target_os = "linux")]
fn require_certutil_success(
    certutil: &CertutilChoice,
    arguments: &[OsString],
    purpose: &str,
) -> Result<Output, SetupError> {
    let output = run_certutil(certutil, arguments)?;
    if !output.status.success() {
        return Err(certutil_command_failure(certutil, &output, purpose));
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn certutil_command_failure(
    certutil: &CertutilChoice,
    output: &Output,
    purpose: &str,
) -> SetupError {
    operation(format!(
        "{} failed to {purpose} ({}): {}",
        certutil.path.display(),
        output.status,
        command_diagnostic(output)
    ))
}

#[cfg(target_os = "linux")]
fn export_nss_certificate(
    certutil: &CertutilChoice,
    database_argument: &OsString,
    nickname: &str,
) -> Result<Vec<u8>, SetupError> {
    let output = require_certutil_success(
        certutil,
        &[
            OsString::from("-d"),
            database_argument.clone(),
            OsString::from("-L"),
            OsString::from("-n"),
            OsString::from(nickname),
            OsString::from("-a"),
        ],
        "export an enumerated certificate from the per-user Chromium NSS database",
    )?;
    if output.stdout.is_empty() || output.stdout.len() as u64 > MAX_JSON_BYTES {
        return Err(operation(format!(
            "certutil returned an empty or oversized certificate export for {nickname}"
        )));
    }
    decode_certificate_pem(&output.stdout)
}

#[cfg(target_os = "linux")]
fn decode_certificate_pem(bytes: &[u8]) -> Result<Vec<u8>, SetupError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(bytes)
        .map_err(|_| operation("certutil certificate export was not valid UTF-8 PEM"))?;
    let begin = text
        .find(BEGIN)
        .ok_or_else(|| operation("certutil certificate export had no PEM begin marker"))?
        + BEGIN.len();
    let end = text[begin..]
        .find(END)
        .map(|offset| begin + offset)
        .ok_or_else(|| operation("certutil certificate export had no PEM end marker"))?;
    if text[end + END.len()..].contains(BEGIN) {
        return Err(operation(
            "certutil certificate export contained multiple PEM certificates",
        ));
    }
    let encoded = text[begin..end]
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let decoded = STANDARD.decode(&encoded).map_err(|error| {
        operation(format!(
            "certutil certificate export contained invalid canonical base64: {error}"
        ))
    })?;
    if decoded.is_empty() {
        return Err(operation("certificate PEM decoded to an empty certificate"));
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
fn certutil_library_search_path(library_directory: &Path) -> OsString {
    library_directory.as_os_str().to_os_string()
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn require_command_success(
    program: &Path,
    arguments: &[OsString],
    purpose: &str,
) -> Result<Output, SetupError> {
    let output = run_command(program, arguments)?;
    if !output.status.success() {
        return Err(operation(format!(
            "{} failed to {purpose} ({}): {}",
            program.display(),
            output.status,
            command_diagnostic(&output)
        )));
    }
    Ok(output)
}

fn command_diagnostic(output: &Output) -> String {
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let text = String::from_utf8_lossy(bytes);
    let mut diagnostic = text
        .trim()
        .chars()
        .take(MAX_COMMAND_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if diagnostic.is_empty() {
        diagnostic = "no diagnostic output".to_owned();
    } else if text.trim().chars().count() > MAX_COMMAND_DIAGNOSTIC_CHARS {
        diagnostic.push('…');
    }
    diagnostic
}

fn required_environment_path(name: &str) -> Result<PathBuf, SetupError> {
    optional_environment_path(name)?.ok_or_else(|| {
        operation(format!(
            "{name} is required to locate the current user's profile"
        ))
    })
}

fn optional_environment_path(name: &str) -> Result<Option<PathBuf>, SetupError> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(operation(format!("{name} is empty")));
    }
    make_absolute(PathBuf::from(value)).map(Some)
}

fn make_absolute(path: PathBuf) -> Result<PathBuf, SetupError> {
    let path = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .map_err(|error| operation(format!("unable to read current directory: {error}")))?
            .join(path)
    };
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(operation(format!(
            "path must not contain parent traversal: {}",
            path.display()
        )));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn validate_executable_path(path: PathBuf) -> Result<PathBuf, SetupError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        operation(format!(
            "unable to inspect certutil helper {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(operation(format!(
            "certutil helper is not an executable regular file: {}",
            path.display()
        )));
    }
    fs::canonicalize(&path).map_err(|error| {
        operation(format!(
            "unable to resolve certutil helper {}: {error}",
            path.display()
        ))
    })
}

#[cfg(target_os = "linux")]
fn validate_library_directory(path: PathBuf) -> Result<PathBuf, SetupError> {
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        operation(format!(
            "unable to inspect certutil library directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(operation(format!(
            "certutil library path is not a regular directory: {}",
            path.display()
        )));
    }
    fs::canonicalize(&path).map_err(|error| {
        operation(format!(
            "unable to resolve certutil library directory {}: {error}",
            path.display()
        ))
    })
}

#[cfg(all(target_os = "linux", any(not(feature = "embedded-host"), test)))]
fn find_executable_on_path(
    name: &str,
    search_path: Option<&std::ffi::OsStr>,
) -> Result<Option<PathBuf>, SetupError> {
    let Some(path) = search_path else {
        return Ok(None);
    };
    for directory in env::split_paths(path) {
        let candidate = directory.join(name);
        if candidate.exists() {
            return validate_executable_path(make_absolute(candidate)?).map(Some);
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn prefixed_os_string(prefix: &str, path: &Path) -> OsString {
    let mut value = OsString::from(prefix);
    value.push(path.as_os_str());
    value
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => path_keys_equal(&left, &right),
        _ => false,
    }
}

fn paths_equivalent_or_lexical(left: &Path, right: &Path) -> bool {
    if path_keys_equal(left, right) {
        return true;
    }
    paths_equivalent(left, right)
}

#[cfg(target_os = "windows")]
fn path_keys_equal(left: &Path, right: &Path) -> bool {
    windows_path_key(left) == windows_path_key(right)
}

#[cfg(target_os = "windows")]
fn windows_path_key(path: &Path) -> String {
    let value = path.to_string_lossy().replace('/', "\\");
    let value = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
    };
    value.to_ascii_lowercase()
}

#[cfg(not(target_os = "windows"))]
fn path_keys_equal(left: &Path, right: &Path) -> bool {
    left == right
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn merge_owned_hashes(
    receipt_history: Option<&[String]>,
    transaction_history: Option<&[String]>,
    current: String,
) -> Vec<String> {
    let mut values = Vec::new();
    for value in receipt_history
        .into_iter()
        .chain(transaction_history)
        .flatten()
    {
        push_unique(&mut values, value.clone());
    }
    push_unique(&mut values, current);
    values
}

fn browser_labels(browsers: &BTreeSet<Browser>) -> String {
    browsers
        .iter()
        .map(|browser| browser.label())
        .collect::<Vec<_>>()
        .join(", ")
}

fn empty_status() -> InstallationStatus {
    InstallationStatus {
        installed: false,
        version: None,
        extension_ids: Vec::new(),
        browsers: BTreeSet::new(),
        native_host_path: None,
        ca_installed: false,
    }
}

fn operation(message: impl Into<String>) -> SetupError {
    SetupError::Operation(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    const EXTENSION_ID: &str = "idejjnoplngbhpnpjekblpalblbianio";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "hns-browser-setup-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn snapshot_temp_files(data_dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(data_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".hns-headers-"))
            })
            .collect()
    }

    #[cfg(unix)]
    fn write_snapshot_host(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_install_verifies_both_layers_and_removes_temporary_file() {
        let temporary = TestDirectory::new("snapshot-success");
        let data_dir = temporary.path().join("data");
        let host = temporary.path().join("native-host");
        write_snapshot_host(
            &host,
            "#!/bin/sh\nprintf '%s\\n' '{\"network\":\"mainnet\",\"status\":\"snapshot_imported\",\"bestHeight\":7,\"error\":null}'\n",
        );
        let raw = b"small verified header snapshot fixture";
        let compressed = gzip(raw);
        let compressed_sha256 = sha256_hex(&compressed);
        let uncompressed_sha256 = sha256_hex(raw);
        let integrity = SnapshotIntegrity {
            target_height: 7,
            compressed_bytes: compressed.len() as u64,
            compressed_sha256: &compressed_sha256,
            uncompressed_bytes: raw.len() as u64,
            uncompressed_sha256: &uncompressed_sha256,
        };

        let status =
            install_header_snapshot_bytes(&compressed, &host, &data_dir, integrity).unwrap();

        assert_eq!(status.status, "snapshot_imported");
        assert_eq!(status.best_height, 7);
        assert!(snapshot_temp_files(&data_dir).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_install_rejects_raw_digest_mismatch_without_invoking_host() {
        let temporary = TestDirectory::new("snapshot-raw-mismatch");
        let data_dir = temporary.path().join("data");
        let host = temporary.path().join("native-host");
        let marker = temporary.path().join("host-was-invoked");
        write_snapshot_host(
            &host,
            &format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        );
        let raw = b"snapshot fixture";
        let compressed = gzip(raw);
        let compressed_sha256 = sha256_hex(&compressed);
        let wrong_uncompressed_sha256 = "00".repeat(32);
        let integrity = SnapshotIntegrity {
            target_height: 1,
            compressed_bytes: compressed.len() as u64,
            compressed_sha256: &compressed_sha256,
            uncompressed_bytes: raw.len() as u64,
            uncompressed_sha256: &wrong_uncompressed_sha256,
        };

        let error = install_header_snapshot_bytes(&compressed, &host, &data_dir, integrity)
            .unwrap_err()
            .to_string();

        assert!(error.contains("decompressed SHA-256 mismatch"));
        assert!(!marker.exists());
        assert!(snapshot_temp_files(&data_dir).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_install_removes_temporary_file_when_native_import_fails() {
        let temporary = TestDirectory::new("snapshot-native-failure");
        let data_dir = temporary.path().join("data");
        let host = temporary.path().join("native-host");
        write_snapshot_host(&host, "#!/bin/sh\necho import-failed >&2\nexit 9\n");
        let raw = b"snapshot fixture";
        let compressed = gzip(raw);
        let compressed_sha256 = sha256_hex(&compressed);
        let uncompressed_sha256 = sha256_hex(raw);
        let integrity = SnapshotIntegrity {
            target_height: 1,
            compressed_bytes: compressed.len() as u64,
            compressed_sha256: &compressed_sha256,
            uncompressed_bytes: raw.len() as u64,
            uncompressed_sha256: &uncompressed_sha256,
        };

        let error = install_header_snapshot_bytes(&compressed, &host, &data_dir, integrity)
            .unwrap_err()
            .to_string();

        assert!(error.contains("install the bundled mainnet header snapshot"));
        assert!(error.contains("import-failed"));
        assert!(snapshot_temp_files(&data_dir).is_empty());
    }

    #[cfg(target_os = "linux")]
    fn linux_test_layout(root: &Path) -> InstallLayout {
        let profile_home = root.join("home");
        let config_home = profile_home.join(".config");
        let user_data_home = profile_home.join(".local").join("share");
        InstallLayout::new(
            user_data_home.join("hns-dane-browser").join("chromium"),
            Some(config_home.clone()),
            profile_home.clone(),
            Some(user_data_home.clone()),
            vec![profile_home, config_home, user_data_home],
        )
        .unwrap()
    }

    #[test]
    fn extension_id_validation_is_exact() {
        assert!(validate_extension_id(EXTENSION_ID).is_ok());
        assert!(validate_extension_id("IDEJJNOPLNGBHPNPJ").is_err());
        assert!(validate_extension_id("abcdefghijklmnopabcdefghijklmnopq").is_err());
        assert!(validate_extension_id("../../native-host").is_err());
        assert!(validate_extension_id("abcdefghijklmnoqabcdefghijklmnop").is_err());
    }

    #[test]
    fn request_normalization_is_sorted_unique_and_bounded() {
        let request = normalize_request(InstallRequest {
            extension_ids: vec![
                "bcdefghijklmnopabcdefghijklmnopa".to_owned(),
                EXTENSION_ID.to_owned(),
                EXTENSION_ID.to_owned(),
            ],
            browsers: [Browser::Chrome].into_iter().collect(),
        })
        .unwrap();
        assert_eq!(
            request.extension_ids,
            vec![
                "bcdefghijklmnopabcdefghijklmnopa".to_owned(),
                EXTENSION_ID.to_owned()
            ]
        );
        assert!(matches!(
            normalize_request(InstallRequest {
                extension_ids: vec![EXTENSION_ID.to_owned()],
                browsers: BTreeSet::new(),
            }),
            Err(SetupError::NoBrowsers)
        ));
    }

    #[test]
    fn browser_registration_maps_preserve_published_contracts() {
        assert_eq!(
            manifest_relative_directories(UnixPlatform::Linux, Browser::Opera),
            &["opera", "google-chrome"]
        );
        assert_eq!(
            manifest_relative_directories(UnixPlatform::Macos, Browser::Opera),
            &["com.operasoftware.Opera", "Google/Chrome"]
        );
        assert_eq!(
            manifest_relative_directories(UnixPlatform::Linux, Browser::Brave),
            &["BraveSoftware/Brave-Browser"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_legacy_extension_loaders_are_removed_exactly() {
        let temporary = TestDirectory::new("legacy-loaders");
        let layout = linux_test_layout(temporary.path());
        let extension_root = layout.install_root.join("extension");
        let source = extension_root.join("source-0.5.4");
        let crx = extension_root.join("source-0.5.4.crx");
        fs::create_dir_all(&source).unwrap();
        fs::write(&crx, b"legacy crx").unwrap();

        let wrapper = layout
            .profile_home
            .join(".local")
            .join("bin")
            .join("chromium");
        fs::create_dir_all(wrapper.parent().unwrap()).unwrap();
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\n\nexec /usr/bin/chromium \\\n  --disable-renderer-accessibility \\\n  --load-extension={} \\\n  \"$@\"\n",
                source.display()
            ),
        )
        .unwrap();

        let registration = layout
            .config_home
            .as_ref()
            .unwrap()
            .join("chromium")
            .join("External Extensions")
            .join(format!("{CANONICAL_EXTENSION_ID}.json"));
        fs::create_dir_all(registration.parent().unwrap()).unwrap();
        fs::write(
            &registration,
            serde_json::to_vec_pretty(&serde_json::json!({
                "external_crx": crx,
                "external_version": "0.5.2"
            }))
            .unwrap(),
        )
        .unwrap();

        let mut details = Vec::new();
        remove_owned_legacy_extension_loaders(&layout, &mut details).unwrap();

        assert!(!wrapper.exists());
        assert!(!registration.exists());
        assert_eq!(details.len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn modified_legacy_extension_loaders_are_preserved() {
        let temporary = TestDirectory::new("foreign-legacy-loaders");
        let layout = linux_test_layout(temporary.path());
        let extension_root = layout.install_root.join("extension");
        let source = extension_root.join("source-0.5.4");
        fs::create_dir_all(&source).unwrap();

        let wrapper = layout
            .profile_home
            .join(".local")
            .join("bin")
            .join("chromium");
        fs::create_dir_all(wrapper.parent().unwrap()).unwrap();
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\n\nexec /usr/bin/chromium \\\n  --user-data-dir=/tmp/custom \\\n  --load-extension={} \\\n  \"$@\"\n",
                source.display()
            ),
        )
        .unwrap();

        let registration = layout
            .config_home
            .as_ref()
            .unwrap()
            .join("chromium")
            .join("External Extensions")
            .join(format!("{CANONICAL_EXTENSION_ID}.json"));
        fs::create_dir_all(registration.parent().unwrap()).unwrap();
        fs::write(
            &registration,
            serde_json::to_vec_pretty(&serde_json::json!({
                "external_crx": temporary.path().join("foreign.crx"),
                "external_version": "0.5.2"
            }))
            .unwrap(),
        )
        .unwrap();

        let mut details = Vec::new();
        remove_owned_legacy_extension_loaders(&layout, &mut details).unwrap();

        assert!(wrapper.is_file());
        assert!(registration.is_file());
        assert_eq!(details.len(), 1);
        assert!(details[0].contains("Left modified or foreign"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsafe_removal_roots_are_rejected() {
        let protected = vec![PathBuf::from("/home/alice")];
        for unsafe_root in [
            Path::new("/"),
            Path::new("/home/alice"),
            Path::new("/tmp/short"),
            Path::new("/home/alice/../bob/install"),
            Path::new("/home/alice/Documents/valuable-project-files"),
        ] {
            assert!(
                ensure_safe_root(unsafe_root, &protected).is_err(),
                "{}",
                unsafe_root.display()
            );
        }
        assert!(
            ensure_safe_root(
                Path::new("/home/alice/.local/share/hns-dane-browser/chromium"),
                &protected
            )
            .is_ok()
        );
    }

    #[test]
    fn manifest_ownership_requires_exact_bytes_hash_and_identity() {
        let host = if cfg!(windows) {
            PathBuf::from(
                r"C:\Users\alice\AppData\Local\HnsDaneBrowser\Chromium\bin\hns-chromium-native-host.exe",
            )
        } else {
            PathBuf::from(
                "/home/alice/.local/share/hns-dane-browser/chromium/bin/hns-chromium-native-host",
            )
        };
        let manifest = serde_json::json!({
            "name": NATIVE_HOST_NAME,
            "description": "HNS DANE Browser Rust native host",
            "path": host,
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")]
        });
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        assert!(validate_host_manifest(&bytes, &host, &[EXTENSION_ID.to_owned()]).is_ok());
        assert!(validate_any_owned_host_manifest(&bytes, &host).is_ok());

        let mut legacy = manifest.clone();
        legacy["allowed_origins"] = serde_json::json!([
            "chrome-extension://fakeegkjadihalgbnenafflijnpiikbc/",
            format!("chrome-extension://{CANONICAL_EXTENSION_ID}/")
        ]);
        assert!(
            validate_legacy_owned_host_manifest(
                &serde_json::to_vec_pretty(&legacy).unwrap(),
                &host
            )
            .is_ok()
        );

        let mut noncanonical_legacy = legacy.clone();
        noncanonical_legacy["allowed_origins"] =
            serde_json::json!(["chrome-extension://fakeegkjadihalgbnenafflijnpiikbc/"]);
        assert!(
            validate_legacy_owned_host_manifest(
                &serde_json::to_vec_pretty(&noncanonical_legacy).unwrap(),
                &host
            )
            .is_err()
        );

        let mut foreign = manifest;
        foreign["path"] = serde_json::Value::String("/tmp/foreign-host".to_owned());
        assert!(
            validate_any_owned_host_manifest(&serde_json::to_vec_pretty(&foreign).unwrap(), &host)
                .is_err()
        );
    }

    #[test]
    fn fingerprints_are_strict_lowercase_hex() {
        assert!(is_lower_hex(&"ab".repeat(32), 64));
        assert!(!is_lower_hex(&"AB".repeat(32), 64));
        assert!(!is_lower_hex(&"ag".repeat(32), 64));
        assert!(!is_lower_hex(&"ab".repeat(31), 64));
    }

    #[test]
    fn windows_registry_views_are_always_queried_32_then_64() {
        assert_eq!(
            WINDOWS_REGISTRY_LOOKUP_ORDER.map(WindowsRegistryView::reg_argument),
            ["/reg:32", "/reg:64"]
        );
        assert_eq!(
            WINDOWS_REGISTRY_LOOKUP_ORDER.map(WindowsRegistryView::label),
            ["32-bit", "64-bit"]
        );
    }

    #[test]
    fn fingerprint_search_is_case_insensitive_without_parsing_names() {
        let sha1 = "ab".repeat(20);
        let output = format!("SHA-1 hash: {}\n", sha1.to_ascii_uppercase());
        assert!(output_contains_fingerprint(output.as_bytes(), &sha1));
    }

    #[test]
    fn nss_trust_listing_requires_exact_nickname_and_ssl_ca_attributes() {
        let nickname = "HNS DANE Browser Local CA (0123456789ab)";
        let listing = format!(
            "Certificate Nickname                                         Trust Attributes\n\
             SSL,S/MIME,JAR/XPI\n\n\
             {nickname}                                      C,,\n\
             {nickname} foreign                              P,,\n"
        );
        assert!(nss_listing_contains_nickname(listing.as_bytes(), nickname));
        assert!(nss_listing_has_ssl_ca_trust(listing.as_bytes(), nickname));

        let untrusted = format!("{nickname}                                      P,,\n");
        assert!(!nss_listing_has_ssl_ca_trust(
            untrusted.as_bytes(),
            nickname
        ));
        assert!(!nss_listing_contains_nickname(
            format!("{nickname}-suffix                                      C,,\n").as_bytes(),
            nickname
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn chromium_nss_location_prefers_existing_legacy_database() {
        let temporary = TestDirectory::new("nss-selection");
        let layout = linux_test_layout(temporary.path());
        let (legacy, modern) = linux_nss_database_candidates(&layout).unwrap();

        assert_eq!(
            resolve_trust_store(&layout).unwrap(),
            TrustStoreReceipt::LinuxNss {
                database_path: modern
            }
        );

        fs::create_dir_all(&legacy).unwrap();
        assert_eq!(
            resolve_trust_store(&layout).unwrap(),
            TrustStoreReceipt::LinuxNss {
                database_path: legacy
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_ancestor_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = TestDirectory::new("ancestor-redirect");
        let actual = temporary.path().join("actual");
        let redirect = temporary.path().join("redirect");
        fs::create_dir(&actual).unwrap();
        symlink(&actual, &redirect).unwrap();

        let redirected_target = redirect
            .join(expected_product_suffix().0)
            .join(expected_product_suffix().1);
        assert!(
            validate_existing_ancestors_no_redirect(
                &redirected_target,
                "test install-root ancestor"
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nested_ca_directory_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = TestDirectory::new("ca-redirect");
        let layout = linux_test_layout(temporary.path());
        fs::create_dir_all(&layout.data_dir).unwrap();
        let foreign = temporary.path().join("foreign-ca");
        fs::create_dir(&foreign).unwrap();
        symlink(&foreign, &layout.ca_directory).unwrap();

        assert!(validate_ca_storage(&layout, false).is_err());
        assert!(validate_ca_storage(&layout, true).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recursive_root_removal_requires_a_validated_ownership_record() {
        let temporary = TestDirectory::new("root-ownership");
        let layout = linux_test_layout(temporary.path());
        fs::create_dir_all(&layout.install_root).unwrap();
        let marker = layout.install_root.join("foreign-marker");
        fs::write(&marker, b"preserve until owned").unwrap();
        let mut details = Vec::new();

        assert!(
            remove_install_root_recursively(
                &layout.install_root,
                &layout.protected_roots,
                false,
                &mut details
            )
            .is_err()
        );
        assert!(marker.is_file());

        let transaction = InstallationTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            product: NATIVE_HOST_NAME.to_owned(),
            version: VERSION.to_owned(),
            extension_ids: vec![EXTENSION_ID.to_owned()],
            browsers: [Browser::Chrome].into_iter().collect(),
            native_host_path: layout.installed_host.clone(),
            native_host_sha256: "a".repeat(64),
            manifest_path: layout.manifest_path.clone(),
            manifest_sha256: "b".repeat(64),
            owned_manifest_sha256s: vec!["b".repeat(64)],
            certificate_path: layout.certificate_path.clone(),
            certificate_sha1: "c".repeat(40),
            certificate_sha256: "d".repeat(64),
            owned_certificate_sha1s: vec!["c".repeat(40)],
            owned_certificate_sha256s: vec!["d".repeat(64)],
            trust_store: TrustStoreReceipt::LinuxNss {
                database_path: layout.user_data_home.join("pki").join("nssdb"),
            },
        };
        write_transaction(&layout, &transaction).unwrap();
        assert!(read_transaction(&layout).unwrap().is_some());
        remove_install_root_recursively(
            &layout.install_root,
            &layout.protected_roots,
            true,
            &mut details,
        )
        .unwrap();
        assert!(!layout.install_root.exists());
    }

    #[test]
    fn repeated_repair_preserves_all_owned_hashes_before_overwriting_transaction() {
        let receipt = ["1".repeat(64), "2".repeat(64)];
        let interrupted_transaction = ["2".repeat(64), "3".repeat(64)];

        assert_eq!(
            merge_owned_hashes(
                Some(&receipt),
                Some(&interrupted_transaction),
                "4".repeat(64)
            ),
            vec![
                "1".repeat(64),
                "2".repeat(64),
                "3".repeat(64),
                "4".repeat(64)
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nss_export_pem_is_decoded_strictly_for_exact_der_hashing() {
        assert_eq!(
            decode_certificate_pem(
                b"Certificate:\n-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
            )
            .unwrap(),
            vec![1, 2, 3, 4]
        );
        assert!(
            decode_certificate_pem(
                b"-----BEGIN CERTIFICATE-----\nAQIDBB==\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
        assert!(
            decode_certificate_pem(
                b"-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bundled_certutil_and_package_libraries_are_used_without_path_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TestDirectory::new("bundled-certutil");
        let root = temporary.path();
        let tools = root.join("tools");
        let libraries = tools.join("lib");
        fs::create_dir(&tools).unwrap();
        fs::create_dir(&libraries).unwrap();
        let certutil_path = tools.join("certutil");
        fs::write(
            &certutil_path,
            b"#!/bin/sh\nprintf '%s' \"${LD_LIBRARY_PATH-}\"\n",
        )
        .unwrap();
        fs::set_permissions(&certutil_path, fs::Permissions::from_mode(0o700)).unwrap();

        let choice = select_linux_certutil_from(&root.join("setup"), None, None, None).unwrap();
        assert_eq!(choice.source, "bundled setup helper");
        assert_eq!(choice.path, fs::canonicalize(&certutil_path).unwrap());
        assert_eq!(
            choice.library_directory,
            Some(fs::canonicalize(&libraries).unwrap())
        );

        let output = run_certutil(&choice, &[]).unwrap();
        assert!(output.status.success());
        let search_path = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            PathBuf::from(search_path),
            choice.library_directory.unwrap()
        );
    }
}
