//! Discovery boundary for an independently released Chromium wallet service.
//!
//! `hns-wallet-ffi` defines the private ABI v2 frame contract and the wallet
//! repository contains a fail-closed subprocess foundation. This module
//! performs bounded local-integrity checks on a staged service artifact but
//! deliberately does not load or execute it. Provider dispatch remains
//! unavailable until a separately released, signed service, reviewed process
//! transport, and opaque browser-engine authority join all exist.

#[cfg(unix)]
use serde::Deserialize;
#[cfg(all(test, unix))]
use serde::Serialize;
use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{self, Read};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

pub(crate) const WALLET_ABI_VERSION: u16 = 2;
pub(crate) const WALLET_SERVICE_PROTOCOL_VERSION: u16 = 2;
pub(crate) const WALLET_PROVIDER_SCHEMA_VERSION: u16 = 1;
pub(crate) const WALLET_ABI_MAX_FRAME_BYTES: u32 = 1_048_576;
const WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION: u16 = 1;
#[cfg(unix)]
const WALLET_ARTIFACT_DIRECTORY: &str = "wallet-abi-v2";
#[cfg(unix)]
const WALLET_ARTIFACT_MANIFEST: &str = "manifest.json";
#[cfg(unix)]
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
#[cfg(unix)]
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(unix)]
const MAX_RELEASE_ID_BYTES: usize = 128;
#[cfg(unix)]
const MAX_ARTIFACT_NAME_BYTES: usize = 128;
#[cfg(unix)]
const REQUIRED_CAPABILITIES: [&str; 5] = [
    "canonical_framing",
    "restart_isolation",
    "opaque_authority_registry",
    "structured_approvals",
    "typed_events",
];

#[derive(Clone, Debug)]
pub(crate) struct WalletAbiDiscovery {
    data_dir: PathBuf,
    state: WalletArtifactState,
}

impl WalletAbiDiscovery {
    pub(crate) fn discover(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_owned(),
            state: inspect_manifest(data_dir),
        }
    }

    pub(crate) fn refresh(&mut self) {
        self.state = inspect_manifest(&self.data_dir);
    }

    pub(crate) fn status_json(&self) -> Value {
        let (artifact_state, reason, release_id, artifact_sha256): (
            &str,
            &str,
            Option<&str>,
            Option<&str>,
        ) = match &self.state {
            #[cfg(unix)]
            WalletArtifactState::Missing => ("missing", "walletArtifactMissing", None, None),
            WalletArtifactState::Rejected(reason) => ("rejected", reason.code(), None, None),
            #[cfg(unix)]
            WalletArtifactState::IntegrityChecked(artifact) => (
                "integrityChecked",
                "walletArtifactAuthenticityUnavailable",
                Some(artifact.release_id.as_str()),
                Some(artifact.artifact_sha256.as_str()),
            ),
        };
        json!({
            "manifestSchemaVersion": WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            "requiredWalletAbiVersion": WALLET_ABI_VERSION,
            "requiredServiceProtocolVersion": WALLET_SERVICE_PROTOCOL_VERSION,
            "requiredProviderSchemaVersion": WALLET_PROVIDER_SCHEMA_VERSION,
            "maximumFrameBytes": WALLET_ABI_MAX_FRAME_BYTES,
            "artifactState": artifact_state,
            "artifactReleaseId": release_id,
            "artifactSha256": artifact_sha256,
            "artifactAuthenticityVerified": false,
            "serviceTransportAvailable": false,
            "runtimeNegotiated": false,
            "providerAuthorityContextAvailable": false,
            "available": false,
            "reason": reason
        })
    }

    pub(crate) fn unavailable_code(&self) -> &'static str {
        match &self.state {
            #[cfg(unix)]
            WalletArtifactState::Missing => "walletArtifactMissing",
            WalletArtifactState::Rejected(reason) => reason.code(),
            #[cfg(unix)]
            WalletArtifactState::IntegrityChecked(_) => "walletArtifactAuthenticityUnavailable",
        }
    }

    pub(crate) fn unavailable_message(&self) -> &'static str {
        match &self.state {
            #[cfg(unix)]
            WalletArtifactState::Missing => {
                "the independently released wallet service artifact is not installed"
            }
            WalletArtifactState::Rejected(_) => {
                "the installed wallet service artifact failed closed during local integrity checks"
            }
            #[cfg(unix)]
            WalletArtifactState::IntegrityChecked(_) => {
                "the wallet artifact passed local integrity checks, but no signed service transport is released and the browser engine does not expose its opaque provider-authority context to this native host"
            }
        }
    }
}

#[derive(Clone, Debug)]
enum WalletArtifactState {
    #[cfg(unix)]
    Missing,
    Rejected(WalletArtifactRejection),
    #[cfg(unix)]
    IntegrityChecked(IntegrityCheckedWalletArtifact),
}

#[derive(Clone, Copy, Debug)]
enum WalletArtifactRejection {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    #[cfg(unix)]
    UnsafeDirectory,
    #[cfg(unix)]
    UnsafeManifest,
    #[cfg(unix)]
    ManifestSize,
    #[cfg(unix)]
    ManifestEncoding,
    #[cfg(unix)]
    ManifestContract,
    #[cfg(unix)]
    ArtifactMissing,
    #[cfg(unix)]
    UnsafeArtifact,
    #[cfg(unix)]
    ArtifactSize,
    #[cfg(unix)]
    ArtifactDigest,
    #[cfg(unix)]
    ArtifactRead,
}

impl WalletArtifactRejection {
    const fn code(self) -> &'static str {
        match self {
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "walletArtifactPlatformUnsupported",
            #[cfg(unix)]
            Self::UnsafeDirectory => "walletArtifactDirectoryUnsafe",
            #[cfg(unix)]
            Self::UnsafeManifest => "walletArtifactManifestUnsafe",
            #[cfg(unix)]
            Self::ManifestSize => "walletArtifactManifestSize",
            #[cfg(unix)]
            Self::ManifestEncoding => "walletArtifactManifestInvalid",
            #[cfg(unix)]
            Self::ManifestContract => "walletArtifactContractMismatch",
            #[cfg(unix)]
            Self::ArtifactMissing => "walletArtifactMissing",
            #[cfg(unix)]
            Self::UnsafeArtifact => "walletArtifactUnsafe",
            #[cfg(unix)]
            Self::ArtifactSize => "walletArtifactSize",
            #[cfg(unix)]
            Self::ArtifactDigest => "walletArtifactDigestMismatch",
            #[cfg(unix)]
            Self::ArtifactRead => "walletArtifactUnreadable",
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct IntegrityCheckedWalletArtifact {
    release_id: String,
    artifact_sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactManifest {
    manifest_schema_version: u16,
    wallet_abi_version: u16,
    service_protocol_version: u16,
    provider_schema_version: u16,
    maximum_frame_bytes: u32,
    release_id: String,
    artifact: String,
    artifact_sha256: String,
    capabilities: Vec<String>,
}

#[cfg(unix)]
fn inspect_manifest(data_dir: &Path) -> WalletArtifactState {
    let data_directory = match open_directory_nofollow(data_dir) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WalletArtifactState::Missing;
        }
        Err(_) => return rejected(WalletArtifactRejection::UnsafeDirectory),
    };
    if !private_directory(&data_directory) {
        return rejected(WalletArtifactRejection::UnsafeDirectory);
    }

    let artifact_directory =
        match open_directory_at_nofollow(&data_directory, WALLET_ARTIFACT_DIRECTORY) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return WalletArtifactState::Missing;
            }
            Err(_) => return rejected(WalletArtifactRejection::UnsafeDirectory),
        };
    if !private_directory(&artifact_directory) {
        return rejected(WalletArtifactRejection::UnsafeDirectory);
    }

    let mut manifest_file =
        match open_file_at_nofollow(&artifact_directory, WALLET_ARTIFACT_MANIFEST) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return WalletArtifactState::Missing;
            }
            Err(_) => return rejected(WalletArtifactRejection::UnsafeManifest),
        };
    let manifest_metadata = match manifest_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::UnsafeManifest),
    };
    if !private_regular_file(&manifest_metadata) {
        return rejected(WalletArtifactRejection::UnsafeManifest);
    }
    if manifest_metadata.len() == 0 || manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return rejected(WalletArtifactRejection::ManifestSize);
    }
    let manifest_bytes = match read_manifest(&mut manifest_file) {
        Ok(bytes) => bytes,
        Err(reason) => return rejected(reason),
    };
    let final_manifest_metadata = match manifest_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::UnsafeManifest),
    };
    if manifest_bytes.len() as u64 != manifest_metadata.len()
        || !same_open_file(&manifest_metadata, &final_manifest_metadata)
    {
        return rejected(WalletArtifactRejection::ManifestSize);
    }

    let manifest = match serde_json::from_slice::<WalletArtifactManifest>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(_) => return rejected(WalletArtifactRejection::ManifestEncoding),
    };
    if !valid_manifest_contract(&manifest) {
        return rejected(WalletArtifactRejection::ManifestContract);
    }

    let mut artifact_file = match open_file_at_nofollow(&artifact_directory, &manifest.artifact) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return rejected(WalletArtifactRejection::ArtifactMissing);
        }
        Err(_) => return rejected(WalletArtifactRejection::ArtifactRead),
    };
    let artifact_metadata = match artifact_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::ArtifactRead),
    };
    if !private_regular_file(&artifact_metadata) || !source_is_executable(&artifact_metadata) {
        return rejected(WalletArtifactRejection::UnsafeArtifact);
    }
    if artifact_metadata.len() == 0 || artifact_metadata.len() > MAX_ARTIFACT_BYTES {
        return rejected(WalletArtifactRejection::ArtifactSize);
    }
    let (digest, bytes_read) = match sha256_reader(&mut artifact_file, MAX_ARTIFACT_BYTES) {
        Ok(result) => result,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return rejected(WalletArtifactRejection::ArtifactSize);
        }
        Err(_) => return rejected(WalletArtifactRejection::ArtifactRead),
    };
    let final_artifact_metadata = match artifact_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::ArtifactRead),
    };
    if bytes_read != artifact_metadata.len()
        || !same_open_file(&artifact_metadata, &final_artifact_metadata)
    {
        return rejected(WalletArtifactRejection::ArtifactRead);
    }
    if digest != manifest.artifact_sha256 {
        return rejected(WalletArtifactRejection::ArtifactDigest);
    }

    WalletArtifactState::IntegrityChecked(IntegrityCheckedWalletArtifact {
        release_id: manifest.release_id,
        artifact_sha256: digest,
    })
}

#[cfg(not(unix))]
fn inspect_manifest(_data_dir: &Path) -> WalletArtifactState {
    rejected(WalletArtifactRejection::UnsupportedPlatform)
}

const fn rejected(reason: WalletArtifactRejection) -> WalletArtifactState {
    WalletArtifactState::Rejected(reason)
}

#[cfg(unix)]
fn valid_manifest_contract(manifest: &WalletArtifactManifest) -> bool {
    manifest.manifest_schema_version == WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION
        && manifest.wallet_abi_version == WALLET_ABI_VERSION
        && manifest.service_protocol_version == WALLET_SERVICE_PROTOCOL_VERSION
        && manifest.provider_schema_version == WALLET_PROVIDER_SCHEMA_VERSION
        && manifest.maximum_frame_bytes == WALLET_ABI_MAX_FRAME_BYTES
        && valid_token(&manifest.release_id, MAX_RELEASE_ID_BYTES)
        && valid_artifact_name(&manifest.artifact)
        && is_lower_hex(&manifest.artifact_sha256, 64)
        && exact_capabilities(&manifest.capabilities)
}

#[cfg(unix)]
fn exact_capabilities(capabilities: &[String]) -> bool {
    if capabilities.len() != REQUIRED_CAPABILITIES.len() {
        return false;
    }
    let mut unique = BTreeSet::new();
    capabilities.iter().all(|capability| {
        valid_token(capability, 64)
            && REQUIRED_CAPABILITIES.contains(&capability.as_str())
            && unique.insert(capability.as_str())
    })
}

#[cfg(unix)]
fn valid_artifact_name(value: &str) -> bool {
    if !valid_token(value, MAX_ARTIFACT_NAME_BYTES)
        || value.bytes().any(|byte| matches!(byte, b':' | b'+'))
    {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && path.components().count() == 1
}

#[cfg(unix)]
fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
}

#[cfg(unix)]
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(unix)]
fn read_manifest(file: &mut File) -> Result<Vec<u8>, WalletArtifactRejection> {
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WalletArtifactRejection::UnsafeManifest)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(WalletArtifactRejection::ManifestSize);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn sha256_reader(file: &mut File, maximum: u64) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file size overflow"))?;
        if total > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file exceeds bounded digest size",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        total,
    ))
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `path` is NUL-terminated and remains alive for the call. A
    // successful descriptor is immediately owned by `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn open_directory_at_nofollow(directory: &File, name: &str) -> io::Result<File> {
    open_at_nofollow(directory, name, libc::O_DIRECTORY)
}

#[cfg(unix)]
fn open_file_at_nofollow(directory: &File, name: &str) -> io::Result<File> {
    open_at_nofollow(directory, name, libc::O_NONBLOCK)
}

#[cfg(unix)]
fn open_at_nofollow(directory: &File, name: &str, flags: i32) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: `name` is NUL-terminated and remains alive for the call. The
    // directory descriptor is borrowed for the call, and a successful result
    // is immediately transferred to `File`.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | flags,
        )
    };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn file_from_descriptor(descriptor: i32) -> io::Result<File> {
    use std::os::fd::FromRawFd;

    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was returned by `open`/`openat`, is non-negative,
    // and ownership is transferred exactly once to this `File`.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn private_directory(directory: &File) -> bool {
    directory.metadata().is_ok_and(|metadata| {
        metadata.is_dir() && source_is_owned_and_not_shared_writable(&metadata)
    })
}

#[cfg(unix)]
fn private_regular_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.is_file()
        && metadata.nlink() == 1
        && source_is_owned_and_not_shared_writable(metadata)
}

#[cfg(unix)]
fn source_is_owned_and_not_shared_writable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `geteuid` has no arguments or memory-safety preconditions.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0
}

#[cfg(unix)]
fn source_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(unix)]
fn same_open_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn absent_artifact_is_explicitly_unavailable() {
        let root = test_root("missing");
        let discovery = WalletAbiDiscovery::discover(&root);
        assert_eq!(discovery.unavailable_code(), "walletArtifactMissing");
        assert_eq!(discovery.status_json()["available"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_abi_version_fails_closed_before_artifact_admission() {
        let root = test_root("wrong-version");
        let directory = root.join(WALLET_ARTIFACT_DIRECTORY);
        fs::create_dir_all(&directory).unwrap();
        let artifact = directory.join("wallet-service");
        fs::write(&artifact, b"fixture executable").unwrap();
        make_executable(&artifact);
        let mut manifest = fixture_manifest(&artifact);
        manifest.wallet_abi_version = WALLET_ABI_VERSION + 1;
        fs::write(
            directory.join(WALLET_ARTIFACT_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let discovery = WalletAbiDiscovery::discover(&root);
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactContractMismatch"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn integrity_checked_artifact_remains_unavailable_without_runtime_and_authority_joins() {
        let root = test_root("integrity-checked");
        let directory = root.join(WALLET_ARTIFACT_DIRECTORY);
        fs::create_dir_all(&directory).unwrap();
        let artifact = directory.join("wallet-service");
        fs::write(&artifact, b"fixture executable").unwrap();
        make_executable(&artifact);
        let manifest = fixture_manifest(&artifact);
        fs::write(
            directory.join(WALLET_ARTIFACT_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let discovery = WalletAbiDiscovery::discover(&root);
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactAuthenticityUnavailable"
        );
        assert_eq!(discovery.status_json()["artifactState"], "integrityChecked");
        assert_eq!(discovery.status_json()["runtimeNegotiated"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn capability_contract_rejects_duplicates_and_unknown_values() {
        let mut manifest = manifest_without_artifact_io();
        manifest.capabilities[1] = manifest.capabilities[0].clone();
        assert!(!valid_manifest_contract(&manifest));

        let mut manifest = manifest_without_artifact_io();
        manifest.capabilities[1] = "future_capability".to_owned();
        assert!(!valid_manifest_contract(&manifest));
    }

    #[test]
    fn artifact_name_rejects_windows_ambiguous_characters() {
        assert!(!valid_artifact_name("wallet:service"));
        assert!(!valid_artifact_name("wallet+service"));
    }

    fn fixture_manifest(artifact: &Path) -> WalletArtifactManifest {
        let mut artifact_file = File::open(artifact).unwrap();
        let (artifact_sha256, _) = sha256_reader(&mut artifact_file, MAX_ARTIFACT_BYTES).unwrap();
        WalletArtifactManifest {
            artifact: artifact
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            artifact_sha256,
            ..manifest_without_artifact_io()
        }
    }

    fn manifest_without_artifact_io() -> WalletArtifactManifest {
        WalletArtifactManifest {
            manifest_schema_version: WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            wallet_abi_version: WALLET_ABI_VERSION,
            service_protocol_version: WALLET_SERVICE_PROTOCOL_VERSION,
            provider_schema_version: WALLET_PROVIDER_SCHEMA_VERSION,
            maximum_frame_bytes: WALLET_ABI_MAX_FRAME_BYTES,
            release_id: "wallet-fixture-v2".to_owned(),
            artifact: "wallet-service".to_owned(),
            artifact_sha256: "00".repeat(32),
            capabilities: REQUIRED_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hns-wallet-abi-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
