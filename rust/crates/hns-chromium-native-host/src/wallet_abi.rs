//! Admission boundary for an independently released Chromium wallet service.
//!
//! The wallet repository owns signed-artifact manifest schema v2. This module
//! consumes that exact contract, preserves the existing no-follow same-handle
//! integrity checks, and adds verifier-owned authenticity, qualification,
//! anti-rollback, and Linux sealed-executable admission. The production trust
//! and qualification tables intentionally remain empty until a real wallet
//! service release is reviewed. Provider, transport, authority, and value
//! availability therefore remain false.

#[cfg(unix)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(target_os = "linux")]
use getrandom::fill as fill_random;
#[cfg(target_os = "linux")]
use hns_chromium_platform_runtime::NetworkKind;
#[cfg(unix)]
use ring::signature::{self, UnparsedPublicKey};
#[cfg(unix)]
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fmt;
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::process::{ChildStdin, ChildStdout};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const WALLET_ABI_VERSION: u16 = 2;
pub(crate) const WALLET_SERVICE_PROTOCOL_VERSION: u16 = 2;
pub(crate) const WALLET_PROVIDER_SCHEMA_VERSION: u16 = 1;
pub(crate) const WALLET_ABI_MAX_FRAME_BYTES: u32 = 1_048_576;
/// No production HRM/HNSA-to-wallet consumer is qualified in this release.
pub(crate) const HRM_HNSA_WALLET_CONSUMER_RELEASE_QUALIFIED: bool = false;
#[cfg(target_os = "linux")]
const WALLET_SERVICE_SESSION_BYTES: usize = 32;
#[cfg(target_os = "linux")]
const WALLET_SERVICE_REQUEST_ID_BYTES: usize = 16;
#[cfg(target_os = "linux")]
const MAX_NEGOTIATED_SERVICE_CAPABILITIES: usize = 64;
#[cfg(target_os = "linux")]
const MAX_WALLET_SERVICE_FAILURE_MESSAGE_BYTES: usize = 1_024;
#[cfg(target_os = "linux")]
const MAX_WALLET_READ_ITEMS: usize = 128;
#[cfg(target_os = "linux")]
const MAX_WALLET_PUBLIC_STRING_BYTES: usize = 4_096;
#[cfg(target_os = "linux")]
const MAX_WALLET_RECEIVE_TARGET_BYTES: usize = 512;
#[cfg(target_os = "linux")]
const MAX_WALLET_DATABASE_NAME_BYTES: usize = 128;
#[cfg(target_os = "linux")]
const MAX_WALLET_SERVICE_OPEN_DESCRIPTORS: usize = 4_096;
/// Fixed child-only descriptor reserved for the opaque wallet bootstrap
/// packet. Standard input and output remain exclusively private ABI v2.
#[cfg(target_os = "linux")]
const WALLET_BOOTSTRAP_DESCRIPTOR: RawFd = 3;
#[cfg(target_os = "linux")]
const FIRST_WALLET_CHILD_AUXILIARY_DESCRIPTOR: RawFd = WALLET_BOOTSTRAP_DESCRIPTOR + 1;
const WALLET_APPROVAL_SCHEMA_VERSION: u16 = 3;
const WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION: u16 = 2;
#[cfg(unix)]
const WALLET_ARTIFACT_DIRECTORY: &str = "wallet-abi-v2";
#[cfg(unix)]
const WALLET_ARTIFACT_MANIFEST: &str = "manifest.json";
#[cfg(unix)]
const WALLET_ANTI_ROLLBACK_STATE: &str = "wallet-abi-v2-admission-state.json";
#[cfg(unix)]
const WALLET_ANTI_ROLLBACK_LOCK: &str = "wallet-abi-v2-admission.lock";
#[cfg(unix)]
const WALLET_ANTI_ROLLBACK_STATE_SCHEMA_VERSION: u16 = 1;
#[cfg(unix)]
const WALLET_SOURCE_REPOSITORY: &str = "https://github.com/handshake-rs/hns-wallet-rs";
#[cfg(unix)]
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
#[cfg(unix)]
const MAX_ANTI_ROLLBACK_STATE_BYTES: u64 = 64 * 1024;
#[cfg(unix)]
const MAX_ANTI_ROLLBACK_RELEASE_LINES: usize = 16;
#[cfg(unix)]
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(unix)]
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
#[cfg(unix)]
const REQUIRED_BASE_CAPABILITIES: [&str; 5] = [
    "canonicalFraming",
    "restartIsolation",
    "opaqueAuthorityRegistry",
    "structuredApprovals",
    "typedEvents",
];
#[cfg(unix)]
const SERVICE_CAPABILITIES: [&str; 12] = [
    "canonicalFraming",
    "restartIsolation",
    "opaqueAuthorityRegistry",
    "persistentPermissions",
    "structuredApprovals",
    "typedEvents",
    "walletOperations",
    "hnsReadOperationsV1",
    "hnsWalletAuthorityContextV1",
    "providerDispatch",
    "valueMovement",
    "browserIntegration",
];
#[cfg(unix)]
const SIGNATURE_ALGORITHM: &str = "ed25519";
#[cfg(unix)]
const SIGNATURE_CANONICALIZATION: &str = "JCS-RFC8785";
#[cfg(unix)]
const ANTI_ROLLBACK_CHECKSUM_CONTEXT: &[u8] = b"hns-dane-browser-wallet-anti-rollback-state-v1\0";

/// No developer or fixture key is compiled into this production table.
#[cfg(unix)]
const PRODUCTION_WALLET_TRUST_ROOTS: &[ProductionWalletTrustRoot] = &[];
/// Qualification is an exact manifest/artifact pin, not a signer-wide grant.
#[cfg(unix)]
const PRODUCTION_QUALIFIED_WALLET_RELEASES: &[ProductionQualifiedWalletRelease] = &[];
/// A release-line floor remains verifier-owned even if user state is removed.
#[cfg(unix)]
const PRODUCTION_WALLET_RELEASE_FLOORS: &[ProductionWalletReleaseFloor] = &[];

#[cfg(unix)]
struct ProductionWalletTrustRoot {
    key_id: &'static str,
    release_line: &'static str,
    public_key: &'static [u8; 32],
    first_sequence: u64,
    last_sequence: u64,
}

#[cfg(unix)]
struct ProductionQualifiedWalletRelease {
    key_id: &'static str,
    release_line: &'static str,
    sequence: u64,
    release_id: &'static str,
    target_triple: &'static str,
    manifest_sha256: &'static str,
    artifact_sha256: &'static str,
    trusted_genesis: bool,
}

#[cfg(unix)]
struct ProductionWalletReleaseFloor {
    release_line: &'static str,
    minimum_sequence: u64,
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct WalletAbiVerifierConfiguration {
    trust_roots: Vec<WalletTrustRoot>,
    qualified_releases: Vec<QualifiedWalletRelease>,
    release_floors: Vec<WalletReleaseFloor>,
}

#[cfg(unix)]
impl WalletAbiVerifierConfiguration {
    fn production() -> Self {
        Self {
            trust_roots: PRODUCTION_WALLET_TRUST_ROOTS
                .iter()
                .map(|root| WalletTrustRoot {
                    key_id: root.key_id.to_owned(),
                    release_line: root.release_line.to_owned(),
                    public_key: root.public_key.to_vec(),
                    first_sequence: root.first_sequence,
                    last_sequence: root.last_sequence,
                })
                .collect(),
            qualified_releases: PRODUCTION_QUALIFIED_WALLET_RELEASES
                .iter()
                .map(|release| QualifiedWalletRelease {
                    key_id: release.key_id.to_owned(),
                    release_line: release.release_line.to_owned(),
                    sequence: release.sequence,
                    release_id: release.release_id.to_owned(),
                    target_triple: release.target_triple.to_owned(),
                    manifest_sha256: release.manifest_sha256.to_owned(),
                    artifact_sha256: release.artifact_sha256.to_owned(),
                    trusted_genesis: release.trusted_genesis,
                })
                .collect(),
            release_floors: PRODUCTION_WALLET_RELEASE_FLOORS
                .iter()
                .map(|floor| WalletReleaseFloor {
                    release_line: floor.release_line.to_owned(),
                    minimum_sequence: floor.minimum_sequence,
                })
                .collect(),
        }
    }

    fn trust_root(
        &self,
        key_id: &str,
        release_line: &str,
        sequence: u64,
    ) -> Option<&WalletTrustRoot> {
        self.trust_roots.iter().find(|root| {
            root.key_id == key_id
                && root.release_line == release_line
                && (root.first_sequence..=root.last_sequence).contains(&sequence)
        })
    }

    fn qualified_release(
        &self,
        manifest: &WalletArtifactManifest,
        manifest_sha256: &str,
    ) -> Option<&QualifiedWalletRelease> {
        self.qualified_releases.iter().find(|release| {
            release.key_id == manifest.signature.key_id
                && release.release_line == manifest.anti_rollback.release_line
                && release.sequence == manifest.anti_rollback.sequence
                && release.release_id == manifest.release.release_id
                && release.target_triple == manifest.target.target_triple
                && release.manifest_sha256 == manifest_sha256
                && release.artifact_sha256 == manifest.release.artifact_sha256
        })
    }

    fn minimum_sequence(&self, release_line: &str) -> Option<u64> {
        self.release_floors
            .iter()
            .find(|floor| floor.release_line == release_line)
            .map(|floor| floor.minimum_sequence)
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct WalletTrustRoot {
    key_id: String,
    release_line: String,
    public_key: Vec<u8>,
    first_sequence: u64,
    last_sequence: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct QualifiedWalletRelease {
    key_id: String,
    release_line: String,
    sequence: u64,
    release_id: String,
    target_triple: String,
    manifest_sha256: String,
    artifact_sha256: String,
    trusted_genesis: bool,
}

#[cfg(unix)]
#[derive(Debug)]
struct WalletReleaseFloor {
    release_line: String,
    minimum_sequence: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
enum NegotiatedWalletServiceCapability {
    CanonicalFraming,
    RestartIsolation,
    OpaqueAuthorityRegistry,
    PersistentPermissions,
    StructuredApprovals,
    TypedEvents,
    WalletOperations,
    HnsReadOperationsV1,
    HnsWalletAuthorityContextV1,
    ProviderDispatch,
    ValueMovement,
    BrowserIntegration,
}

#[cfg(target_os = "linux")]
const WALLET_READ_SESSION_REQUIRED_CAPABILITIES: [NegotiatedWalletServiceCapability; 7] = [
    NegotiatedWalletServiceCapability::CanonicalFraming,
    NegotiatedWalletServiceCapability::RestartIsolation,
    NegotiatedWalletServiceCapability::OpaqueAuthorityRegistry,
    NegotiatedWalletServiceCapability::StructuredApprovals,
    NegotiatedWalletServiceCapability::TypedEvents,
    NegotiatedWalletServiceCapability::WalletOperations,
    NegotiatedWalletServiceCapability::HnsReadOperationsV1,
];

#[cfg(target_os = "linux")]
// The persistent standalone service reports permission persistence and
// provider dispatch as process capabilities even for native wallet reads.
// They may pass hello validation, but the closed request enum below cannot
// express provider, permission, approval, unlock, lock, or mutation calls.
// HnsReadOperationsV1 freezes the enum's exact six-operation non-workflow set.
const WALLET_READ_SESSION_ALLOWED_CAPABILITIES: [NegotiatedWalletServiceCapability; 10] = [
    NegotiatedWalletServiceCapability::CanonicalFraming,
    NegotiatedWalletServiceCapability::RestartIsolation,
    NegotiatedWalletServiceCapability::OpaqueAuthorityRegistry,
    NegotiatedWalletServiceCapability::PersistentPermissions,
    NegotiatedWalletServiceCapability::StructuredApprovals,
    NegotiatedWalletServiceCapability::TypedEvents,
    NegotiatedWalletServiceCapability::WalletOperations,
    NegotiatedWalletServiceCapability::HnsReadOperationsV1,
    NegotiatedWalletServiceCapability::HnsWalletAuthorityContextV1,
    NegotiatedWalletServiceCapability::ProviderDispatch,
];

#[cfg(target_os = "linux")]
impl NegotiatedWalletServiceCapability {
    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "canonicalFraming" => Some(Self::CanonicalFraming),
            "restartIsolation" => Some(Self::RestartIsolation),
            "opaqueAuthorityRegistry" => Some(Self::OpaqueAuthorityRegistry),
            "persistentPermissions" => Some(Self::PersistentPermissions),
            "structuredApprovals" => Some(Self::StructuredApprovals),
            "typedEvents" => Some(Self::TypedEvents),
            "walletOperations" => Some(Self::WalletOperations),
            "hnsReadOperationsV1" => Some(Self::HnsReadOperationsV1),
            "hnsWalletAuthorityContextV1" => Some(Self::HnsWalletAuthorityContextV1),
            "providerDispatch" => Some(Self::ProviderDispatch),
            "valueMovement" => Some(Self::ValueMovement),
            "browserIntegration" => Some(Self::BrowserIntegration),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
fn wallet_read_session_capability_ceiling(
    admitted_capabilities: &BTreeSet<NegotiatedWalletServiceCapability>,
) -> io::Result<BTreeSet<NegotiatedWalletServiceCapability>> {
    if !WALLET_READ_SESSION_REQUIRED_CAPABILITIES
        .iter()
        .all(|capability| admitted_capabilities.contains(capability))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wallet artifact does not admit the required read-session capabilities",
        ));
    }
    let allowed = WALLET_READ_SESSION_ALLOWED_CAPABILITIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let ceiling = admitted_capabilities
        .intersection(&allowed)
        .copied()
        .collect::<BTreeSet<_>>();
    if !WALLET_READ_SESSION_REQUIRED_CAPABILITIES
        .iter()
        .all(|capability| ceiling.contains(capability))
        || ceiling.contains(&NegotiatedWalletServiceCapability::ValueMovement)
        || ceiling.contains(&NegotiatedWalletServiceCapability::BrowserIntegration)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wallet read-session capability ceiling is invalid",
        ));
    }
    Ok(ceiling)
}

/// Canonical Handshake network identity carried by the private wallet wire.
///
/// This is an encoding of the native host's already-selected `NetworkKind`,
/// not an authority supplied by the wallet service. Every use is checked
/// against the canonical engine network name and magic before it can become a
/// wallet authority context.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum WalletHandshakeNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

#[cfg(target_os = "linux")]
impl WalletHandshakeNetwork {
    const fn from_kind(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Mainnet => Self::Mainnet,
            NetworkKind::Testnet => Self::Testnet,
            NetworkKind::Regtest => Self::Regtest,
        }
    }

    fn matches_kind_and_magic(self, network: NetworkKind, network_magic: u32) -> bool {
        self == Self::from_kind(network) && network.network().magic == network_magic
    }
}

/// Exact native-only wallet namespace lease claim selected by a trusted
/// bootstrap source. The network magic comes only from canonical engine
/// parameters, and the generation is never accepted from the service alone.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct WalletNamespaceLeaseClaim {
    network: NetworkKind,
    network_magic: u32,
    namespace_id: [u8; 16],
    generation: u64,
}

#[cfg(target_os = "linux")]
impl WalletNamespaceLeaseClaim {
    #[allow(dead_code)]
    pub(crate) fn new(
        network: NetworkKind,
        namespace_id: [u8; 16],
        generation: u64,
    ) -> io::Result<Self> {
        if namespace_id.iter().all(|byte| *byte == 0) || generation == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wallet namespace lease identity and generation must be nonzero",
            ));
        }
        Ok(Self {
            network,
            network_magic: network.network().magic,
            namespace_id,
            generation,
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for WalletNamespaceLeaseClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletNamespaceLeaseClaim")
            .field("network", &"<bound>")
            .field("network_magic", &"<bound>")
            .field("namespace_id", &"<bound>")
            .field("generation", &"<bound>")
            .finish()
    }
}

/// Broker-owned currentness guard for one wallet storage namespace.
///
/// Implementations must call `operation` synchronously at most once and only
/// while the exact lease claim and bundled retained database namespace remain
/// current. `true` means the claim was held both at callback entry and at its
/// release boundary; loss or fence replacement during the callback must return
/// `false`. Returning a revision or checking it once is not equivalent to
/// holding this guard through use. Callbacks must stay read-only because an
/// external side effect could escape before a failed release-boundary check.
#[cfg(target_os = "linux")]
pub(crate) trait WalletNamespaceLeaseGuard {
    fn use_if_current(
        &mut self,
        claim: WalletNamespaceLeaseClaim,
        operation: &mut dyn FnMut(),
    ) -> bool;
}

#[cfg(target_os = "linux")]
enum WalletNamespaceLeaseUseError {
    GuardDenied,
    Operation(io::Error),
}

/// Session-held, nonserializable namespace exclusion. A defensive wrapper
/// prevents a malformed guard from invoking a dependent operation more than
/// once or claiming success without invoking it.
#[cfg(target_os = "linux")]
pub(crate) struct WalletNamespaceLease {
    claim: WalletNamespaceLeaseClaim,
    guard: Box<dyn WalletNamespaceLeaseGuard>,
}

#[cfg(target_os = "linux")]
impl WalletNamespaceLease {
    #[allow(dead_code)]
    pub(crate) fn new(
        claim: WalletNamespaceLeaseClaim,
        guard: Box<dyn WalletNamespaceLeaseGuard>,
    ) -> Self {
        Self { claim, guard }
    }

    fn use_if_current<T>(
        &mut self,
        operation: impl FnOnce(WalletNamespaceLeaseClaim) -> io::Result<T>,
    ) -> Result<T, WalletNamespaceLeaseUseError> {
        let mut operation = Some(operation);
        let mut operation_result = None;
        let mut callback_count = 0_u8;
        let claim = self.claim;
        let mut guarded_operation = || {
            callback_count = callback_count.saturating_add(1);
            let Some(operation) = operation.take() else {
                return;
            };
            operation_result = Some(operation(claim));
        };
        let guard_succeeded = self.guard.use_if_current(claim, &mut guarded_operation);
        if callback_count != 1 || !guard_succeeded {
            return Err(WalletNamespaceLeaseUseError::GuardDenied);
        }
        match operation_result {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => Err(WalletNamespaceLeaseUseError::Operation(error)),
            None => Err(WalletNamespaceLeaseUseError::GuardDenied),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for WalletNamespaceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletNamespaceLease")
            .field("claim", &"<bound>")
            .field("guard", &"<opaque currentness guard>")
            .finish()
    }
}

/// Retained identity for one explicitly configured, pre-existing wallet
/// database. This type never discovers wallet state and is intentionally not
/// serializable or exposed through native messaging.
#[cfg(target_os = "linux")]
pub(crate) struct TrustedWalletDatabaseConfiguration {
    database_path: PathBuf,
    parent_path: PathBuf,
    parent_directory: File,
    parent_metadata: fs::Metadata,
    database_file: File,
    database_metadata: fs::Metadata,
    database_name: String,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl TrustedWalletDatabaseConfiguration {
    pub(crate) fn open(database_path: &Path) -> io::Result<Self> {
        if !database_path.is_absolute()
            || !database_path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wallet database path must be an exact absolute path",
            ));
        }
        let database_name = database_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_wallet_database_name(name))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "wallet database basename is outside the closed filename contract",
                )
            })?
            .to_owned();
        let parent_path = database_path
            .parent()
            .filter(|parent| parent.is_absolute())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "wallet database must have an absolute parent directory",
                )
            })?
            .to_owned();
        let parent_directory = open_absolute_directory_path_nofollow(&parent_path)?;
        let parent_metadata = parent_directory.metadata()?;
        if !private_wallet_database_directory(&parent_directory) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet database parent directory is not owner-private",
            ));
        }
        let database_file = open_file_at_nofollow(&parent_directory, &database_name)?;
        let database_metadata = database_file.metadata()?;
        if !private_wallet_database_file(&database_metadata) || database_metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet database is not a nonempty owner-private single-link file",
            ));
        }
        if fs::canonicalize(database_path)? != database_path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet database path is not canonical",
            ));
        }
        let configuration = Self {
            database_path: database_path.to_owned(),
            parent_path,
            parent_directory,
            parent_metadata,
            database_file,
            database_metadata,
            database_name,
        };
        configuration.revalidate()?;
        Ok(configuration)
    }

    fn database_path(&self) -> &Path {
        &self.database_path
    }

    fn revalidate(&self) -> io::Result<()> {
        let result = (|| -> io::Result<()> {
            let current_parent = open_absolute_directory_path_nofollow(&self.parent_path)?;
            let current_parent_metadata = current_parent.metadata()?;
            let retained_parent_metadata = self.parent_directory.metadata()?;
            if !same_open_directory(&self.parent_metadata, &current_parent_metadata)
                || !same_open_directory(&self.parent_metadata, &retained_parent_metadata)
                || !private_wallet_database_directory(&current_parent)
                || !private_wallet_database_directory(&self.parent_directory)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wallet database parent identity changed",
                ));
            }

            let current_database = open_file_at_nofollow(&current_parent, &self.database_name)?;
            let retained_path_database =
                open_file_at_nofollow(&self.parent_directory, &self.database_name)?;
            let current_database_metadata = current_database.metadata()?;
            let retained_path_database_metadata = retained_path_database.metadata()?;
            let retained_database_metadata = self.database_file.metadata()?;
            if !same_wallet_database_identity(&self.database_metadata, &current_database_metadata)
                || !same_wallet_database_identity(
                    &self.database_metadata,
                    &retained_path_database_metadata,
                )
                || !same_wallet_database_identity(
                    &self.database_metadata,
                    &retained_database_metadata,
                )
                || !private_wallet_database_file(&current_database_metadata)
                || !private_wallet_database_file(&retained_database_metadata)
                || current_database_metadata.len() == 0
                || retained_database_metadata.len() == 0
                || fs::canonicalize(&self.database_path)? != self.database_path
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wallet database identity changed",
                ));
            }
            Ok(())
        })();
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted wallet database path or identity changed",
            )
        })
    }
}

/// One trusted, single-use launch authorization for a pre-existing wallet
/// database. The descriptor contents are owned by the independently released
/// wallet service and are deliberately opaque to this browser repository.
///
/// This type is not serializable, is not exposed through native messaging,
/// and reveals neither descriptor identity nor packet contents through Debug.
#[cfg(target_os = "linux")]
pub(crate) struct WalletBootstrapLease {
    restart_generation: u64,
    database: TrustedWalletDatabaseConfiguration,
    namespace_lease: WalletNamespaceLease,
    bootstrap_read: File,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl WalletBootstrapLease {
    pub(crate) fn new(
        restart_generation: u64,
        database: TrustedWalletDatabaseConfiguration,
        namespace_lease: WalletNamespaceLease,
        bootstrap_read: File,
    ) -> io::Result<Self> {
        if restart_generation == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wallet bootstrap lease restart generation must be nonzero",
            ));
        }
        require_wallet_bootstrap_read_descriptor(&bootstrap_read)?;
        Ok(Self {
            restart_generation,
            database,
            namespace_lease,
            bootstrap_read,
        })
    }

    fn into_launch_parts(
        self,
        expected_restart_generation: u64,
        expected_network: NetworkKind,
    ) -> io::Result<(
        TrustedWalletDatabaseConfiguration,
        WalletNamespaceLease,
        File,
    )> {
        if self.restart_generation != expected_restart_generation {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet bootstrap lease restart generation mismatch",
            ));
        }
        if self.namespace_lease.claim.network != expected_network
            || self.namespace_lease.claim.network_magic != expected_network.network().magic
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet bootstrap lease network mismatch",
            ));
        }
        Ok((self.database, self.namespace_lease, self.bootstrap_read))
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for WalletBootstrapLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletBootstrapLease")
            .field("restart_generation", &"<bound>")
            .field("database", &"<retained identity>")
            .field("namespace_lease", &"<opaque currentness guard>")
            .field("bootstrap", &"<opaque single-use descriptor>")
            .finish()
    }
}

/// Native-only source of a one-shot bootstrap lease. Production deliberately
/// supplies only the unavailable implementation below until a separately
/// authenticated platform broker is reviewed and qualified.
#[cfg(target_os = "linux")]
pub(crate) trait WalletBootstrapSource {
    /// Transfers a fresh lease for exactly this restart generation. A source
    /// must never reissue a lease consumed by an earlier generation. Its
    /// namespace ID and currentness guard must describe the exact retained
    /// database configuration bundled in the returned lease, not merely a
    /// process-wide or network-wide generation.
    fn take_lease(
        &mut self,
        restart_generation: u64,
        expected_network: NetworkKind,
    ) -> io::Result<Option<WalletBootstrapLease>>;
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub(crate) struct UnavailableWalletBootstrapSource;

#[cfg(target_os = "linux")]
impl WalletBootstrapSource for UnavailableWalletBootstrapSource {
    fn take_lease(
        &mut self,
        _restart_generation: u64,
        _expected_network: NetworkKind,
    ) -> io::Result<Option<WalletBootstrapLease>> {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn require_wallet_bootstrap_read_descriptor(descriptor: &File) -> io::Result<()> {
    let file_descriptor = descriptor.as_raw_fd();
    // SAFETY: both fcntl calls inspect the live descriptor borrowed above and
    // do not retain pointers or mutate memory.
    let descriptor_flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFD) };
    let status_flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFL) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the supplied stat buffer on success and does
    // not retain its pointer.
    let stat_result = unsafe { libc::fstat(file_descriptor, status.as_mut_ptr()) };
    if descriptor_flags < 0 || status_flags < 0 || stat_result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fstat above initialized the complete value.
    let status = unsafe { status.assume_init() };
    if descriptor_flags & libc::FD_CLOEXEC == 0
        || status_flags & libc::O_ACCMODE != libc::O_RDONLY
        || status.st_mode & libc::S_IFMT != libc::S_IFIFO
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wallet bootstrap descriptor must be a close-on-exec read-only pipe",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NegotiatedWalletServiceLimits {
    outer_frame_bytes: u32,
    provider_request_bytes: u32,
    provider_result_bytes: u32,
    provider_event_bytes: u32,
    approval_frame_bytes: u32,
    approval_lifetime_ms: u64,
}

#[cfg(target_os = "linux")]
impl NegotiatedWalletServiceLimits {
    fn is_exact_v2(&self) -> bool {
        self.outer_frame_bytes == WALLET_ABI_MAX_FRAME_BYTES
            && self.provider_request_bytes == 65_536
            && self.provider_result_bytes == 262_144
            && self.provider_event_bytes == 65_536
            && self.approval_frame_bytes == 16_384
            && self.approval_lifetime_ms == 90_000
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WalletHostHelloFrame<'a> {
    Hello { hello: WalletHostHello<'a> },
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletHostHello<'a> {
    protocol_version: u16,
    platform: &'static str,
    host_session_id: &'a str,
    restart_generation: u64,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WalletServiceHelloFrame {
    Hello { hello: WalletServiceHello },
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletServiceHello {
    protocol_version: u16,
    platform: String,
    host_session_id: String,
    service_session_id: String,
    restart_generation: u64,
    capabilities: Vec<NegotiatedWalletServiceCapability>,
    limits: NegotiatedWalletServiceLimits,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WalletHostRequestFrame<'a> {
    Request {
        envelope: WalletHostRequestEnvelope<'a>,
    },
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletHostRequestEnvelope<'a> {
    protocol_version: u16,
    host_session_id: &'a str,
    service_session_id: &'a str,
    restart_generation: u64,
    channel_sequence: u64,
    request_id: &'a str,
    body: WalletReadOnlyServiceRequest,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WalletReadOnlyServiceRequest {
    Wallet {
        request: WalletReadOnlyRequest,
    },
    WalletAuthority {
        request: WalletAuthorityContextRequest,
    },
}

/// Additive native-only authority operation. Keeping this request outside
/// `WalletReadOnlyRequest` preserves the exact six-operation
/// `hnsReadOperationsV1` contract byte-for-byte.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WalletAuthorityContextRequest {
    CurrentHnsContext {
        network: WalletHandshakeNetwork,
        network_magic: u32,
        namespace_id: [u8; 16],
        namespace_lease_generation: u64,
        module: WalletReadOnlyModule,
    },
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WalletReadOnlyRequest {
    Status,
    ListAccounts,
    Balance {
        module: WalletReadOnlyModule,
        account: [u8; 16],
    },
    ReceiveTarget {
        module: WalletReadOnlyModule,
        account: [u8; 16],
    },
    TransactionHistory {
        module: WalletReadOnlyModule,
        account: [u8; 16],
    },
    ModuleStatus {
        module: WalletReadOnlyModule,
    },
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(
    tag = "frameType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WalletServiceResponseFrame {
    Response {
        envelope: WalletServiceResponseEnvelope,
    },
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletServiceResponseEnvelope {
    protocol_version: u16,
    host_session_id: String,
    service_session_id: String,
    restart_generation: u64,
    channel_sequence: u64,
    request_id: String,
    body: WalletReadOnlyServiceResponse,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(
    tag = "result",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WalletReadOnlyServiceResponse {
    Wallet {
        response: WalletReadOnlyResponse,
    },
    WalletAuthority {
        context: WalletServiceHnsAuthorityContext,
    },
    Failure {
        failure: WalletServiceFailure,
    },
}

/// Service evidence joined to trusted browser and broker state before a
/// native-only wallet authority can be used. This wire value is never itself
/// an authority and is never exposed to extension or page JavaScript.
#[cfg(target_os = "linux")]
#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletServiceHnsAuthorityContext {
    network: WalletHandshakeNetwork,
    network_magic: u32,
    namespace_id: [u8; 16],
    namespace_lease_generation: u64,
    active_wallet: [u8; 16],
    account: [u8; 16],
    wallet_authority_revision: u64,
    account_authority_revision: u64,
    locked: bool,
    module: WalletReadOnlyModule,
    persistent_wallet_confirmed: bool,
    recovery_pending: bool,
    retirement_pending: bool,
    hns_reads_ready: bool,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for WalletServiceHnsAuthorityContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletServiceHnsAuthorityContext")
            .field("network", &"<bound>")
            .field("network_magic", &"<bound>")
            .field("namespace_id", &"<bound>")
            .field("namespace_lease_generation", &"<bound>")
            .field("active_wallet", &"<opaque>")
            .field("account", &"<opaque>")
            .field("wallet_authority_revision", &"<bound>")
            .field("account_authority_revision", &"<bound>")
            .field("lifecycle", &"<untrusted>")
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl WalletServiceHnsAuthorityContext {
    fn validates_against(
        &self,
        claim: WalletNamespaceLeaseClaim,
        active_wallet: [u8; 16],
        account: [u8; 16],
    ) -> bool {
        self.network
            .matches_kind_and_magic(claim.network, self.network_magic)
            && self.network_magic == claim.network_magic
            && self.namespace_id == claim.namespace_id
            && self.namespace_lease_generation == claim.generation
            && self.active_wallet.iter().any(|byte| *byte != 0)
            && self.active_wallet == active_wallet
            && self.account.iter().any(|byte| *byte != 0)
            && self.account == account
            && self.wallet_authority_revision != 0
            && self.account_authority_revision != 0
            && !self.locked
            && self.module == WalletReadOnlyModule::Handshake
            && self.persistent_wallet_confirmed
            && !self.recovery_pending
            && !self.retirement_pending
            && self.hns_reads_ready
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum WalletServiceErrorCode {
    InvalidFrame,
    VersionMismatch,
    SessionMismatch,
    SequenceMismatch,
    AuthorityUnknown,
    AuthorityStale,
    PermissionDenied,
    ApprovalStale,
    WalletLocked,
    RateLimited,
    Replay,
    UnsupportedCapability,
    InvalidRequest,
    PersistenceFailure,
    RuntimeFailure,
}

#[cfg(target_os = "linux")]
impl WalletServiceErrorCode {
    fn is_protocol_failure(self) -> bool {
        matches!(
            self,
            Self::InvalidFrame
                | Self::VersionMismatch
                | Self::SessionMismatch
                | Self::SequenceMismatch
                | Self::Replay
                | Self::UnsupportedCapability
        )
    }

    fn operation_error_message(self) -> &'static str {
        match self {
            Self::AuthorityUnknown => "wallet service authority is unknown",
            Self::AuthorityStale => "wallet service authority is stale",
            Self::PermissionDenied => "wallet service denied the operation",
            Self::ApprovalStale => "wallet service approval is stale",
            Self::WalletLocked => "wallet service is locked",
            Self::RateLimited => "wallet service rate limited the operation",
            Self::InvalidRequest => "wallet service rejected the operation",
            Self::PersistenceFailure => "wallet service persistence failed",
            Self::RuntimeFailure => "wallet service runtime failed",
            Self::InvalidFrame
            | Self::VersionMismatch
            | Self::SessionMismatch
            | Self::SequenceMismatch
            | Self::Replay
            | Self::UnsupportedCapability => "wallet service reported a protocol failure",
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletServiceFailure {
    code: WalletServiceErrorCode,
    message: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    unsupported_capability: Option<NegotiatedWalletServiceCapability>,
}

#[cfg(target_os = "linux")]
impl WalletServiceFailure {
    fn validate(&self) -> bool {
        !self.message.is_empty()
            && self.message.len() <= MAX_WALLET_SERVICE_FAILURE_MESSAGE_BYTES
            && self.message.is_ascii()
            && (self.code == WalletServiceErrorCode::UnsupportedCapability)
                == self.unsupported_capability.is_some()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(
    tag = "result",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WalletReadOnlyResponse {
    Status {
        status: WalletReadOnlyStatus,
    },
    Accounts {
        accounts: Vec<WalletReadOnlyAccountSummary>,
    },
    Balance {
        amount: WalletReadOnlyAmount,
    },
    ReceiveTarget {
        target: WalletReadOnlyReceiveTarget,
    },
    TransactionHistory {
        transactions: Vec<WalletReadOnlyTransactionSummary>,
    },
    ModuleStatus {
        status: WalletReadOnlySyncStatus,
    },
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WalletReadOnlyModule {
    Handshake,
    Bitcoin,
    Ethereum,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletReadOnlyStatus {
    pub(crate) locked: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) active_wallet: Option<[u8; 16]>,
    enabled_modules: Vec<WalletReadOnlyModule>,
    pub(crate) mainnet_settlement_enabled: bool,
}

#[cfg(target_os = "linux")]
fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyStatus {
    #[allow(dead_code)]
    pub(crate) fn enabled_modules(&self) -> &[WalletReadOnlyModule] {
        &self.enabled_modules
    }

    fn validate(&self) -> bool {
        !self.mainnet_settlement_enabled
            && self.locked == self.active_wallet.is_none()
            && self
                .active_wallet
                .is_none_or(|wallet| wallet.iter().any(|byte| *byte != 0))
            && self.enabled_modules.len() <= 1
            && self
                .enabled_modules
                .iter()
                .all(|module| *module == WalletReadOnlyModule::Handshake)
            && self
                .enabled_modules
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                == self.enabled_modules.len()
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletReadOnlyAccountSummary {
    pub(crate) account_id: [u8; 16],
    pub(crate) module: WalletReadOnlyModule,
    pub(crate) label: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) receive_display: Option<String>,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyAccountSummary {
    fn validate(&self) -> bool {
        self.account_id.iter().any(|byte| *byte != 0)
            && self.module == WalletReadOnlyModule::Handshake
            && valid_wallet_public_string(&self.label, MAX_WALLET_PUBLIC_STRING_BYTES)
            && self.receive_display.as_ref().is_none_or(|display| {
                valid_wallet_public_string(display, MAX_WALLET_PUBLIC_STRING_BYTES)
            })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum WalletReadOnlyAsset {
    Hns,
    Btc,
    Eth,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalletReadOnlyBaseUnits(u128);

#[cfg(target_os = "linux")]
impl WalletReadOnlyBaseUnits {
    #[allow(dead_code)]
    pub(crate) const fn get(self) -> u128 {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl<'de> Deserialize<'de> for WalletReadOnlyBaseUnits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let canonical = encoded == "0"
            || (!encoded.is_empty()
                && encoded.len() <= 39
                && encoded.as_bytes()[0].is_ascii_digit()
                && encoded.as_bytes()[0] != b'0'
                && encoded.as_bytes()[1..].iter().all(u8::is_ascii_digit));
        if !canonical {
            return Err(serde::de::Error::custom(
                "wallet base units are not canonical decimal u128",
            ));
        }
        encoded
            .parse::<u128>()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("wallet base units exceed u128"))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletReadOnlyAmount {
    pub(crate) asset: WalletReadOnlyAsset,
    pub(crate) base_units: WalletReadOnlyBaseUnits,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyAmount {
    fn validate(&self) -> bool {
        self.asset == WalletReadOnlyAsset::Hns
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletReadOnlyReceiveTarget {
    pub(crate) module: WalletReadOnlyModule,
    pub(crate) account: [u8; 16],
    pub(crate) display: String,
    pub(crate) derivation_index: u32,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyReceiveTarget {
    fn validate(&self, selected_account: [u8; 16]) -> bool {
        self.module == WalletReadOnlyModule::Handshake
            && self.account == selected_account
            && valid_wallet_display_string(&self.display, MAX_WALLET_RECEIVE_TARGET_BYTES)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WalletReadOnlyTransactionStatus {
    Prepared,
    Authorized,
    Broadcast,
    Mempool,
    Confirmed,
    Replaced,
    Conflicted,
    Reorged,
    Dropped,
    Failed,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletReadOnlySignedBaseUnits {
    pub(crate) negative: bool,
    pub(crate) magnitude: WalletReadOnlyBaseUnits,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlySignedBaseUnits {
    fn validate(&self) -> bool {
        !self.negative || self.magnitude.get() != 0
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletReadOnlyTransactionSummary {
    pub(crate) module: WalletReadOnlyModule,
    pub(crate) txid: [u8; 32],
    pub(crate) status: WalletReadOnlyTransactionStatus,
    pub(crate) net_amount: WalletReadOnlySignedBaseUnits,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) fee: Option<WalletReadOnlyBaseUnits>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) block_height: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) first_seen_unix: Option<u64>,
    pub(crate) confirmation_count: u32,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyTransactionSummary {
    fn validate(&self) -> bool {
        self.module == WalletReadOnlyModule::Handshake
            && self.txid.iter().any(|byte| *byte != 0)
            && self.net_amount.validate()
    }
}

#[cfg(target_os = "linux")]
fn validate_wallet_transaction_history(transactions: &[WalletReadOnlyTransactionSummary]) -> bool {
    let unique_txids = transactions
        .iter()
        .map(|transaction| transaction.txid)
        .collect::<BTreeSet<_>>();
    transactions.len() <= MAX_WALLET_READ_ITEMS
        && unique_txids.len() == transactions.len()
        && transactions
            .iter()
            .all(WalletReadOnlyTransactionSummary::validate)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WalletReadOnlySyncPhase {
    Disabled,
    Starting,
    Headers,
    Filters,
    WalletScan,
    Ready,
    Degraded,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletReadOnlySyncStatus {
    pub(crate) phase: WalletReadOnlySyncPhase,
    pub(crate) validated_height: u64,
    pub(crate) scanned_height: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) target_height: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) last_error: Option<String>,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlySyncStatus {
    fn validate(&self) -> bool {
        self.phase == WalletReadOnlySyncPhase::Ready
            && self.validated_height == self.scanned_height
            && self.target_height == Some(self.validated_height)
            && self.last_error.is_none()
    }
}

/// One native-only projection assembled by executing the frozen six-operation
/// HNS read contract in order. Each value-bearing operation has its own live
/// synchronization authority; this aggregate deliberately does not claim one
/// cross-operation chain snapshot.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalletReadOnlyView {
    pub(crate) status: WalletReadOnlyStatus,
    pub(crate) account: WalletReadOnlyAccountSummary,
    pub(crate) balance: WalletReadOnlyAmount,
    pub(crate) receive_target: WalletReadOnlyReceiveTarget,
    pub(crate) transactions: Vec<WalletReadOnlyTransactionSummary>,
    pub(crate) module_status: WalletReadOnlySyncStatus,
}

/// Nonserializable native authority assembled only while the trusted wallet
/// namespace lease is held current. It binds canonical browser network state,
/// the retained wallet database, service channel/restart identity, the active
/// wallet/account and the service's nonzero authority revisions. Consumers
/// receive only a temporary shared borrow inside the lease callback.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) struct WalletHnsAuthorityContext {
    network: NetworkKind,
    network_magic: u32,
    namespace_id: [u8; 16],
    namespace_lease_generation: u64,
    database_device: u64,
    database_inode: u64,
    restart_generation: u64,
    host_session_id: String,
    service_session_id: String,
    active_wallet: [u8; 16],
    account: [u8; 16],
    wallet_authority_revision: u64,
    account_authority_revision: u64,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for WalletHnsAuthorityContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletHnsAuthorityContext")
            .field("network", &"<canonical>")
            .field("network_magic", &"<canonical>")
            .field("namespace_id", &"<bound>")
            .field("namespace_lease_generation", &"<bound>")
            .field("database_device", &"<bound>")
            .field("database_inode", &"<bound>")
            .field("restart_generation", &"<bound>")
            .field("host_session_id", &"<opaque>")
            .field("service_session_id", &"<opaque>")
            .field("active_wallet", &"<opaque>")
            .field("account", &"<opaque>")
            .field("wallet_authority_revision", &"<bound>")
            .field("account_authority_revision", &"<bound>")
            .finish()
    }
}

#[cfg(target_os = "linux")]
fn valid_wallet_public_string(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

#[cfg(target_os = "linux")]
fn valid_wallet_display_string(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalletReadOnlyResponseKind {
    Status,
    Accounts,
    Balance,
    ReceiveTarget,
    TransactionHistory,
    ModuleStatus,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalletServiceResponseKind {
    Wallet(WalletReadOnlyResponseKind),
    WalletAuthority,
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyResponse {
    fn kind(&self) -> WalletReadOnlyResponseKind {
        match self {
            Self::Status { .. } => WalletReadOnlyResponseKind::Status,
            Self::Accounts { .. } => WalletReadOnlyResponseKind::Accounts,
            Self::Balance { .. } => WalletReadOnlyResponseKind::Balance,
            Self::ReceiveTarget { .. } => WalletReadOnlyResponseKind::ReceiveTarget,
            Self::TransactionHistory { .. } => WalletReadOnlyResponseKind::TransactionHistory,
            Self::ModuleStatus { .. } => WalletReadOnlyResponseKind::ModuleStatus,
        }
    }
}

#[cfg(target_os = "linux")]
impl WalletReadOnlyServiceResponse {
    fn kind(&self) -> Option<WalletServiceResponseKind> {
        match self {
            Self::Wallet { response } => Some(WalletServiceResponseKind::Wallet(response.kind())),
            Self::WalletAuthority { .. } => Some(WalletServiceResponseKind::WalletAuthority),
            Self::Failure { .. } => None,
        }
    }
}

#[cfg(target_os = "linux")]
struct WalletServiceProcess {
    child: Option<Child>,
}

#[cfg(target_os = "linux")]
fn terminate_wallet_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
impl WalletServiceProcess {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn terminate(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        terminate_wallet_child(&mut child);
    }

    fn attests_open_wallet_database(&mut self, expected: &fs::Metadata) -> io::Result<()> {
        let child = self.child.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service process is no longer available",
            )
        })?;
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service exited before database identity attestation",
            ));
        }
        let descriptor_directory = PathBuf::from(format!("/proc/{}/fd", child.id()));
        let mut matched = false;
        for (index, entry) in fs::read_dir(descriptor_directory)?.enumerate() {
            if index >= MAX_WALLET_SERVICE_OPEN_DESCRIPTORS {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wallet service descriptor table exceeds the admitted bound",
                ));
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(metadata) = fs::metadata(entry.path()) else {
                continue;
            };
            if same_wallet_database_identity(expected, &metadata) {
                matched = true;
            }
        }
        if !matched || child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service did not retain the admitted database identity",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for WalletServiceProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct WalletServiceController<R: Read + AsRawFd, W: Write + AsRawFd> {
    reader: R,
    writer: W,
    process: Option<WalletServiceProcess>,
    timeout: Duration,
    host_session_id: String,
    service_session_id: String,
    restart_generation: u64,
    next_host_sequence: u64,
    next_service_sequence: u64,
    capabilities: BTreeSet<NegotiatedWalletServiceCapability>,
    selected_active_wallet: Option<[u8; 16]>,
    selected_hns_account: Option<[u8; 16]>,
    poisoned: bool,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) type SpawnedWalletServiceController = WalletServiceController<ChildStdout, ChildStdin>;

#[cfg(target_os = "linux")]
impl WalletServiceController<ChildStdout, ChildStdin> {
    #[allow(dead_code)]
    fn negotiate_spawned(
        mut child: Child,
        admitted_capabilities: BTreeSet<NegotiatedWalletServiceCapability>,
        restart_generation: u64,
        timeout: Duration,
    ) -> io::Result<Self> {
        let reader = match child.stdout.take() {
            Some(reader) => reader,
            None => {
                let mut process = WalletServiceProcess::new(child);
                process.terminate();
                return Err(io::Error::other(
                    "wallet service stdout pipe is unavailable",
                ));
            }
        };
        let writer = match child.stdin.take() {
            Some(writer) => writer,
            None => {
                let mut process = WalletServiceProcess::new(child);
                process.terminate();
                return Err(io::Error::other("wallet service stdin pipe is unavailable"));
            }
        };
        Self::negotiate(
            reader,
            writer,
            Some(WalletServiceProcess::new(child)),
            admitted_capabilities,
            restart_generation,
            timeout,
        )
    }

    fn attest_open_wallet_database(&mut self, expected: &fs::Metadata) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service controller is poisoned",
            ));
        }
        let result = match self.process.as_mut() {
            Some(process) => process.attests_open_wallet_database(expected),
            None => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service process identity is unavailable",
            )),
        };
        if result.is_err() {
            self.poison();
        }
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service database identity attestation failed",
            )
        })
    }
}

#[cfg(target_os = "linux")]
impl<R: Read + AsRawFd, W: Write + AsRawFd> WalletServiceController<R, W> {
    fn negotiate(
        reader: R,
        writer: W,
        process: Option<WalletServiceProcess>,
        admitted_capabilities: BTreeSet<NegotiatedWalletServiceCapability>,
        restart_generation: u64,
        timeout: Duration,
    ) -> io::Result<Self> {
        if restart_generation == 0 || timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wallet service restart generation and I/O timeout must be nonzero",
            ));
        }
        set_nonblocking_fd(reader.as_raw_fd())?;
        set_nonblocking_fd(writer.as_raw_fd())?;
        let host_session_id = random_wallet_wire_id::<WALLET_SERVICE_SESSION_BYTES>()?;
        let mut controller = Self {
            reader,
            writer,
            process,
            timeout,
            host_session_id,
            service_session_id: String::new(),
            restart_generation,
            next_host_sequence: 1,
            next_service_sequence: 1,
            capabilities: BTreeSet::new(),
            selected_active_wallet: None,
            selected_hns_account: None,
            poisoned: false,
        };
        let frame = WalletHostHelloFrame::Hello {
            hello: WalletHostHello {
                protocol_version: WALLET_SERVICE_PROTOCOL_VERSION,
                platform: "chromiumNativeHost",
                host_session_id: &controller.host_session_id,
                restart_generation,
            },
        };
        let payload = serde_json::to_vec(&frame).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "wallet hello encoding failed")
        })?;
        let response = controller.exchange(&payload)?;
        let response = serde_json::from_slice::<WalletServiceHelloFrame>(&response)
            .map_err(|_| controller.protocol_error("wallet service hello is malformed"))?;
        let WalletServiceHelloFrame::Hello { hello } = response;
        if hello.protocol_version != WALLET_SERVICE_PROTOCOL_VERSION
            || hello.platform != "chromiumNativeHost"
            || hello.host_session_id != controller.host_session_id
            || hello.restart_generation != restart_generation
            || !valid_wallet_wire_id(&hello.service_session_id, WALLET_SERVICE_SESSION_BYTES)
            || !hello.limits.is_exact_v2()
            || hello.capabilities.is_empty()
            || hello.capabilities.len() > MAX_NEGOTIATED_SERVICE_CAPABILITIES
        {
            return Err(controller.protocol_error("wallet service hello contract mismatch"));
        }
        let capability_count = hello.capabilities.len();
        let capabilities = hello.capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty()
            || capabilities.len() > MAX_NEGOTIATED_SERVICE_CAPABILITIES
            || capabilities.len() != capability_count
            || !capabilities.is_subset(&admitted_capabilities)
            || !WALLET_READ_SESSION_REQUIRED_CAPABILITIES
                .iter()
                .all(|capability| capabilities.contains(capability))
            || (capabilities.contains(&NegotiatedWalletServiceCapability::ValueMovement)
                && !capabilities.contains(&NegotiatedWalletServiceCapability::ProviderDispatch))
        {
            return Err(controller.protocol_error("wallet service capabilities are invalid"));
        }
        controller.service_session_id = hello.service_session_id;
        controller.capabilities = capabilities;
        Ok(controller)
    }

    /// Reads wallet lock/module status without granting any page authority.
    #[allow(dead_code)]
    pub(crate) fn read_status(&mut self) -> io::Result<WalletReadOnlyStatus> {
        let response = self.wallet_request(
            WalletReadOnlyRequest::Status,
            WalletReadOnlyResponseKind::Status,
        )?;
        let WalletReadOnlyResponse::Status { status } = response else {
            return Err(self.protocol_error("wallet status response class changed after checking"));
        };
        if !status.validate() {
            return Err(self.protocol_error("wallet status response violates bounded HNS contract"));
        }
        if let Some(active_wallet) = status.active_wallet {
            if self
                .selected_active_wallet
                .is_some_and(|selected| selected != active_wallet)
            {
                return Err(self.protocol_error("wallet service changed its active wallet"));
            }
            self.selected_active_wallet = Some(active_wallet);
        }
        if status.locked
            || !status
                .enabled_modules
                .contains(&WalletReadOnlyModule::Handshake)
        {
            self.selected_active_wallet = None;
            self.selected_hns_account = None;
        }
        Ok(status)
    }

    /// Resolves the service's one exact HNS account. Subsequent read methods
    /// use this retained identifier rather than accepting caller-selected
    /// account or module input.
    #[allow(dead_code)]
    pub(crate) fn list_accounts(&mut self) -> io::Result<WalletReadOnlyAccountSummary> {
        let response = self.wallet_request(
            WalletReadOnlyRequest::ListAccounts,
            WalletReadOnlyResponseKind::Accounts,
        )?;
        let WalletReadOnlyResponse::Accounts { mut accounts } = response else {
            return Err(
                self.protocol_error("wallet accounts response class changed after checking")
            );
        };
        if accounts.len() != 1 || !accounts[0].validate() {
            return Err(self.protocol_error("wallet account response violates exact HNS contract"));
        }
        let Some(account) = accounts.pop() else {
            return Err(
                self.protocol_error("wallet account response changed after bounded validation")
            );
        };
        if self
            .selected_hns_account
            .is_some_and(|selected| selected != account.account_id)
        {
            return Err(self.protocol_error("wallet service changed its selected HNS account"));
        }
        self.selected_hns_account = Some(account.account_id);
        Ok(account)
    }

    /// Each value read is a separate service operation and therefore carries
    /// only its own synchronization authority; these methods do not compose a
    /// cross-operation snapshot.
    #[allow(dead_code)]
    pub(crate) fn read_balance(&mut self) -> io::Result<WalletReadOnlyAmount> {
        let account = self.require_selected_hns_account()?;
        let response = self.wallet_request(
            WalletReadOnlyRequest::Balance {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyResponseKind::Balance,
        )?;
        let WalletReadOnlyResponse::Balance { amount } = response else {
            return Err(self.protocol_error("wallet balance response class changed after checking"));
        };
        if !amount.validate() {
            return Err(self.protocol_error("wallet balance response violates HNS contract"));
        }
        Ok(amount)
    }

    #[allow(dead_code)]
    pub(crate) fn read_receive_target(&mut self) -> io::Result<WalletReadOnlyReceiveTarget> {
        let account = self.require_selected_hns_account()?;
        let response = self.wallet_request(
            WalletReadOnlyRequest::ReceiveTarget {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyResponseKind::ReceiveTarget,
        )?;
        let WalletReadOnlyResponse::ReceiveTarget { target } = response else {
            return Err(
                self.protocol_error("wallet receive-target response class changed after checking")
            );
        };
        if !target.validate(account) {
            return Err(
                self.protocol_error("wallet receive target response violates exact HNS contract")
            );
        }
        Ok(target)
    }

    #[allow(dead_code)]
    pub(crate) fn read_transaction_history(
        &mut self,
    ) -> io::Result<Vec<WalletReadOnlyTransactionSummary>> {
        let account = self.require_selected_hns_account()?;
        let response = self.wallet_request(
            WalletReadOnlyRequest::TransactionHistory {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyResponseKind::TransactionHistory,
        )?;
        let WalletReadOnlyResponse::TransactionHistory { transactions } = response else {
            return Err(self.protocol_error("wallet history response class changed after checking"));
        };
        if !validate_wallet_transaction_history(&transactions) {
            return Err(
                self.protocol_error("wallet history response violates bounded HNS contract")
            );
        }
        Ok(transactions)
    }

    #[allow(dead_code)]
    pub(crate) fn read_module_status(&mut self) -> io::Result<WalletReadOnlySyncStatus> {
        self.require_selected_hns_account()?;
        let response = self.wallet_request(
            WalletReadOnlyRequest::ModuleStatus {
                module: WalletReadOnlyModule::Handshake,
            },
            WalletReadOnlyResponseKind::ModuleStatus,
        )?;
        let WalletReadOnlyResponse::ModuleStatus { status } = response else {
            return Err(
                self.protocol_error("wallet module-status response class changed after checking")
            );
        };
        if !status.validate() {
            return Err(self.protocol_error("wallet module status violates bounded HNS contract"));
        }
        Ok(status)
    }

    /// Execute every operation promised by the exact HNS read marker and
    /// retain only its minimized native projection. A locked or not-yet-ready
    /// runtime is an availability result, not a protocol violation; malformed
    /// or substituted responses still poison the controller in the individual
    /// operation validators.
    #[allow(dead_code)]
    pub(crate) fn read_all(&mut self) -> io::Result<WalletReadOnlyView> {
        let status = self.read_status()?;
        if status.locked
            || status.active_wallet.is_none()
            || status.enabled_modules() != [WalletReadOnlyModule::Handshake]
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet HNS read runtime is not unlocked and ready",
            ));
        }
        let account = self.list_accounts()?;
        let balance = self.read_balance()?;
        let receive_target = self.read_receive_target()?;
        let transactions = self.read_transaction_history()?;
        let module_status = self.read_module_status()?;
        Ok(WalletReadOnlyView {
            status,
            account,
            balance,
            receive_target,
            transactions,
            module_status,
        })
    }

    fn require_selected_hns_account(&self) -> io::Result<[u8; 16]> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service controller is poisoned",
            ));
        }
        self.selected_hns_account.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet HNS account must be selected through listAccounts first",
            )
        })
    }

    fn wallet_request(
        &mut self,
        request: WalletReadOnlyRequest,
        expected_response: WalletReadOnlyResponseKind,
    ) -> io::Result<WalletReadOnlyResponse> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service controller is poisoned",
            ));
        }
        if !self
            .capabilities
            .contains(&NegotiatedWalletServiceCapability::WalletOperations)
            || !self
                .capabilities
                .contains(&NegotiatedWalletServiceCapability::HnsReadOperationsV1)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service did not negotiate the exact HNS read-operation contract",
            ));
        }
        let response = self.service_request(
            WalletReadOnlyServiceRequest::Wallet { request },
            WalletServiceResponseKind::Wallet(expected_response),
        )?;
        let WalletReadOnlyServiceResponse::Wallet { response } = response else {
            return Err(self.protocol_error("wallet response class changed after checking"));
        };
        Ok(response)
    }

    fn read_hns_authority_context(
        &mut self,
        claim: WalletNamespaceLeaseClaim,
    ) -> io::Result<WalletServiceHnsAuthorityContext> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service controller is poisoned",
            ));
        }
        if !self
            .capabilities
            .contains(&NegotiatedWalletServiceCapability::HnsWalletAuthorityContextV1)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service did not negotiate the exact HNS authority-context contract",
            ));
        }
        let active_wallet = self.selected_active_wallet.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet status must bind an active wallet before authority use",
            )
        })?;
        let account = self.require_selected_hns_account()?;
        if !WalletHandshakeNetwork::from_kind(claim.network)
            .matches_kind_and_magic(claim.network, claim.network_magic)
            || claim.namespace_id.iter().all(|byte| *byte == 0)
            || claim.generation == 0
        {
            return Err(self.protocol_error("wallet namespace lease claim is malformed"));
        }
        let response = self.service_request(
            WalletReadOnlyServiceRequest::WalletAuthority {
                request: WalletAuthorityContextRequest::CurrentHnsContext {
                    network: WalletHandshakeNetwork::from_kind(claim.network),
                    network_magic: claim.network_magic,
                    namespace_id: claim.namespace_id,
                    namespace_lease_generation: claim.generation,
                    module: WalletReadOnlyModule::Handshake,
                },
            },
            WalletServiceResponseKind::WalletAuthority,
        )?;
        let WalletReadOnlyServiceResponse::WalletAuthority { context } = response else {
            return Err(
                self.protocol_error("wallet authority response class changed after checking")
            );
        };
        if !context.validates_against(claim, active_wallet, account) {
            return Err(
                self.protocol_error("wallet HNS authority response violates exact context binding")
            );
        }
        Ok(context)
    }

    fn service_request(
        &mut self,
        body: WalletReadOnlyServiceRequest,
        expected_response: WalletServiceResponseKind,
    ) -> io::Result<WalletReadOnlyServiceResponse> {
        let request_id = random_wallet_wire_id::<WALLET_SERVICE_REQUEST_ID_BYTES>()?;
        let host_sequence = self.next_host_sequence;
        let frame = WalletHostRequestFrame::Request {
            envelope: WalletHostRequestEnvelope {
                protocol_version: WALLET_SERVICE_PROTOCOL_VERSION,
                host_session_id: &self.host_session_id,
                service_session_id: &self.service_session_id,
                restart_generation: self.restart_generation,
                channel_sequence: host_sequence,
                request_id: &request_id,
                body,
            },
        };
        let payload = serde_json::to_vec(&frame).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "wallet request encoding failed")
        })?;
        let response = self.exchange(&payload)?;
        let response = serde_json::from_slice::<WalletServiceResponseFrame>(&response)
            .map_err(|_| self.protocol_error("wallet read response is malformed"))?;
        let WalletServiceResponseFrame::Response { envelope } = response;
        if envelope.protocol_version != WALLET_SERVICE_PROTOCOL_VERSION
            || envelope.host_session_id != self.host_session_id
            || envelope.service_session_id != self.service_session_id
            || envelope.restart_generation != self.restart_generation
            || envelope.channel_sequence != self.next_service_sequence
            || envelope.request_id != request_id
        {
            return Err(self.protocol_error("wallet read response session or sequence mismatch"));
        }
        match envelope.body {
            WalletReadOnlyServiceResponse::Failure { failure } => {
                if !failure.validate() {
                    return Err(self.protocol_error("wallet service failure is malformed"));
                }
                if failure.code.is_protocol_failure() {
                    return Err(self.protocol_error("wallet service reported a protocol failure"));
                }
                self.advance_sequences()?;
                Err(io::Error::other(failure.code.operation_error_message()))
            }
            response => {
                if response.kind() != Some(expected_response) {
                    return Err(self.protocol_error("wallet response class does not match request"));
                }
                self.advance_sequences()?;
                Ok(response)
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn provider_available(&self) -> bool {
        false
    }

    #[allow(dead_code)]
    pub(crate) const fn value_available(&self) -> bool {
        false
    }

    fn exchange(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wallet service controller is poisoned",
            ));
        }
        let Some(deadline) = Instant::now().checked_add(self.timeout) else {
            self.poison();
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wallet service frame deadline is outside the clock range",
            ));
        };
        if let Err(error) = write_wallet_payload(&mut self.writer, payload, deadline) {
            self.poison();
            return Err(error);
        }
        match read_wallet_payload(&mut self.reader, deadline) {
            Ok(payload) => Ok(payload),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    fn protocol_error(&mut self, message: &'static str) -> io::Error {
        self.poison();
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn advance_sequences(&mut self) -> io::Result<()> {
        let Some(next_host_sequence) = self.next_host_sequence.checked_add(1) else {
            return Err(self.protocol_error("wallet host sequence exhausted"));
        };
        let Some(next_service_sequence) = self.next_service_sequence.checked_add(1) else {
            return Err(self.protocol_error("wallet service sequence exhausted"));
        };
        self.next_host_sequence = next_host_sequence;
        self.next_service_sequence = next_service_sequence;
        Ok(())
    }

    fn poison(&mut self) {
        self.poisoned = true;
        if let Some(process) = &mut self.process {
            process.terminate();
        }
    }
}

#[cfg(target_os = "linux")]
impl<R: Read + AsRawFd, W: Write + AsRawFd> Drop for WalletServiceController<R, W> {
    fn drop(&mut self) {
        self.poison();
    }
}

/// One admitted native-only read session. Database identity is rebound and the
/// child's live descriptor table is attested before every operation and after
/// every nonpoisoning result. A poisoned operation has already killed and
/// reaped the child; any identity failure does the same before reuse.
#[cfg(target_os = "linux")]
struct AdmittedWalletReadSession {
    controller: SpawnedWalletServiceController,
    database: TrustedWalletDatabaseConfiguration,
    namespace_lease: WalletNamespaceLease,
    restart_generation: u64,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl AdmittedWalletReadSession {
    fn new(
        mut controller: SpawnedWalletServiceController,
        database: TrustedWalletDatabaseConfiguration,
        namespace_lease: WalletNamespaceLease,
        restart_generation: u64,
    ) -> io::Result<Self> {
        let allowed_capabilities = WALLET_READ_SESSION_ALLOWED_CAPABILITIES
            .into_iter()
            .collect::<BTreeSet<_>>();
        if controller.restart_generation != restart_generation
            || !WALLET_READ_SESSION_REQUIRED_CAPABILITIES
                .iter()
                .all(|capability| controller.capabilities.contains(capability))
            || !controller.capabilities.is_subset(&allowed_capabilities)
        {
            controller.poison();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet service did not negotiate the native read-session contract",
            ));
        }
        if let Err(error) = database.revalidate() {
            controller.poison();
            return Err(error);
        }
        controller.attest_open_wallet_database(&database.database_metadata)?;
        Ok(Self {
            controller,
            database,
            namespace_lease,
            restart_generation,
        })
    }

    fn execute<T>(
        &mut self,
        operation: impl FnOnce(&mut SpawnedWalletServiceController) -> io::Result<T>,
    ) -> io::Result<T> {
        let (namespace_lease, database, controller) = (
            &mut self.namespace_lease,
            &self.database,
            &mut self.controller,
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            namespace_lease.use_if_current(|_claim| {
                Self::revalidate_database_boundary_parts(database, controller)?;
                let result = operation(controller);
                if !controller.poisoned {
                    Self::revalidate_database_boundary_parts(database, controller)?;
                }
                result
            })
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                controller.poison();
                std::panic::resume_unwind(payload);
            }
        };
        match result {
            Ok(value) => Ok(value),
            Err(WalletNamespaceLeaseUseError::Operation(error)) => Err(error),
            Err(WalletNamespaceLeaseUseError::GuardDenied) => {
                controller.poison();
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wallet namespace lease is not current",
                ))
            }
        }
    }

    fn revalidate_database_boundary(&mut self) -> io::Result<()> {
        Self::revalidate_database_boundary_parts(&self.database, &mut self.controller)
    }

    fn revalidate_database_boundary_parts(
        database: &TrustedWalletDatabaseConfiguration,
        controller: &mut SpawnedWalletServiceController,
    ) -> io::Result<()> {
        if let Err(error) = database.revalidate() {
            controller.poison();
            return Err(error);
        }
        controller.attest_open_wallet_database(&database.database_metadata)
    }

    fn use_current_hns_authority<T>(
        &mut self,
        operation: impl for<'authority> FnOnce(&'authority WalletHnsAuthorityContext) -> io::Result<T>,
    ) -> io::Result<T> {
        if !self
            .controller
            .capabilities
            .contains(&NegotiatedWalletServiceCapability::HnsWalletAuthorityContextV1)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet authority context capability is unavailable",
            ));
        }
        let (namespace_lease, database, controller) = (
            &mut self.namespace_lease,
            &self.database,
            &mut self.controller,
        );
        let restart_generation = self.restart_generation;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            namespace_lease.use_if_current(|claim| {
                use std::os::unix::fs::MetadataExt;

                Self::revalidate_database_boundary_parts(database, controller)?;
                let status = controller.read_status()?;
                if status.locked
                    || status.active_wallet.is_none()
                    || status.enabled_modules() != [WalletReadOnlyModule::Handshake]
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "wallet HNS authority runtime is not unlocked and ready",
                    ));
                }
                let active_wallet = status.active_wallet.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "wallet HNS authority runtime lost its active wallet",
                    )
                })?;
                let account = controller.list_accounts()?;
                let service_context = controller.read_hns_authority_context(claim)?;
                Self::revalidate_database_boundary_parts(database, controller)?;
                let authority = WalletHnsAuthorityContext {
                    network: claim.network,
                    network_magic: claim.network_magic,
                    namespace_id: claim.namespace_id,
                    namespace_lease_generation: claim.generation,
                    database_device: database.database_metadata.dev(),
                    database_inode: database.database_metadata.ino(),
                    restart_generation,
                    host_session_id: controller.host_session_id.clone(),
                    service_session_id: controller.service_session_id.clone(),
                    active_wallet,
                    account: account.account_id,
                    wallet_authority_revision: service_context.wallet_authority_revision,
                    account_authority_revision: service_context.account_authority_revision,
                };
                let consumer_result = operation(&authority);
                if controller.poisoned {
                    return consumer_result;
                }
                let final_status = controller.read_status()?;
                if final_status != status {
                    return Err(
                        controller.protocol_error("wallet status changed during HNS authority use")
                    );
                }
                let final_account = controller.list_accounts()?;
                if final_account != account {
                    return Err(controller
                        .protocol_error("wallet account changed during HNS authority use"));
                }
                let final_service_context = controller.read_hns_authority_context(claim)?;
                if final_service_context != service_context {
                    return Err(controller.protocol_error(
                        "wallet authority revision or lifecycle changed during use",
                    ));
                }
                Self::revalidate_database_boundary_parts(database, controller)?;
                consumer_result
            })
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                controller.poison();
                std::panic::resume_unwind(payload);
            }
        };
        match result {
            Ok(value) => Ok(value),
            Err(WalletNamespaceLeaseUseError::GuardDenied) => {
                controller.poison();
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wallet namespace lease was lost during authority use",
                ))
            }
            Err(WalletNamespaceLeaseUseError::Operation(error)) => {
                controller.poison();
                Err(error)
            }
        }
    }

    fn is_poisoned(&self) -> bool {
        self.controller.poisoned
    }

    fn read_status(&mut self) -> io::Result<WalletReadOnlyStatus> {
        self.execute(WalletServiceController::read_status)
    }

    fn list_accounts(&mut self) -> io::Result<WalletReadOnlyAccountSummary> {
        self.execute(WalletServiceController::list_accounts)
    }

    fn read_balance(&mut self) -> io::Result<WalletReadOnlyAmount> {
        self.execute(WalletServiceController::read_balance)
    }

    fn read_receive_target(&mut self) -> io::Result<WalletReadOnlyReceiveTarget> {
        self.execute(WalletServiceController::read_receive_target)
    }

    fn read_transaction_history(&mut self) -> io::Result<Vec<WalletReadOnlyTransactionSummary>> {
        self.execute(WalletServiceController::read_transaction_history)
    }

    fn read_module_status(&mut self) -> io::Result<WalletReadOnlySyncStatus> {
        self.execute(WalletServiceController::read_module_status)
    }

    fn read_all(&mut self) -> io::Result<WalletReadOnlyView> {
        self.execute(WalletServiceController::read_all)
    }
}

/// Generation-owning slot for the private read session. A new start always
/// drops the prior child first, failed generations are never reused, and a
/// stale invalidation cannot tear down a newer session.
#[cfg(target_os = "linux")]
pub(crate) struct WalletReadSessionLifecycle {
    next_restart_generation: u64,
    active: Option<AdmittedWalletReadSession>,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl WalletReadSessionLifecycle {
    pub(crate) const fn new() -> Self {
        Self {
            next_restart_generation: 1,
            active: None,
        }
    }

    pub(crate) fn start(
        &mut self,
        discovery: &mut WalletAbiDiscovery,
        bootstrap_source: &mut dyn WalletBootstrapSource,
        expected_network: NetworkKind,
        timeout: Duration,
    ) -> io::Result<u64> {
        let restart_generation = self.next_restart_generation;
        self.next_restart_generation = restart_generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("wallet service restart generation exhausted"))?;
        // Drop is the synchronous kill-and-wait boundary for the previous
        // process. The allocated generation remains consumed if startup fails.
        self.active = None;
        let lease = bootstrap_source
            .take_lease(restart_generation, expected_network)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "trusted wallet bootstrap lease is unavailable",
                )
            })?;
        let session = discovery.compose_admitted_read_session(
            lease,
            restart_generation,
            expected_network,
            timeout,
        )?;
        self.active = Some(session);
        Ok(restart_generation)
    }

    pub(crate) fn invalidate(&mut self, restart_generation: u64) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|session| session.restart_generation == restart_generation)
        {
            self.active = None;
            true
        } else {
            false
        }
    }

    fn active_session(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<&mut AdmittedWalletReadSession> {
        match self.active.as_mut() {
            Some(session) if session.restart_generation == restart_generation => Ok(session),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet read session generation is stale",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "wallet read session is not active",
            )),
        }
    }

    fn execute_active<T>(
        &mut self,
        restart_generation: u64,
        operation: impl FnOnce(&mut AdmittedWalletReadSession) -> io::Result<T>,
    ) -> io::Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operation(self.active_session(restart_generation)?)
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                if let Some(session) = &mut self.active {
                    session.controller.poison();
                }
                self.active = None;
                std::panic::resume_unwind(payload);
            }
        };
        if self
            .active
            .as_ref()
            .is_some_and(AdmittedWalletReadSession::is_poisoned)
        {
            self.active = None;
        }
        result
    }

    pub(crate) fn read_status(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<WalletReadOnlyStatus> {
        self.execute_active(restart_generation, AdmittedWalletReadSession::read_status)
    }

    pub(crate) fn list_accounts(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<WalletReadOnlyAccountSummary> {
        self.execute_active(restart_generation, AdmittedWalletReadSession::list_accounts)
    }

    pub(crate) fn read_balance(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<WalletReadOnlyAmount> {
        self.execute_active(restart_generation, AdmittedWalletReadSession::read_balance)
    }

    pub(crate) fn read_receive_target(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<WalletReadOnlyReceiveTarget> {
        self.execute_active(
            restart_generation,
            AdmittedWalletReadSession::read_receive_target,
        )
    }

    pub(crate) fn read_transaction_history(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<Vec<WalletReadOnlyTransactionSummary>> {
        self.execute_active(
            restart_generation,
            AdmittedWalletReadSession::read_transaction_history,
        )
    }

    pub(crate) fn read_module_status(
        &mut self,
        restart_generation: u64,
    ) -> io::Result<WalletReadOnlySyncStatus> {
        self.execute_active(
            restart_generation,
            AdmittedWalletReadSession::read_module_status,
        )
    }

    pub(crate) fn read_all(&mut self, restart_generation: u64) -> io::Result<WalletReadOnlyView> {
        self.execute_active(restart_generation, AdmittedWalletReadSession::read_all)
    }

    pub(crate) fn use_current_hns_authority<T>(
        &mut self,
        restart_generation: u64,
        operation: impl for<'authority> FnOnce(&'authority WalletHnsAuthorityContext) -> io::Result<T>,
    ) -> io::Result<T> {
        self.execute_active(restart_generation, |session| {
            session.use_current_hns_authority(operation)
        })
    }

    fn authority_context_available_with_release_qualification(
        &self,
        release_qualified: bool,
    ) -> bool {
        release_qualified
            && self.active.as_ref().is_some_and(|session| {
                !session.is_poisoned()
                    && session
                        .controller
                        .capabilities
                        .contains(&NegotiatedWalletServiceCapability::HnsWalletAuthorityContextV1)
            })
    }

    pub(crate) fn authority_context_available(&self) -> bool {
        self.authority_context_available_with_release_qualification(
            HRM_HNSA_WALLET_CONSUMER_RELEASE_QUALIFIED,
        )
    }

    pub(crate) const fn provider_available(&self) -> bool {
        false
    }

    pub(crate) const fn value_available(&self) -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
impl Default for WalletReadSessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn random_wallet_wire_id<const BYTES: usize>() -> io::Result<String> {
    let mut bytes = [0_u8; BYTES];
    fill_random(&mut bytes)
        .map_err(|_| io::Error::other("unable to generate wallet service session material"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other(
            "wallet service session generator returned the reserved zero value",
        ));
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(target_os = "linux")]
fn valid_wallet_wire_id(value: &str, decoded_bytes: usize) -> bool {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .is_ok_and(|decoded| {
            decoded.len() == decoded_bytes
                && decoded.iter().any(|byte| *byte != 0)
                && URL_SAFE_NO_PAD.encode(decoded) == value
        })
}

#[cfg(target_os = "linux")]
fn set_nonblocking_fd(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: descriptor is borrowed from a live pipe/socket and fcntl neither
    // retains it nor crosses the owning Rust object's lifetime.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_wallet_fd(descriptor: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "wallet service frame deadline elapsed",
            ));
        };
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "wallet service frame deadline elapsed",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
fn write_wallet_payload<W: Write + AsRawFd>(
    writer: &mut W,
    payload: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > WALLET_ABI_MAX_FRAME_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wallet service frame is empty or oversized",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "wallet frame is oversized"))?;
    write_wallet_bytes(writer, &length.to_be_bytes(), deadline)?;
    write_wallet_bytes(writer, payload, deadline)
}

#[cfg(target_os = "linux")]
fn write_wallet_bytes<W: Write + AsRawFd>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "wallet service pipe stopped accepting a frame",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_wallet_fd(writer.as_raw_fd(), libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_wallet_payload<R: Read + AsRawFd>(
    reader: &mut R,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    read_wallet_bytes(reader, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > WALLET_ABI_MAX_FRAME_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet service declared an empty or oversized frame",
        ));
    }
    let mut payload = vec![0_u8; length];
    read_wallet_bytes(reader, &mut payload, deadline)?;
    Ok(payload)
}

#[cfg(target_os = "linux")]
fn read_wallet_bytes<R: Read + AsRawFd>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match reader.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "wallet service ended inside a frame",
                ));
            }
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_wallet_fd(reader.as_raw_fd(), libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct WalletAbiDiscovery {
    data_dir: PathBuf,
    #[cfg(unix)]
    configuration: WalletAbiVerifierConfiguration,
    state: WalletArtifactState,
}

impl WalletAbiDiscovery {
    pub(crate) fn discover(data_dir: &Path) -> Self {
        #[cfg(unix)]
        {
            let configuration = WalletAbiVerifierConfiguration::production();
            let state = inspect_manifest(data_dir, &configuration);
            Self {
                data_dir: data_dir.to_owned(),
                configuration,
                state,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                data_dir: data_dir.to_owned(),
                state: inspect_manifest(data_dir),
            }
        }
    }

    #[cfg(all(test, unix))]
    fn discover_with_configuration(
        data_dir: &Path,
        configuration: WalletAbiVerifierConfiguration,
    ) -> Self {
        let state = inspect_manifest(data_dir, &configuration);
        Self {
            data_dir: data_dir.to_owned(),
            configuration,
            state,
        }
    }

    pub(crate) fn refresh(&mut self) {
        #[cfg(unix)]
        {
            self.state = inspect_manifest(&self.data_dir, &self.configuration);
        }
        #[cfg(not(unix))]
        {
            self.state = inspect_manifest(&self.data_dir);
        }
    }

    pub(crate) fn status_json(&self) -> Value {
        let mut artifact_authenticity_verified = false;
        let mut artifact_release_qualified = false;
        let mut artifact_anti_rollback_committed = false;
        let mut artifact_launch_admitted = false;
        let (artifact_state, reason, summary): (&str, &str, Option<&WalletArtifactSummary>) =
            match &self.state {
                #[cfg(unix)]
                WalletArtifactState::Missing => ("missing", "walletArtifactMissing", None),
                WalletArtifactState::Rejected(reason) => ("rejected", reason.code(), None),
                #[cfg(unix)]
                WalletArtifactState::IntegrityChecked(artifact) => (
                    "integrityChecked",
                    "walletArtifactAuthenticityUnavailable",
                    Some(artifact),
                ),
                #[cfg(unix)]
                WalletArtifactState::AuthenticityVerified(artifact) => {
                    artifact_authenticity_verified = true;
                    (
                        "authenticityVerified",
                        "walletArtifactQualificationUnavailable",
                        Some(artifact),
                    )
                }
                #[cfg(unix)]
                WalletArtifactState::LaunchAdmitted(artifact) => {
                    artifact_authenticity_verified = true;
                    artifact_release_qualified = true;
                    artifact_anti_rollback_committed = true;
                    artifact_launch_admitted = true;
                    (
                        "launchAdmitted",
                        "walletServiceTransportUnavailable",
                        Some(&artifact.summary),
                    )
                }
            };
        json!({
            "manifestSchemaVersion": WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            "requiredWalletAbiVersion": WALLET_ABI_VERSION,
            "requiredServiceProtocolVersion": WALLET_SERVICE_PROTOCOL_VERSION,
            "requiredProviderSchemaVersion": WALLET_PROVIDER_SCHEMA_VERSION,
            "requiredApprovalSchemaVersion": WALLET_APPROVAL_SCHEMA_VERSION,
            "maximumFrameBytes": WALLET_ABI_MAX_FRAME_BYTES,
            "artifactState": artifact_state,
            "artifactReleaseId": summary.map(|value| value.release_id.as_str()),
            "artifactReleaseLine": summary.map(|value| value.release_line.as_str()),
            "artifactReleaseSequence": summary.map(|value| value.sequence),
            "artifactSha256": summary.map(|value| value.artifact_sha256.as_str()),
            "artifactManifestSha256": summary.map(|value| value.manifest_sha256.as_str()),
            "artifactSignerKeyId": summary.map(|value| value.signer_key_id.as_str()),
            "artifactAuthenticityVerified": artifact_authenticity_verified,
            "artifactReleaseQualified": artifact_release_qualified,
            "artifactAntiRollbackCommitted": artifact_anti_rollback_committed,
            "artifactLaunchAdmitted": artifact_launch_admitted,
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
            #[cfg(unix)]
            WalletArtifactState::AuthenticityVerified(_) => {
                "walletArtifactQualificationUnavailable"
            }
            #[cfg(unix)]
            WalletArtifactState::LaunchAdmitted(_) => "walletServiceTransportUnavailable",
        }
    }

    pub(crate) fn unavailable_message(&self) -> &'static str {
        match &self.state {
            #[cfg(unix)]
            WalletArtifactState::Missing => {
                "the independently released wallet service artifact is not installed"
            }
            WalletArtifactState::Rejected(_) => {
                "the installed wallet service artifact failed closed during admission"
            }
            #[cfg(unix)]
            WalletArtifactState::IntegrityChecked(_) => {
                "the wallet artifact passed local integrity checks but has no verifier-owned trusted signer"
            }
            #[cfg(unix)]
            WalletArtifactState::AuthenticityVerified(_) => {
                "the wallet artifact signature is trusted but this exact release is not product-qualified"
            }
            #[cfg(unix)]
            WalletArtifactState::LaunchAdmitted(_) => {
                "the wallet artifact is launch-admitted, but no released private transport or browser-engine opaque provider authority is joined"
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn compose_admitted_read_session(
        &mut self,
        lease: WalletBootstrapLease,
        restart_generation: u64,
        expected_network: NetworkKind,
        timeout: Duration,
    ) -> io::Result<AdmittedWalletReadSession> {
        let (database, namespace_lease, bootstrap_read) =
            lease.into_launch_parts(restart_generation, expected_network)?;
        match &mut self.state {
            WalletArtifactState::LaunchAdmitted(artifact) => {
                database.revalidate()?;
                let admitted_capabilities = artifact.admitted_service_capabilities()?;
                let capability_ceiling =
                    wallet_read_session_capability_ceiling(&admitted_capabilities)?;
                let child = artifact.launch_for_database(&database, bootstrap_read)?;
                let controller = SpawnedWalletServiceController::negotiate_spawned(
                    child,
                    capability_ceiling,
                    restart_generation,
                    timeout,
                )?;
                AdmittedWalletReadSession::new(
                    controller,
                    database,
                    namespace_lease,
                    restart_generation,
                )
            }
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wallet artifact has not passed signed release admission",
            )),
        }
    }
}

#[derive(Debug)]
enum WalletArtifactState {
    #[cfg(unix)]
    Missing,
    Rejected(WalletArtifactRejection),
    #[cfg(unix)]
    IntegrityChecked(WalletArtifactSummary),
    #[cfg(unix)]
    AuthenticityVerified(WalletArtifactSummary),
    #[cfg(unix)]
    LaunchAdmitted(Box<LaunchAdmittedWalletArtifact>),
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
    ManifestCanonicalization,
    #[cfg(unix)]
    ManifestContract,
    #[cfg(unix)]
    ArtifactMissing,
    #[cfg(unix)]
    UnsafeArtifact,
    #[cfg(unix)]
    MutableArtifact,
    #[cfg(unix)]
    ArtifactSize,
    #[cfg(unix)]
    ArtifactDigest,
    #[cfg(unix)]
    ArtifactRead,
    #[cfg(unix)]
    ArtifactPlatform,
    #[cfg(unix)]
    SignaturePayload,
    #[cfg(unix)]
    SignatureInvalid,
    #[cfg(unix)]
    VerifierConfiguration,
    #[cfg(unix)]
    ReleaseFloor,
    #[cfg(unix)]
    ReleaseTimeWindow,
    #[cfg(unix)]
    AntiRollback,
    #[cfg(unix)]
    PathBinding,
    #[cfg(target_os = "linux")]
    LaunchFailed,
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
            Self::ManifestCanonicalization => "walletArtifactManifestNotCanonical",
            #[cfg(unix)]
            Self::ManifestContract => "walletArtifactContractMismatch",
            #[cfg(unix)]
            Self::ArtifactMissing => "walletArtifactMissing",
            #[cfg(unix)]
            Self::UnsafeArtifact => "walletArtifactUnsafe",
            #[cfg(unix)]
            Self::MutableArtifact => "walletArtifactMutable",
            #[cfg(unix)]
            Self::ArtifactSize => "walletArtifactSize",
            #[cfg(unix)]
            Self::ArtifactDigest => "walletArtifactDigestMismatch",
            #[cfg(unix)]
            Self::ArtifactRead => "walletArtifactUnreadable",
            #[cfg(unix)]
            Self::ArtifactPlatform => "walletArtifactPlatformMismatch",
            #[cfg(unix)]
            Self::SignaturePayload => "walletArtifactSignaturePayloadMismatch",
            #[cfg(unix)]
            Self::SignatureInvalid => "walletArtifactSignatureInvalid",
            #[cfg(unix)]
            Self::VerifierConfiguration => "walletArtifactVerifierConfigurationInvalid",
            #[cfg(unix)]
            Self::ReleaseFloor => "walletArtifactReleaseBelowFloor",
            #[cfg(unix)]
            Self::ReleaseTimeWindow => "walletArtifactReleaseTimeInvalid",
            #[cfg(unix)]
            Self::AntiRollback => "walletArtifactRollbackRejected",
            #[cfg(unix)]
            Self::PathBinding => "walletArtifactPathBindingChanged",
            #[cfg(target_os = "linux")]
            Self::LaunchFailed => "walletArtifactLaunchFailed",
        }
    }
}

#[derive(Debug)]
struct WalletArtifactSummary {
    release_id: String,
    release_line: String,
    sequence: u64,
    signer_key_id: String,
    manifest_sha256: String,
    artifact_sha256: String,
}

#[cfg(unix)]
#[derive(Debug)]
struct LaunchAdmittedWalletArtifact {
    summary: WalletArtifactSummary,
    data_directory_path: PathBuf,
    data_directory: File,
    data_directory_metadata: fs::Metadata,
    artifact_directory: File,
    artifact_directory_metadata: fs::Metadata,
    manifest_file: File,
    artifact_file: File,
    manifest_metadata: fs::Metadata,
    artifact_metadata: fs::Metadata,
    manifest_bytes: Vec<u8>,
    artifact_name: String,
    anti_rollback_entry: WalletAntiRollbackEntry,
}

#[cfg(unix)]
impl LaunchAdmittedWalletArtifact {
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn admitted_service_capabilities(
        &self,
    ) -> io::Result<BTreeSet<NegotiatedWalletServiceCapability>> {
        let manifest = serde_json::from_slice::<WalletArtifactManifest>(&self.manifest_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wallet manifest changed"))?;
        manifest
            .target
            .capabilities
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wallet manifest capability is unsupported",
                    )
                })
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn launch_for_database(
        &mut self,
        database: &TrustedWalletDatabaseConfiguration,
        bootstrap_read: File,
    ) -> io::Result<Child> {
        require_wallet_bootstrap_read_descriptor(&bootstrap_read)?;
        database.revalidate()?;
        let anti_rollback_lock = acquire_anti_rollback_lock(&self.data_directory)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason.code()))?;
        self.revalidate_for_launch_while_locked(&anti_rollback_lock)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason.code()))?;
        let sealed = sealed_executable_copy(
            &mut self.artifact_file,
            &self.artifact_metadata,
            &self.summary.artifact_sha256,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                WalletArtifactRejection::LaunchFailed.code(),
            )
        })?;
        self.revalidate_for_launch_while_locked(&anti_rollback_lock)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason.code()))?;
        database.revalidate()?;
        let mut child =
            spawn_sealed_linux_executable(sealed, database.database_path(), bootstrap_read)?;
        if let Err(error) = database.revalidate() {
            terminate_wallet_child(&mut child);
            return Err(error);
        }
        Ok(child)
    }

    fn revalidate_for_launch_while_locked(
        &mut self,
        anti_rollback_lock: &WalletAntiRollbackLock,
    ) -> Result<(), WalletArtifactRejection> {
        let initial_unix_ms =
            current_unix_ms().ok_or(WalletArtifactRejection::ReleaseTimeWindow)?;
        self.revalidate_for_launch_while_locked_at(initial_unix_ms, anti_rollback_lock)?;
        let final_unix_ms = current_unix_ms().ok_or(WalletArtifactRejection::ReleaseTimeWindow)?;
        self.require_signed_time_window_at(final_unix_ms)
    }

    fn revalidate_for_launch_while_locked_at(
        &mut self,
        now_unix_ms: u64,
        anti_rollback_lock: &WalletAntiRollbackLock,
    ) -> Result<(), WalletArtifactRejection> {
        let current_data_directory = open_directory_nofollow(&self.data_directory_path)
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let current_data_directory_metadata = current_data_directory
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let retained_data_directory_metadata = self
            .data_directory
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        if !same_open_directory(
            &self.data_directory_metadata,
            &current_data_directory_metadata,
        ) || !same_open_directory(
            &self.data_directory_metadata,
            &retained_data_directory_metadata,
        ) || !private_directory(&current_data_directory)
            || !private_directory(&self.data_directory)
        {
            return Err(WalletArtifactRejection::PathBinding);
        }
        let current_artifact_directory =
            open_directory_at_nofollow(&current_data_directory, WALLET_ARTIFACT_DIRECTORY)
                .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let current_artifact_directory_metadata = current_artifact_directory
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let retained_artifact_directory_metadata = self
            .artifact_directory
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        if !same_open_directory(
            &self.artifact_directory_metadata,
            &current_artifact_directory_metadata,
        ) || !same_open_directory(
            &self.artifact_directory_metadata,
            &retained_artifact_directory_metadata,
        ) || !private_directory(&current_artifact_directory)
            || !private_directory(&self.artifact_directory)
        {
            return Err(WalletArtifactRejection::PathBinding);
        }
        let current_manifest =
            open_file_at_nofollow(&current_artifact_directory, WALLET_ARTIFACT_MANIFEST)
                .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let current_manifest_metadata = current_manifest
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        if !same_open_file(&self.manifest_metadata, &current_manifest_metadata)
            || !private_immutable_regular_file(&current_manifest_metadata)
        {
            return Err(WalletArtifactRejection::PathBinding);
        }

        self.manifest_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let manifest_bytes = read_manifest(&mut self.manifest_file)
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let final_manifest_metadata = self
            .manifest_file
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        if manifest_bytes != self.manifest_bytes
            || !same_open_file(&self.manifest_metadata, &final_manifest_metadata)
        {
            return Err(WalletArtifactRejection::PathBinding);
        }

        let current_artifact =
            open_file_at_nofollow(&current_artifact_directory, &self.artifact_name)
                .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let current_artifact_metadata = current_artifact
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        let retained_artifact_metadata = self
            .artifact_file
            .metadata()
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        if !same_open_file(&self.artifact_metadata, &current_artifact_metadata)
            || !same_open_file(&self.artifact_metadata, &retained_artifact_metadata)
            || !private_immutable_executable(&retained_artifact_metadata)
        {
            return Err(WalletArtifactRejection::PathBinding);
        }
        require_anti_rollback_entry_locked(
            &self.data_directory,
            &self.anti_rollback_entry,
            anti_rollback_lock,
        )?;
        self.require_signed_time_window_at(now_unix_ms)
    }

    fn require_signed_time_window_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<(), WalletArtifactRejection> {
        let manifest = serde_json::from_slice::<WalletArtifactManifest>(&self.manifest_bytes)
            .map_err(|_| WalletArtifactRejection::PathBinding)?;
        valid_manifest_time_window(&manifest, now_unix_ms)
            .then_some(())
            .ok_or(WalletArtifactRejection::ReleaseTimeWindow)
    }
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactManifest {
    manifest_schema_version: u16,
    target: WalletArtifactTarget,
    source: WalletArtifactSource,
    release: WalletArtifactRelease,
    anti_rollback: WalletArtifactAntiRollback,
    signature: WalletArtifactSignature,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactTarget {
    artifact_kind: String,
    target_triple: String,
    executable_format: String,
    wallet_abi_version: u16,
    service_protocol_version: u16,
    provider_schema_version: u16,
    approval_schema_version: u16,
    maximum_frame_bytes: u32,
    capabilities: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactSource {
    repository: String,
    commit_id: String,
    tree_id: String,
    source_archive_sha256: String,
    dirty: bool,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactRelease {
    release_id: String,
    version: String,
    artifact: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    published_at_unix_ms: u64,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactAntiRollback {
    release_line: String,
    sequence: u64,
    previous_manifest_sha256: Option<String>,
    not_before_unix_ms: u64,
    expires_at_unix_ms: Option<u64>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletArtifactSignature {
    algorithm: String,
    key_id: String,
    payload_canonicalization: String,
    signed_payload_sha256: String,
    value: String,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletAntiRollbackState {
    state_schema_version: u16,
    entries: Vec<WalletAntiRollbackEntry>,
    checksum_sha256: String,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletAntiRollbackEntry {
    release_line: String,
    highest_sequence: u64,
    release_id: String,
    signer_key_id: String,
    manifest_sha256: String,
    artifact_sha256: String,
}

#[cfg(unix)]
fn inspect_manifest(
    data_dir: &Path,
    configuration: &WalletAbiVerifierConfiguration,
) -> WalletArtifactState {
    if !valid_verifier_configuration(configuration) {
        return rejected(WalletArtifactRejection::VerifierConfiguration);
    }
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
    let data_directory_metadata = match data_directory.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::UnsafeDirectory),
    };

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
    let artifact_directory_metadata = match artifact_directory.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return rejected(WalletArtifactRejection::UnsafeDirectory),
    };

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
    let canonical_manifest = match jcs_bytes(&manifest) {
        Some(bytes) => bytes,
        None => return rejected(WalletArtifactRejection::ManifestEncoding),
    };
    if canonical_manifest != manifest_bytes {
        return rejected(WalletArtifactRejection::ManifestCanonicalization);
    }
    let now_unix_ms = match current_unix_ms() {
        Some(value) => value,
        None => return rejected(WalletArtifactRejection::ManifestContract),
    };
    if !valid_manifest_contract(&manifest, now_unix_ms) {
        return rejected(WalletArtifactRejection::ManifestContract);
    }

    let signed_payload = match signed_manifest_payload(&manifest) {
        Some(bytes) => bytes,
        None => return rejected(WalletArtifactRejection::SignaturePayload),
    };
    if sha256_bytes(&signed_payload) != manifest.signature.signed_payload_sha256 {
        return rejected(WalletArtifactRejection::SignaturePayload);
    }
    let manifest_sha256 = sha256_bytes(&manifest_bytes);

    let mut artifact_file =
        match open_file_at_nofollow(&artifact_directory, &manifest.release.artifact) {
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
    if artifact_metadata.len() == 0
        || artifact_metadata.len() > MAX_ARTIFACT_BYTES
        || artifact_metadata.len() != manifest.release.artifact_size_bytes
    {
        return rejected(WalletArtifactRejection::ArtifactSize);
    }
    let (artifact_sha256, bytes_read) = match sha256_reader(&mut artifact_file, MAX_ARTIFACT_BYTES)
    {
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
    if artifact_sha256 != manifest.release.artifact_sha256 {
        return rejected(WalletArtifactRejection::ArtifactDigest);
    }

    let summary = WalletArtifactSummary {
        release_id: manifest.release.release_id.clone(),
        release_line: manifest.anti_rollback.release_line.clone(),
        sequence: manifest.anti_rollback.sequence,
        signer_key_id: manifest.signature.key_id.clone(),
        manifest_sha256: manifest_sha256.clone(),
        artifact_sha256: artifact_sha256.clone(),
    };
    let Some(trust_root) = configuration.trust_root(
        &manifest.signature.key_id,
        &manifest.anti_rollback.release_line,
        manifest.anti_rollback.sequence,
    ) else {
        return WalletArtifactState::IntegrityChecked(summary);
    };
    let signature_bytes = match URL_SAFE_NO_PAD.decode(manifest.signature.value.as_bytes()) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => return rejected(WalletArtifactRejection::SignatureInvalid),
    };
    if UnparsedPublicKey::new(&signature::ED25519, &trust_root.public_key)
        .verify(&signed_payload, &signature_bytes)
        .is_err()
    {
        return rejected(WalletArtifactRejection::SignatureInvalid);
    }
    if configuration
        .minimum_sequence(&manifest.anti_rollback.release_line)
        .is_none_or(|minimum| manifest.anti_rollback.sequence < minimum)
    {
        return rejected(WalletArtifactRejection::ReleaseFloor);
    }
    let Some(qualified_release) = configuration.qualified_release(&manifest, &manifest_sha256)
    else {
        return WalletArtifactState::AuthenticityVerified(summary);
    };
    if !private_immutable_regular_file(&manifest_metadata)
        || !private_immutable_executable(&artifact_metadata)
    {
        return rejected(WalletArtifactRejection::MutableArtifact);
    }
    if !cfg!(target_os = "linux") || !current_platform_executable(&mut artifact_file) {
        return rejected(WalletArtifactRejection::ArtifactPlatform);
    }

    let anti_rollback_entry = match commit_anti_rollback(
        &data_directory,
        &manifest,
        &manifest_sha256,
        qualified_release.trusted_genesis,
    ) {
        Ok(entry) => entry,
        Err(reason) => return rejected(reason),
    };
    WalletArtifactState::LaunchAdmitted(Box::new(LaunchAdmittedWalletArtifact {
        summary,
        data_directory_path: data_dir.to_owned(),
        data_directory,
        data_directory_metadata,
        artifact_directory,
        artifact_directory_metadata,
        manifest_file,
        artifact_file,
        manifest_metadata,
        artifact_metadata,
        manifest_bytes,
        artifact_name: manifest.release.artifact,
        anti_rollback_entry,
    }))
}

#[cfg(not(unix))]
fn inspect_manifest(_data_dir: &Path) -> WalletArtifactState {
    rejected(WalletArtifactRejection::UnsupportedPlatform)
}

const fn rejected(reason: WalletArtifactRejection) -> WalletArtifactState {
    WalletArtifactState::Rejected(reason)
}

#[cfg(unix)]
fn valid_verifier_configuration(configuration: &WalletAbiVerifierConfiguration) -> bool {
    let roots_valid = configuration.trust_roots.iter().all(|root| {
        valid_token(&root.key_id, 128)
            && valid_token(&root.release_line, 128)
            && root.public_key.len() == 32
            && root.first_sequence > 0
            && root.first_sequence <= root.last_sequence
            && root.last_sequence <= MAX_SAFE_INTEGER
            && configuration.minimum_sequence(&root.release_line).is_some()
    });
    let floors_valid = configuration.release_floors.iter().all(|floor| {
        valid_token(&floor.release_line, 128)
            && floor.minimum_sequence > 0
            && floor.minimum_sequence <= MAX_SAFE_INTEGER
    });
    let releases_valid = configuration.qualified_releases.iter().all(|release| {
        valid_token(&release.key_id, 128)
            && valid_token(&release.release_line, 128)
            && release.sequence > 0
            && release.sequence <= MAX_SAFE_INTEGER
            && valid_token(&release.release_id, 128)
            && valid_token(&release.target_triple, 128)
            && is_lower_hex(&release.manifest_sha256, 64)
            && is_lower_hex(&release.artifact_sha256, 64)
            && configuration
                .minimum_sequence(&release.release_line)
                .is_some_and(|minimum| release.sequence >= minimum)
    });
    roots_valid
        && floors_valid
        && releases_valid
        && unique_configuration(configuration)
        && configuration.qualified_releases.iter().all(|release| {
            configuration
                .trust_root(&release.key_id, &release.release_line, release.sequence)
                .is_some()
        })
}

#[cfg(unix)]
fn unique_configuration(configuration: &WalletAbiVerifierConfiguration) -> bool {
    let mut floor_lines = BTreeSet::new();
    let mut release_ids = BTreeSet::new();
    let roots_unambiguous = configuration
        .trust_roots
        .iter()
        .enumerate()
        .all(|(index, root)| {
            configuration.trust_roots[index + 1..].iter().all(|other| {
                root.key_id != other.key_id
                    || root.release_line != other.release_line
                    || root.last_sequence < other.first_sequence
                    || other.last_sequence < root.first_sequence
            })
        });
    roots_unambiguous
        && configuration
            .release_floors
            .iter()
            .all(|floor| floor_lines.insert(floor.release_line.as_str()))
        && configuration.qualified_releases.iter().all(|release| {
            release_ids.insert((
                release.release_line.as_str(),
                release.sequence,
                release.target_triple.as_str(),
            ))
        })
}

#[cfg(unix)]
fn valid_manifest_contract(manifest: &WalletArtifactManifest, now_unix_ms: u64) -> bool {
    let Some((target_triple, executable_format)) = current_target_contract() else {
        return false;
    };
    manifest.manifest_schema_version == WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION
        && manifest.target.artifact_kind == "walletService"
        && manifest.target.target_triple == target_triple
        && manifest.target.executable_format == executable_format
        && manifest.target.wallet_abi_version == WALLET_ABI_VERSION
        && manifest.target.service_protocol_version == WALLET_SERVICE_PROTOCOL_VERSION
        && manifest.target.provider_schema_version == WALLET_PROVIDER_SCHEMA_VERSION
        && manifest.target.approval_schema_version == WALLET_APPROVAL_SCHEMA_VERSION
        && manifest.target.maximum_frame_bytes == WALLET_ABI_MAX_FRAME_BYTES
        && exact_capabilities(&manifest.target.capabilities)
        && manifest.source.repository == WALLET_SOURCE_REPOSITORY
        && valid_git_id(&manifest.source.commit_id)
        && valid_git_id(&manifest.source.tree_id)
        && is_lower_hex(&manifest.source.source_archive_sha256, 64)
        && !manifest.source.dirty
        && valid_token(&manifest.release.release_id, 128)
        && valid_semver(&manifest.release.version)
        && valid_artifact_name(&manifest.release.artifact)
        && is_lower_hex(&manifest.release.artifact_sha256, 64)
        && manifest.release.artifact_size_bytes > 0
        && manifest.release.artifact_size_bytes <= MAX_ARTIFACT_BYTES
        && positive_safe_integer(manifest.release.published_at_unix_ms)
        && valid_token(&manifest.anti_rollback.release_line, 128)
        && positive_safe_integer(manifest.anti_rollback.sequence)
        && manifest
            .anti_rollback
            .previous_manifest_sha256
            .as_deref()
            .is_none_or(|digest| is_lower_hex(digest, 64))
        && positive_safe_integer(manifest.anti_rollback.not_before_unix_ms)
        && manifest
            .anti_rollback
            .expires_at_unix_ms
            .is_none_or(positive_safe_integer)
        && valid_manifest_time_window(manifest, now_unix_ms)
        && manifest.signature.algorithm == SIGNATURE_ALGORITHM
        && valid_token(&manifest.signature.key_id, 128)
        && manifest.signature.payload_canonicalization == SIGNATURE_CANONICALIZATION
        && is_lower_hex(&manifest.signature.signed_payload_sha256, 64)
        && valid_base64url_signature(&manifest.signature.value)
}

#[cfg(unix)]
fn valid_manifest_time_window(manifest: &WalletArtifactManifest, now_unix_ms: u64) -> bool {
    manifest.release.published_at_unix_ms <= now_unix_ms
        && manifest.anti_rollback.not_before_unix_ms <= now_unix_ms
        && manifest
            .anti_rollback
            .expires_at_unix_ms
            .is_none_or(|expiry| expiry > now_unix_ms)
        && manifest
            .anti_rollback
            .expires_at_unix_ms
            .is_none_or(|expiry| expiry > manifest.anti_rollback.not_before_unix_ms)
}

#[cfg(unix)]
fn exact_capabilities(capabilities: &[String]) -> bool {
    if capabilities.len() > SERVICE_CAPABILITIES.len() {
        return false;
    }
    let mut unique = BTreeSet::new();
    capabilities.iter().all(|capability| {
        SERVICE_CAPABILITIES.contains(&capability.as_str()) && unique.insert(capability.as_str())
    }) && REQUIRED_BASE_CAPABILITIES
        .iter()
        .all(|required| unique.contains(required))
}

#[cfg(unix)]
fn valid_artifact_name(value: &str) -> bool {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        let path = Path::new(value);
        return !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            && path.components().count() == 1;
    }
    false
}

#[cfg(target_os = "linux")]
fn valid_wallet_database_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WALLET_DATABASE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && Path::new(value).components().count() == 1
}

#[cfg(unix)]
fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
        })
}

#[cfg(unix)]
fn valid_git_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && is_lower_hex(value, value.len())
}

#[cfg(unix)]
fn valid_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(left, right)| (left, Some(right)));
    if build.is_some_and(|suffix| suffix.is_empty() || !semver_suffix(suffix))
        || without_build.contains('+')
    {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(left, right)| (left, Some(right)));
    if prerelease.is_some_and(|suffix| suffix.is_empty() || !semver_suffix(suffix)) {
        return false;
    }
    let mut parts = core.split('.');
    parts.next().is_some_and(decimal_component)
        && parts.next().is_some_and(decimal_component)
        && parts.next().is_some_and(decimal_component)
        && parts.next().is_none()
}

#[cfg(unix)]
fn decimal_component(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(unix)]
fn semver_suffix(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

#[cfg(unix)]
fn positive_safe_integer(value: u64) -> bool {
    value > 0 && value <= MAX_SAFE_INTEGER
}

#[cfg(unix)]
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(unix)]
fn valid_base64url_signature(value: &str) -> bool {
    value.len() == 86
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b'A' | b'Q' | b'g' | b'w'))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .is_ok_and(|decoded| decoded.len() == 64)
}

#[cfg(unix)]
fn current_target_contract() -> Option<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some(("x86_64-unknown-linux-gnu", "elf")),
        ("linux", "aarch64") => Some(("aarch64-unknown-linux-gnu", "elf")),
        ("macos", "x86_64") => Some(("x86_64-apple-darwin", "machO")),
        ("macos", "aarch64") => Some(("aarch64-apple-darwin", "machO")),
        _ => None,
    }
}

#[cfg(unix)]
fn current_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|value| *value <= MAX_SAFE_INTEGER)
}

#[cfg(unix)]
fn signed_manifest_payload(manifest: &WalletArtifactManifest) -> Option<Vec<u8>> {
    let mut value = serde_json::to_value(manifest).ok()?;
    value.as_object_mut()?.remove("signature")?;
    jcs_value_bytes(&value)
}

#[cfg(unix)]
fn jcs_bytes<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    jcs_value_bytes(&serde_json::to_value(value).ok()?)
}

#[cfg(unix)]
fn jcs_value_bytes(value: &Value) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    write_jcs_value(value, &mut bytes).then_some(bytes)
}

#[cfg(unix)]
fn write_jcs_value(value: &Value, output: &mut Vec<u8>) -> bool {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Number(number) => {
            let Some(number) = number.as_u64() else {
                return false;
            };
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => {
            if serde_json::to_writer(output, string).is_err() {
                return false;
            }
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                if !write_jcs_value(value, output) {
                    return false;
                }
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            output.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                if serde_json::to_writer(&mut *output, key).is_err() {
                    return false;
                }
                output.push(b':');
                if !write_jcs_value(&values[key], output) {
                    return false;
                }
            }
            output.push(b'}');
        }
    }
    true
}

#[cfg(unix)]
fn read_manifest(file: &mut File) -> Result<Vec<u8>, WalletArtifactRejection> {
    read_bounded(file, MAX_MANIFEST_BYTES).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            WalletArtifactRejection::ManifestSize
        } else {
            WalletArtifactRejection::UnsafeManifest
        }
    })
}

#[cfg(unix)]
fn read_bounded(file: &mut File, maximum: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds bounded size",
        ));
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
    Ok((lower_hex(&hasher.finalize()), total))
}

#[cfg(unix)]
fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

#[cfg(unix)]
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
struct WalletAntiRollbackLock {
    _file: File,
}

#[cfg(unix)]
fn acquire_anti_rollback_lock(
    data_directory: &File,
) -> Result<WalletAntiRollbackLock, WalletArtifactRejection> {
    use std::os::unix::fs::PermissionsExt;

    let file = open_lock_file_at_nofollow(data_directory, WALLET_ANTI_ROLLBACK_LOCK)
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let metadata = file
        .metadata()
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    if !private_regular_file(&metadata)
        || metadata.len() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    lock_file_exclusive(&file).map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let current = open_file_at_nofollow(data_directory, WALLET_ANTI_ROLLBACK_LOCK)
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let current_metadata = current
        .metadata()
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    if !same_open_file(&metadata, &current_metadata)
        || !private_regular_file(&current_metadata)
        || current_metadata.len() != 0
        || current_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    Ok(WalletAntiRollbackLock { _file: file })
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    loop {
        // SAFETY: the descriptor remains owned by file throughout the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn commit_anti_rollback(
    data_directory: &File,
    manifest: &WalletArtifactManifest,
    manifest_sha256: &str,
    trusted_genesis: bool,
) -> Result<WalletAntiRollbackEntry, WalletArtifactRejection> {
    let anti_rollback_lock = acquire_anti_rollback_lock(data_directory)?;
    let mut state = read_anti_rollback_state_locked(data_directory, &anti_rollback_lock)?
        .unwrap_or(WalletAntiRollbackState {
            state_schema_version: WALLET_ANTI_ROLLBACK_STATE_SCHEMA_VERSION,
            entries: Vec::new(),
            checksum_sha256: String::new(),
        });
    let current = WalletAntiRollbackEntry {
        release_line: manifest.anti_rollback.release_line.clone(),
        highest_sequence: manifest.anti_rollback.sequence,
        release_id: manifest.release.release_id.clone(),
        signer_key_id: manifest.signature.key_id.clone(),
        manifest_sha256: manifest_sha256.to_owned(),
        artifact_sha256: manifest.release.artifact_sha256.clone(),
    };
    match state
        .entries
        .binary_search_by(|entry| entry.release_line.cmp(&current.release_line))
    {
        Ok(index) => {
            let previous = &state.entries[index];
            if current.highest_sequence < previous.highest_sequence {
                return Err(WalletArtifactRejection::AntiRollback);
            }
            if current.highest_sequence == previous.highest_sequence {
                if current != *previous {
                    return Err(WalletArtifactRejection::AntiRollback);
                }
                return Ok(current);
            }
            if manifest.anti_rollback.previous_manifest_sha256.as_deref()
                != Some(previous.manifest_sha256.as_str())
            {
                return Err(WalletArtifactRejection::AntiRollback);
            }
            state.entries[index] = current.clone();
        }
        Err(index) => {
            if !trusted_genesis || manifest.anti_rollback.previous_manifest_sha256.is_some() {
                return Err(WalletArtifactRejection::AntiRollback);
            }
            state.entries.insert(index, current.clone());
        }
    }
    if state.entries.len() > MAX_ANTI_ROLLBACK_RELEASE_LINES {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    state.checksum_sha256 =
        anti_rollback_checksum(&state).ok_or(WalletArtifactRejection::AntiRollback)?;
    write_anti_rollback_state_locked(data_directory, &state, &anti_rollback_lock)?;
    require_anti_rollback_entry_locked(data_directory, &current, &anti_rollback_lock)?;
    Ok(current)
}

#[cfg(unix)]
fn require_anti_rollback_entry_locked(
    data_directory: &File,
    expected: &WalletAntiRollbackEntry,
    anti_rollback_lock: &WalletAntiRollbackLock,
) -> Result<(), WalletArtifactRejection> {
    let state = read_anti_rollback_state_locked(data_directory, anti_rollback_lock)?
        .ok_or(WalletArtifactRejection::AntiRollback)?;
    state
        .entries
        .binary_search_by(|entry| entry.release_line.cmp(&expected.release_line))
        .ok()
        .and_then(|index| state.entries.get(index))
        .filter(|entry| *entry == expected)
        .map(|_| ())
        .ok_or(WalletArtifactRejection::AntiRollback)
}

#[cfg(unix)]
fn read_anti_rollback_state_locked(
    data_directory: &File,
    _anti_rollback_lock: &WalletAntiRollbackLock,
) -> Result<Option<WalletAntiRollbackState>, WalletArtifactRejection> {
    let mut file = match open_file_at_nofollow(data_directory, WALLET_ANTI_ROLLBACK_STATE) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WalletArtifactRejection::AntiRollback),
    };
    let metadata = file
        .metadata()
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    if !private_immutable_regular_file(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_ANTI_ROLLBACK_STATE_BYTES
    {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    let bytes = read_bounded(&mut file, MAX_ANTI_ROLLBACK_STATE_BYTES)
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let final_metadata = file
        .metadata()
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    if bytes.len() as u64 != metadata.len() || !same_open_file(&metadata, &final_metadata) {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    let state = serde_json::from_slice::<WalletAntiRollbackState>(&bytes)
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    if jcs_bytes(&state).as_deref() != Some(bytes.as_slice())
        || !valid_anti_rollback_state(&state)
        || anti_rollback_checksum(&state).as_deref() != Some(state.checksum_sha256.as_str())
    {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    Ok(Some(state))
}

#[cfg(unix)]
fn valid_anti_rollback_state(state: &WalletAntiRollbackState) -> bool {
    if state.state_schema_version != WALLET_ANTI_ROLLBACK_STATE_SCHEMA_VERSION
        || state.entries.len() > MAX_ANTI_ROLLBACK_RELEASE_LINES
        || !is_lower_hex(&state.checksum_sha256, 64)
    {
        return false;
    }
    let mut prior_line: Option<&str> = None;
    state.entries.iter().all(|entry| {
        let ordered = prior_line.is_none_or(|prior| prior < entry.release_line.as_str());
        prior_line = Some(entry.release_line.as_str());
        ordered
            && valid_token(&entry.release_line, 128)
            && positive_safe_integer(entry.highest_sequence)
            && valid_token(&entry.release_id, 128)
            && valid_token(&entry.signer_key_id, 128)
            && is_lower_hex(&entry.manifest_sha256, 64)
            && is_lower_hex(&entry.artifact_sha256, 64)
    })
}

#[cfg(unix)]
fn anti_rollback_checksum(state: &WalletAntiRollbackState) -> Option<String> {
    let mut value = serde_json::to_value(state).ok()?;
    value.as_object_mut()?.remove("checksumSha256")?;
    let payload = jcs_value_bytes(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(ANTI_ROLLBACK_CHECKSUM_CONTEXT);
    hasher.update(payload);
    Some(lower_hex(&hasher.finalize()))
}

#[cfg(unix)]
fn write_anti_rollback_state_locked(
    data_directory: &File,
    state: &WalletAntiRollbackState,
    _anti_rollback_lock: &WalletAntiRollbackLock,
) -> Result<(), WalletArtifactRejection> {
    let bytes = jcs_bytes(state).ok_or(WalletArtifactRejection::AntiRollback)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ANTI_ROLLBACK_STATE_BYTES {
        return Err(WalletArtifactRejection::AntiRollback);
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let temporary_name = format!(
        ".admission-state-{}-{}.tmp",
        std::process::id(),
        lower_hex(&nonce)
    );
    let mut temporary = create_file_at_exclusive(data_directory, &temporary_name)
        .map_err(|_| WalletArtifactRejection::AntiRollback)?;
    let write_result = (|| -> io::Result<()> {
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;
        use std::os::unix::fs::PermissionsExt;
        temporary.set_permissions(fs::Permissions::from_mode(0o400))?;
        let metadata = temporary.metadata()?;
        if !private_immutable_regular_file(&metadata) || metadata.len() != bytes.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "anti-rollback temporary file is unsafe",
            ));
        }
        temporary.sync_all()?;
        rename_at(data_directory, &temporary_name, WALLET_ANTI_ROLLBACK_STATE)?;
        data_directory.sync_all()
    })();
    if write_result.is_err() {
        let _ = unlink_at(data_directory, &temporary_name);
        return Err(WalletArtifactRejection::AntiRollback);
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: path is NUL-terminated and remains alive for the call. A
    // successful descriptor is immediately owned by File.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

#[cfg(target_os = "linux")]
fn open_absolute_directory_path_nofollow(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path must be absolute",
        ));
    }
    let mut directory = open_directory_nofollow(Path::new("/"))?;
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(name) if saw_root => {
                let name = name.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wallet database path is not UTF-8",
                    )
                })?;
                directory = open_directory_at_nofollow(&directory, name)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "wallet database path is not canonical",
                ));
            }
        }
    }
    Ok(directory)
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
fn open_lock_file_at_nofollow(directory: &File, name: &str) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: name is NUL-terminated and the retained directory descriptor is
    // valid. The lock contains no data; O_CREAT establishes one stable inode.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn open_at_nofollow(directory: &File, name: &str, flags: i32) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: name is NUL-terminated and the borrowed directory descriptor is
    // valid for the call. A successful descriptor is transferred to File.
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
fn create_file_at_exclusive(directory: &File, name: &str) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: name and directory descriptor remain valid for the call. O_EXCL
    // plus O_NOFOLLOW prevents adoption of an existing path.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn rename_at(directory: &File, source: &str, destination: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let source = CString::new(source)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source contains NUL"))?;
    let destination = CString::new(destination)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "destination contains NUL"))?;
    // SAFETY: both names are NUL-terminated and the same retained directory
    // descriptor is valid for the atomic rename.
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlink_at(directory: &File, name: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: name is NUL-terminated and directory remains valid.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn file_from_descriptor(descriptor: i32) -> io::Result<File> {
    use std::os::fd::FromRawFd;

    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor came from a successful open call and ownership moves
    // exactly once into File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn private_directory(directory: &File) -> bool {
    directory.metadata().is_ok_and(|metadata| {
        metadata.is_dir() && source_is_owned_and_not_shared_writable(&metadata)
    })
}

#[cfg(target_os = "linux")]
fn private_wallet_database_directory(directory: &File) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    directory.metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == effective_uid
            && metadata.permissions().mode() & 0o7777 == 0o700
    })
}

#[cfg(target_os = "linux")]
fn private_wallet_database_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    metadata.is_file()
        && metadata.uid() == effective_uid
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == 0o600
}

#[cfg(unix)]
fn private_regular_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.is_file() && metadata.nlink() == 1 && source_is_owned_and_not_shared_writable(metadata)
}

#[cfg(unix)]
fn private_immutable_regular_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    private_regular_file(metadata) && metadata.permissions().mode() & 0o222 == 0
}

#[cfg(unix)]
fn private_immutable_executable(metadata: &fs::Metadata) -> bool {
    private_immutable_regular_file(metadata) && source_is_executable(metadata)
}

#[cfg(unix)]
fn source_is_owned_and_not_shared_writable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0
}

#[cfg(unix)]
fn source_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(unix)]
fn same_open_directory(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.is_dir()
        && after.is_dir()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
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

#[cfg(target_os = "linux")]
fn same_wallet_database_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.is_file()
        && after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
}

#[cfg(unix)]
fn current_platform_executable(file: &mut File) -> bool {
    let mut header = [0_u8; 24];
    if file.seek(SeekFrom::Start(0)).is_err() || file.read_exact(&mut header).is_err() {
        return false;
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return valid_elf_executable_header(&header)
            && u16::from_le_bytes([header[18], header[19]]) == 62;
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return valid_elf_executable_header(&header)
            && u16::from_le_bytes([header[18], header[19]]) == 183;
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return u32::from_le_bytes(header[..4].try_into().expect("fixed header")) == 0xfeedfacf
            && u32::from_le_bytes(header[4..8].try_into().expect("fixed header")) == 0x01000007;
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return u32::from_le_bytes(header[..4].try_into().expect("fixed header")) == 0xfeedfacf
            && u32::from_le_bytes(header[4..8].try_into().expect("fixed header")) == 0x0100000c;
    }
    #[allow(unreachable_code)]
    false
}

#[cfg(target_os = "linux")]
fn valid_elf_executable_header(header: &[u8; 24]) -> bool {
    let file_type = u16::from_le_bytes([header[16], header[17]]);
    header[..7] == [0x7f, b'E', b'L', b'F', 2, 1, 1]
        && matches!(file_type, 2 | 3)
        && u32::from_le_bytes([header[20], header[21], header[22], header[23]]) == 1
}

#[cfg(target_os = "linux")]
fn sealed_executable_copy(
    source: &mut File,
    expected_metadata: &fs::Metadata,
    expected_sha256: &str,
) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let name = c"hns-wallet-service";
    // SAFETY: name is a valid C string and a successful descriptor is
    // transferred immediately to File.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    let mut sealed = file_from_descriptor(descriptor)?;
    source.seek(SeekFrom::Start(0))?;
    let before = source.metadata()?;
    if !same_open_file(expected_metadata, &before) || !private_immutable_executable(&before) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wallet artifact changed before sealed copy",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file size overflow"))?;
        if total > MAX_ARTIFACT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "wallet artifact exceeds sealed-copy limit",
            ));
        }
        hasher.update(&buffer[..read]);
        sealed.write_all(&buffer[..read])?;
    }
    let after = source.metadata()?;
    if total != expected_metadata.len()
        || !same_open_file(expected_metadata, &after)
        || lower_hex(&hasher.finalize()) != expected_sha256
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wallet artifact changed during sealed copy",
        ));
    }
    // SAFETY: descriptor belongs to sealed and fchmod/fcntl do not outlive it.
    if unsafe { libc::fchmod(sealed.as_raw_fd(), 0o500) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    // SAFETY: F_ADD_SEALS is applied to the valid memfd owned by sealed.
    if unsafe { libc::fcntl(sealed.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    sealed.seek(SeekFrom::Start(0))?;
    if !current_platform_executable(&mut sealed) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed wallet artifact has the wrong native format",
        ));
    }
    sealed.seek(SeekFrom::Start(0))?;
    Ok(sealed)
}

#[cfg(target_os = "linux")]
fn spawn_sealed_linux_executable(
    sealed: File,
    database_path: &Path,
    bootstrap_read: File,
) -> io::Result<Child> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    require_wallet_bootstrap_read_descriptor(&bootstrap_read)?;
    // Command configures descriptors 0-2 for the private ABI and descriptor 3
    // for the bootstrap packet. Keep both inherited backing descriptors above
    // that complete reserved range before Command's child-side remapping.
    let sealed = duplicate_file_at_or_above(sealed, FIRST_WALLET_CHILD_AUXILIARY_DESCRIPTOR)?;
    let bootstrap_read =
        duplicate_file_at_or_above(bootstrap_read, FIRST_WALLET_CHILD_AUXILIARY_DESCRIPTOR)?;
    let descriptor = sealed.as_raw_fd();
    let bootstrap_descriptor = bootstrap_read.as_raw_fd();
    let executable = format!("/proc/self/fd/{descriptor}");
    let mut command = Command::new(executable);
    command
        .arg("--database")
        .arg(database_path)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // `--database` and the retained configuration's exact absolute path are
    // the complete child argument list. The opaque one-shot bootstrap enters
    // only through fixed descriptor 3; standard input starts with the ABI-v2
    // host hello, and no service mode or caller input can append an operation.
    // SAFETY: the child hook performs only async-signal-safe dup2/fcntl calls.
    // It clears close-on-exec on the sealed memfd and installs only the opaque
    // pipe read end at the fixed child descriptor. The original pipe end keeps
    // close-on-exec and disappears during exec when it differs from the target.
    // Rust 1.92's Unix Command path builds stdio before its exec-error channel,
    // performs the stdio dup2 calls before pre_exec, and cannot use posix_spawn
    // when this callback is present. Consequently a low-FD stdin pipe may
    // temporarily occupy descriptor 3, but its child end is already retained
    // at descriptor 0 before this callback atomically replaces descriptor 3.
    // The isolated low-FD regression below pins that ordering assumption.
    unsafe {
        command
            .pre_exec(move || install_wallet_child_descriptors(descriptor, bootstrap_descriptor));
    }
    command.spawn()
}

#[cfg(target_os = "linux")]
fn install_wallet_child_descriptors(
    sealed_descriptor: RawFd,
    bootstrap_descriptor: RawFd,
) -> io::Result<()> {
    // SAFETY: this helper is called after fork with live inherited
    // descriptors. fcntl and dup2 are async-signal-safe and retain no pointer.
    unsafe {
        let sealed_flags = libc::fcntl(sealed_descriptor, libc::F_GETFD);
        if sealed_flags < 0
            || libc::fcntl(
                sealed_descriptor,
                libc::F_SETFD,
                sealed_flags & !libc::FD_CLOEXEC,
            ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        if bootstrap_descriptor != WALLET_BOOTSTRAP_DESCRIPTOR
            && libc::dup2(bootstrap_descriptor, WALLET_BOOTSTRAP_DESCRIPTOR) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let bootstrap_flags = libc::fcntl(WALLET_BOOTSTRAP_DESCRIPTOR, libc::F_GETFD);
        if bootstrap_flags < 0
            || libc::fcntl(
                WALLET_BOOTSTRAP_DESCRIPTOR,
                libc::F_SETFD,
                bootstrap_flags & !libc::FD_CLOEXEC,
            ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn duplicate_file_at_or_above(file: File, minimum: RawFd) -> io::Result<File> {
    if file.as_raw_fd() >= minimum {
        return Ok(file);
    }
    // SAFETY: fcntl duplicates the live descriptor and transfers no ownership
    // until the successful raw descriptor is wrapped immediately below.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate is a new owned descriptor returned by fcntl.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Barrier};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_KEY_ID: &str = "wallet-release-test";
    const TEST_RELEASE_LINE: &str = "wallet-service-stable";
    const TEST_ARTIFACT_NAME: &str = "hns-wallet-service";
    #[cfg(target_os = "linux")]
    const LOW_FD_SPAWN_HELPER_ENV: &str = "HNS_WALLET_LOW_FD_SPAWN_HELPER";
    #[cfg(target_os = "linux")]
    const TEST_WALLET_NAMESPACE_ID: [u8; 16] = [6; 16];
    #[cfg(target_os = "linux")]
    const POSITIVE_WALLET_READ_CAPABILITIES: [&str; 8] = [
        "canonicalFraming",
        "restartIsolation",
        "opaqueAuthorityRegistry",
        "structuredApprovals",
        "typedEvents",
        "walletOperations",
        "hnsReadOperationsV1",
        "hnsWalletAuthorityContextV1",
    ];

    #[cfg(target_os = "linux")]
    fn wallet_read_bootstrap(namespace_id: [u8; 16], namespace_lease_generation: u64) -> Vec<u8> {
        let namespace_hex = namespace_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "chromium-wallet-read-bootstrap-v2\nregtest\n2922943951\n{namespace_hex}\n{namespace_lease_generation}\n"
        )
        .into_bytes()
    }

    #[cfg(target_os = "linux")]
    fn positive_wallet_read_bootstrap(namespace_lease_generation: u64) -> Vec<u8> {
        wallet_read_bootstrap(TEST_WALLET_NAMESPACE_ID, namespace_lease_generation)
    }

    struct InstalledRelease {
        manifest: WalletArtifactManifest,
        manifest_bytes: Vec<u8>,
        artifact_bytes: Vec<u8>,
    }

    #[cfg(target_os = "linux")]
    struct OneShotWalletBootstrapSource {
        lease: Option<WalletBootstrapLease>,
        claimed_generations: Vec<u64>,
        claimed_networks: Vec<NetworkKind>,
    }

    #[cfg(target_os = "linux")]
    struct AlwaysCurrentWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for AlwaysCurrentWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            operation: &mut dyn FnMut(),
        ) -> bool {
            operation();
            true
        }
    }

    #[cfg(target_os = "linux")]
    struct DenyAfterUseWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for DenyAfterUseWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            operation: &mut dyn FnMut(),
        ) -> bool {
            operation();
            false
        }
    }

    #[cfg(target_os = "linux")]
    struct SkipUseWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for SkipUseWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            _operation: &mut dyn FnMut(),
        ) -> bool {
            true
        }
    }

    #[cfg(target_os = "linux")]
    struct DoubleUseWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for DoubleUseWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            operation: &mut dyn FnMut(),
        ) -> bool {
            operation();
            operation();
            true
        }
    }

    #[cfg(target_os = "linux")]
    struct PanicBeforeUseWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for PanicBeforeUseWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            _operation: &mut dyn FnMut(),
        ) -> bool {
            panic!("fixture broker guard panic before use")
        }
    }

    #[cfg(target_os = "linux")]
    struct PanicAfterUseWalletNamespaceGuard;

    #[cfg(target_os = "linux")]
    impl WalletNamespaceLeaseGuard for PanicAfterUseWalletNamespaceGuard {
        fn use_if_current(
            &mut self,
            _claim: WalletNamespaceLeaseClaim,
            operation: &mut dyn FnMut(),
        ) -> bool {
            operation();
            panic!("fixture broker guard panic after use")
        }
    }

    #[cfg(target_os = "linux")]
    struct TemporarilyVacantDescriptor {
        target: RawFd,
        saved: Option<RawFd>,
    }

    #[cfg(target_os = "linux")]
    impl TemporarilyVacantDescriptor {
        fn new(target: RawFd) -> Self {
            // SAFETY: fcntl and close operate on descriptor values only. A
            // successful duplicate is owned by the returned guard.
            unsafe {
                let flags = libc::fcntl(target, libc::F_GETFD);
                let saved = if flags >= 0 {
                    let duplicate = libc::fcntl(target, libc::F_DUPFD_CLOEXEC, 64);
                    assert!(duplicate >= 0);
                    assert_eq!(libc::close(target), 0);
                    Some(duplicate)
                } else {
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                    None
                };
                assert_eq!(libc::fcntl(target, libc::F_GETFD), -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                Self { target, saved }
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TemporarilyVacantDescriptor {
        fn drop(&mut self) {
            if let Some(saved) = self.saved.take() {
                // SAFETY: saved is the live duplicate owned by this guard;
                // dup2 restores target and close then releases the duplicate.
                unsafe {
                    assert_eq!(libc::dup2(saved, self.target), self.target);
                    assert_eq!(libc::close(saved), 0);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl WalletBootstrapSource for OneShotWalletBootstrapSource {
        fn take_lease(
            &mut self,
            restart_generation: u64,
            expected_network: NetworkKind,
        ) -> io::Result<Option<WalletBootstrapLease>> {
            self.claimed_generations.push(restart_generation);
            self.claimed_networks.push(expected_network);
            Ok(self.lease.take())
        }
    }

    #[cfg(target_os = "linux")]
    fn test_wallet_namespace_lease(network: NetworkKind, generation: u64) -> WalletNamespaceLease {
        test_wallet_namespace_lease_with_guard(
            network,
            TEST_WALLET_NAMESPACE_ID,
            generation,
            Box::new(AlwaysCurrentWalletNamespaceGuard),
        )
    }

    #[cfg(target_os = "linux")]
    fn test_wallet_namespace_lease_with_guard(
        network: NetworkKind,
        namespace_id: [u8; 16],
        generation: u64,
        guard: Box<dyn WalletNamespaceLeaseGuard>,
    ) -> WalletNamespaceLease {
        WalletNamespaceLease::new(
            WalletNamespaceLeaseClaim::new(network, namespace_id, generation).unwrap(),
            guard,
        )
    }

    #[cfg(target_os = "linux")]
    fn test_wallet_bootstrap_pipe() -> (File, File) {
        let mut descriptors = [-1; 2];
        // SAFETY: pipe2 initializes both descriptors on success. Each is
        // wrapped exactly once immediately below.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: successful pipe2 returned two newly owned descriptors.
        unsafe {
            (
                File::from_raw_fd(descriptors[0]),
                File::from_raw_fd(descriptors[1]),
            )
        }
    }

    #[cfg(target_os = "linux")]
    fn test_wallet_bootstrap_source(
        restart_generation: u64,
        database: TrustedWalletDatabaseConfiguration,
    ) -> (OneShotWalletBootstrapSource, File) {
        test_wallet_bootstrap_source_with_authority(
            restart_generation,
            database,
            TEST_WALLET_NAMESPACE_ID,
            restart_generation,
            Box::new(AlwaysCurrentWalletNamespaceGuard),
        )
    }

    #[cfg(target_os = "linux")]
    fn test_wallet_bootstrap_source_with_authority(
        restart_generation: u64,
        database: TrustedWalletDatabaseConfiguration,
        namespace_id: [u8; 16],
        namespace_lease_generation: u64,
        guard: Box<dyn WalletNamespaceLeaseGuard>,
    ) -> (OneShotWalletBootstrapSource, File) {
        let (bootstrap_read, bootstrap_write) = test_wallet_bootstrap_pipe();
        let lease = WalletBootstrapLease::new(
            restart_generation,
            database,
            test_wallet_namespace_lease_with_guard(
                NetworkKind::Regtest,
                namespace_id,
                namespace_lease_generation,
                guard,
            ),
            bootstrap_read,
        )
        .unwrap();
        (
            OneShotWalletBootstrapSource {
                lease: Some(lease),
                claimed_generations: Vec::new(),
                claimed_networks: Vec::new(),
            },
            bootstrap_write,
        )
    }

    #[cfg(target_os = "linux")]
    fn assert_pipe_has_no_readers(writer: &File) {
        let mut descriptor = libc::pollfd {
            fd: writer.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized pollfd for the duration of the
        // call and retains no pointer.
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 1);
        assert_ne!(descriptor.revents & libc::POLLERR, 0);
    }

    #[cfg(target_os = "linux")]
    fn test_capability_ceiling() -> BTreeSet<NegotiatedWalletServiceCapability> {
        SERVICE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn negotiate_fixture_service(
        service: &mut UnixStream,
        deadline: Instant,
        service_session_byte: u8,
    ) -> (String, u64, String) {
        write_fixture_service_hello(
            service,
            deadline,
            service_session_byte,
            json!([
                "canonicalFraming",
                "restartIsolation",
                "opaqueAuthorityRegistry",
                "persistentPermissions",
                "structuredApprovals",
                "typedEvents",
                "walletOperations",
                "hnsReadOperationsV1",
                "providerDispatch"
            ]),
        )
    }

    #[cfg(target_os = "linux")]
    fn write_fixture_service_hello(
        service: &mut UnixStream,
        deadline: Instant,
        service_session_byte: u8,
        capabilities: Value,
    ) -> (String, u64, String) {
        let hello = read_wallet_payload(service, deadline).unwrap();
        let hello = serde_json::from_slice::<Value>(&hello).unwrap();
        assert_eq!(hello["frameType"], "hello");
        assert_eq!(hello["hello"]["protocolVersion"], 2);
        assert_eq!(hello["hello"]["platform"], "chromiumNativeHost");
        let host_session = hello["hello"]["hostSessionId"].as_str().unwrap().to_owned();
        let restart_generation = hello["hello"]["restartGeneration"].as_u64().unwrap();
        let service_session = URL_SAFE_NO_PAD.encode([service_session_byte; 32]);
        let response = json!({
            "frameType": "hello",
            "hello": {
                "protocolVersion": 2,
                "platform": "chromiumNativeHost",
                "hostSessionId": host_session,
                "serviceSessionId": service_session,
                "restartGeneration": restart_generation,
                "capabilities": capabilities,
                "limits": {
                    "outerFrameBytes": 1_048_576,
                    "providerRequestBytes": 65_536,
                    "providerResultBytes": 262_144,
                    "providerEventBytes": 65_536,
                    "approvalFrameBytes": 16_384,
                    "approvalLifetimeMs": 90_000
                }
            }
        });
        write_wallet_payload(service, &serde_json::to_vec(&response).unwrap(), deadline).unwrap();
        (host_session, restart_generation, service_session)
    }

    #[cfg(target_os = "linux")]
    fn status_service_fixture(request_count: u64) -> (UnixStream, std::thread::JoinHandle<()>) {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 2);

            for sequence in 1..=request_count {
                let deadline = Instant::now() + Duration::from_secs(2);
                let request = read_wallet_payload(&mut service, deadline).unwrap();
                let request = serde_json::from_slice::<Value>(&request).unwrap();
                let envelope = &request["envelope"];
                assert_eq!(request["frameType"], "request");
                assert_eq!(envelope["protocolVersion"], 2);
                assert_eq!(envelope["hostSessionId"], host_session);
                assert_eq!(envelope["serviceSessionId"], service_session);
                assert_eq!(envelope["restartGeneration"], restart_generation);
                assert_eq!(envelope["channelSequence"], sequence);
                assert_eq!(envelope["body"]["operation"], "wallet");
                assert_eq!(envelope["body"]["request"]["operation"], "status");
                let response = json!({
                    "frameType": "response",
                    "envelope": {
                        "protocolVersion": 2,
                        "hostSessionId": host_session,
                        "serviceSessionId": service_session,
                        "restartGeneration": restart_generation,
                        "channelSequence": sequence,
                        "requestId": envelope["requestId"],
                        "body": {
                            "result": "wallet",
                            "response": {
                                "result": "status",
                                "status": {
                                    "locked": sequence == 1,
                                    "activeWallet": if sequence == 1 {
                                        Value::Null
                                    } else {
                                        json!(vec![7_u8; 16])
                                    },
                                    "enabledModules": if sequence == 1 {
                                        json!([])
                                    } else {
                                        json!(["handshake"])
                                    },
                                    "mainnetSettlementEnabled": false
                                }
                            }
                        }
                    }
                });
                write_wallet_payload(
                    &mut service,
                    &serde_json::to_vec(&response).unwrap(),
                    deadline,
                )
                .unwrap();
            }
        });
        (host, task)
    }

    #[cfg(target_os = "linux")]
    fn assert_wallet_fixture_request(
        request: &Value,
        host_session: &str,
        service_session: &str,
        restart_generation: u64,
        sequence: u64,
        expected_body: Value,
    ) {
        let envelope = &request["envelope"];
        assert_eq!(request["frameType"], "request");
        assert_eq!(envelope["protocolVersion"], WALLET_SERVICE_PROTOCOL_VERSION);
        assert_eq!(envelope["hostSessionId"], host_session);
        assert_eq!(envelope["serviceSessionId"], service_session);
        assert_eq!(envelope["restartGeneration"], restart_generation);
        assert_eq!(envelope["channelSequence"], sequence);
        assert!(valid_wallet_wire_id(
            envelope["requestId"].as_str().unwrap(),
            WALLET_SERVICE_REQUEST_ID_BYTES
        ));
        assert_eq!(envelope["body"], expected_body);
    }

    #[cfg(target_os = "linux")]
    fn write_wallet_fixture_result(
        service: &mut UnixStream,
        deadline: Instant,
        session: (&str, &str, u64),
        sequence: u64,
        request: &Value,
        response: Value,
    ) {
        let (host_session, service_session, restart_generation) = session;
        let frame = json!({
            "frameType": "response",
            "envelope": {
                "protocolVersion": WALLET_SERVICE_PROTOCOL_VERSION,
                "hostSessionId": host_session,
                "serviceSessionId": service_session,
                "restartGeneration": restart_generation,
                "channelSequence": sequence,
                "requestId": request["envelope"]["requestId"],
                "body": {
                    "result": "wallet",
                    "response": response
                }
            }
        });
        write_wallet_payload(service, &serde_json::to_vec(&frame).unwrap(), deadline).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn hns_account_json(account_byte: u8) -> Value {
        json!({
            "accountId": vec![account_byte; 16],
            "module": "handshake",
            "label": "Primary HNS",
            "receiveDisplay": null
        })
    }

    #[cfg(target_os = "linux")]
    fn hns_transaction_json(txid_byte: u8, status: &str, confirmed: bool) -> Value {
        json!({
            "module": "handshake",
            "txid": vec![txid_byte; 32],
            "status": status,
            "net_amount": {
                "negative": false,
                "magnitude": "17"
            },
            "fee": "2",
            "block_height": if confirmed { Some(100_u64) } else { None },
            "first_seen_unix": 1_700_000_000_u64,
            "confirmation_count": if confirmed { 6_u32 } else { 0_u32 }
        })
    }

    #[test]
    fn production_tables_contain_no_fixture_trust_or_release_authority() {
        assert!(PRODUCTION_WALLET_TRUST_ROOTS.is_empty());
        assert!(PRODUCTION_QUALIFIED_WALLET_RELEASES.is_empty());
        assert!(PRODUCTION_WALLET_RELEASE_FLOORS.is_empty());

        let root = test_root("production-empty");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let discovery = WalletAbiDiscovery::discover(&root);
        assert_eq!(discovery.status_json()["artifactState"], "integrityChecked");
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactAuthenticityUnavailable"
        );
        assert_eq!(
            discovery.status_json()["artifactAuthenticityVerified"],
            false
        );
        cleanup(&root);
        drop(release);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_transport_uses_one_exact_big_endian_bounded_frame() {
        let (mut host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(host.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let mut prefix = [0_u8; 4];
            service.read_exact(&mut prefix).unwrap();
            assert_eq!(prefix, 5_u32.to_be_bytes());
            let mut payload = [0_u8; 5];
            service.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"hello");
            service.write_all(&3_u32.to_be_bytes()).unwrap();
            service.write_all(b"ack").unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        write_wallet_payload(&mut host, b"hello", deadline).unwrap();
        assert_eq!(read_wallet_payload(&mut host, deadline).unwrap(), b"ack");
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_transport_rejects_oversized_truncated_and_eof_frames() {
        let (mut oversized_reader, mut oversized_writer) = UnixStream::pair().unwrap();
        set_nonblocking_fd(oversized_reader.as_raw_fd()).unwrap();
        oversized_writer
            .write_all(&(WALLET_ABI_MAX_FRAME_BYTES + 1).to_be_bytes())
            .unwrap();
        drop(oversized_writer);
        assert_eq!(
            read_wallet_payload(
                &mut oversized_reader,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );

        let (mut truncated_reader, mut truncated_writer) = UnixStream::pair().unwrap();
        set_nonblocking_fd(truncated_reader.as_raw_fd()).unwrap();
        truncated_writer.write_all(&5_u32.to_be_bytes()).unwrap();
        truncated_writer.write_all(b"ab").unwrap();
        drop(truncated_writer);
        assert_eq!(
            read_wallet_payload(
                &mut truncated_reader,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (mut eof_reader, eof_writer) = UnixStream::pair().unwrap();
        set_nonblocking_fd(eof_reader.as_raw_fd()).unwrap();
        drop(eof_writer);
        assert_eq!(
            read_wallet_payload(&mut eof_reader, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_transport_bounds_silent_peers_and_reports_write_failure() {
        let (mut timeout_reader, timeout_peer) = UnixStream::pair().unwrap();
        set_nonblocking_fd(timeout_reader.as_raw_fd()).unwrap();
        let timeout = read_wallet_payload(
            &mut timeout_reader,
            Instant::now() + Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);
        drop(timeout_peer);

        let (mut failed_writer, failed_peer) = UnixStream::pair().unwrap();
        set_nonblocking_fd(failed_writer.as_raw_fd()).unwrap();
        drop(failed_peer);
        let failure = write_wallet_payload(
            &mut failed_writer,
            b"request",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(
            failure.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hns_read_operations_v1_is_exactly_the_six_closed_requests() {
        let account = [9_u8; 16];
        let requests = [
            WalletReadOnlyRequest::Status,
            WalletReadOnlyRequest::ListAccounts,
            WalletReadOnlyRequest::Balance {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyRequest::ReceiveTarget {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyRequest::TransactionHistory {
                module: WalletReadOnlyModule::Handshake,
                account,
            },
            WalletReadOnlyRequest::ModuleStatus {
                module: WalletReadOnlyModule::Handshake,
            },
        ];
        let operation_names = requests
            .into_iter()
            .map(|request| {
                let frozen_name = match request {
                    WalletReadOnlyRequest::Status => "status",
                    WalletReadOnlyRequest::ListAccounts => "listAccounts",
                    WalletReadOnlyRequest::Balance { .. } => "balance",
                    WalletReadOnlyRequest::ReceiveTarget { .. } => "receiveTarget",
                    WalletReadOnlyRequest::TransactionHistory { .. } => "transactionHistory",
                    WalletReadOnlyRequest::ModuleStatus { .. } => "moduleStatus",
                };
                assert_eq!(
                    serde_json::to_value(request).unwrap()["operation"],
                    frozen_name
                );
                frozen_name
            })
            .collect::<Vec<_>>();
        assert_eq!(
            operation_names,
            [
                "status",
                "listAccounts",
                "balance",
                "receiveTarget",
                "transactionHistory",
                "moduleStatus"
            ]
        );
        assert_eq!(operation_names.len(), 6);
        assert!(
            !operation_names
                .iter()
                .any(|operation| operation.contains("workflow"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_controller_negotiates_sessions_and_sequences_for_status() {
        let (host, service) = status_service_fixture(2);
        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            7,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!controller.provider_available());
        assert!(!controller.value_available());

        assert_eq!(
            controller.read_all().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!controller.poisoned);

        let second = controller.read_status().unwrap();
        assert!(!second.locked);
        assert_eq!(second.enabled_modules(), &[WalletReadOnlyModule::Handshake]);
        assert!(!controller.provider_available());
        assert!(!controller.value_available());
        drop(controller);
        service.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_status_clears_both_selected_wallet_and_account() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 31);
            let responses = [
                json!({
                    "result": "status",
                    "status": {
                        "locked": false,
                        "activeWallet": vec![7_u8; 16],
                        "enabledModules": ["handshake"],
                        "mainnetSettlementEnabled": false
                    }
                }),
                json!({
                    "result": "accounts",
                    "accounts": [hns_account_json(9)]
                }),
                json!({
                    "result": "status",
                    "status": {
                        "locked": true,
                        "activeWallet": null,
                        "enabledModules": [],
                        "mainnetSettlementEnabled": false
                    }
                }),
            ];
            let operations = ["status", "listAccounts", "status"];
            for (index, (operation, response)) in operations.into_iter().zip(responses).enumerate()
            {
                let sequence = index as u64 + 1;
                let deadline = Instant::now() + Duration::from_secs(2);
                let request = read_wallet_payload(&mut service, deadline).unwrap();
                let request = serde_json::from_slice::<Value>(&request).unwrap();
                assert_wallet_fixture_request(
                    &request,
                    &host_session,
                    &service_session,
                    restart_generation,
                    sequence,
                    json!({
                        "operation": "wallet",
                        "request": { "operation": operation }
                    }),
                );
                write_wallet_fixture_result(
                    &mut service,
                    deadline,
                    (&host_session, &service_session, restart_generation),
                    sequence,
                    &request,
                    response,
                );
            }
        });
        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            7,
            Duration::from_secs(2),
        )
        .unwrap();

        assert!(!controller.read_status().unwrap().locked);
        assert_eq!(controller.selected_active_wallet, Some([7_u8; 16]));
        assert_eq!(controller.list_accounts().unwrap().account_id, [9_u8; 16]);
        assert_eq!(controller.selected_hns_account, Some([9_u8; 16]));
        assert!(controller.read_status().unwrap().locked);
        assert_eq!(controller.selected_active_wallet, None);
        assert_eq!(controller.selected_hns_account, None);
        drop(controller);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_controller_reads_the_exact_selected_hns_account_operations() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 21);
            let account = vec![9_u8; 16];

            for sequence in 1..=6 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let request = read_wallet_payload(&mut service, deadline).unwrap();
                let request = serde_json::from_slice::<Value>(&request).unwrap();
                let (expected_body, response) = match sequence {
                    1 => (
                        json!({
                            "operation": "wallet",
                            "request": { "operation": "status" }
                        }),
                        json!({
                            "result": "status",
                            "status": {
                                "locked": false,
                                "activeWallet": vec![7_u8; 16],
                                "enabledModules": ["handshake"],
                                "mainnetSettlementEnabled": false
                            }
                        }),
                    ),
                    2 => (
                        json!({
                            "operation": "wallet",
                            "request": { "operation": "listAccounts" }
                        }),
                        json!({
                            "result": "accounts",
                            "accounts": [hns_account_json(9)]
                        }),
                    ),
                    3 => (
                        json!({
                            "operation": "wallet",
                            "request": {
                                "operation": "balance",
                                "module": "handshake",
                                "account": account
                            }
                        }),
                        json!({
                            "result": "balance",
                            "amount": {
                                "asset": "HNS",
                                "base_units": "340282366920938463463374607431768211455"
                            }
                        }),
                    ),
                    4 => (
                        json!({
                            "operation": "wallet",
                            "request": {
                                "operation": "receiveTarget",
                                "module": "handshake",
                                "account": account
                            }
                        }),
                        json!({
                            "result": "receiveTarget",
                            "target": {
                                "module": "handshake",
                                "account": account,
                                "display": "rs1qchromiumwallet",
                                "derivation_index": 7
                            }
                        }),
                    ),
                    5 => (
                        json!({
                            "operation": "wallet",
                            "request": {
                                "operation": "transactionHistory",
                                "module": "handshake",
                                "account": account
                            }
                        }),
                        json!({
                            "result": "transactionHistory",
                            "transactions": [
                                hns_transaction_json(0xab, "confirmed", true),
                                hns_transaction_json(0xcd, "mempool", false)
                            ]
                        }),
                    ),
                    6 => (
                        json!({
                            "operation": "wallet",
                            "request": {
                                "operation": "moduleStatus",
                                "module": "handshake"
                            }
                        }),
                        json!({
                            "result": "moduleStatus",
                            "status": {
                                "phase": "ready",
                                "validated_height": 100,
                                "scanned_height": 100,
                                "target_height": 100,
                                "last_error": null
                            }
                        }),
                    ),
                    _ => unreachable!(),
                };
                assert_wallet_fixture_request(
                    &request,
                    &host_session,
                    &service_session,
                    restart_generation,
                    sequence,
                    expected_body,
                );
                write_wallet_fixture_result(
                    &mut service,
                    deadline,
                    (&host_session, &service_session, restart_generation),
                    sequence,
                    &request,
                    response,
                );
            }
        });

        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            20,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            controller.read_balance().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let view = controller.read_all().unwrap();
        assert!(!view.status.locked);
        assert_eq!(view.status.active_wallet, Some([7_u8; 16]));
        assert_eq!(
            view.status.enabled_modules(),
            &[WalletReadOnlyModule::Handshake]
        );

        assert_eq!(view.account.account_id, [9_u8; 16]);
        assert_eq!(view.account.module, WalletReadOnlyModule::Handshake);
        assert_eq!(view.account.label, "Primary HNS");
        assert!(view.account.receive_display.is_none());

        assert_eq!(view.balance.asset, WalletReadOnlyAsset::Hns);
        assert_eq!(view.balance.base_units.get(), u128::MAX);

        assert_eq!(view.receive_target.account, [9_u8; 16]);
        assert_eq!(view.receive_target.display, "rs1qchromiumwallet");
        assert_eq!(view.receive_target.derivation_index, 7);

        assert_eq!(view.transactions.len(), 2);
        assert_eq!(view.transactions[0].txid, [0xab; 32]);
        assert_eq!(
            view.transactions[0].status,
            WalletReadOnlyTransactionStatus::Confirmed
        );
        assert_eq!(
            view.transactions[0].fee.map(WalletReadOnlyBaseUnits::get),
            Some(2)
        );
        assert_eq!(view.transactions[0].block_height, Some(100));
        assert_eq!(view.transactions[0].first_seen_unix, Some(1_700_000_000));
        assert_eq!(view.transactions[0].confirmation_count, 6);
        assert_eq!(
            view.transactions[1].status,
            WalletReadOnlyTransactionStatus::Mempool
        );

        assert_eq!(view.module_status.phase, WalletReadOnlySyncPhase::Ready);
        assert_eq!(view.module_status.validated_height, 100);
        assert_eq!(view.module_status.scanned_height, 100);
        assert_eq!(view.module_status.target_height, Some(100));
        assert!(view.module_status.last_error.is_none());
        assert!(!controller.provider_available());
        assert!(!controller.value_available());
        drop(controller);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_read_response_class_substitution_poisons_the_session() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 22);
            let request = read_wallet_payload(&mut service, deadline).unwrap();
            let request = serde_json::from_slice::<Value>(&request).unwrap();
            assert_wallet_fixture_request(
                &request,
                &host_session,
                &service_session,
                restart_generation,
                1,
                json!({
                    "operation": "wallet",
                    "request": { "operation": "listAccounts" }
                }),
            );
            write_wallet_fixture_result(
                &mut service,
                deadline,
                (&host_session, &service_session, restart_generation),
                1,
                &request,
                json!({
                    "result": "balance",
                    "amount": { "asset": "HNS", "base_units": "42" }
                }),
            );
        });

        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            21,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            controller.list_accounts().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(controller);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_read_domain_validation_failure_poisons_the_session() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 23);
            let request = read_wallet_payload(&mut service, deadline).unwrap();
            let request = serde_json::from_slice::<Value>(&request).unwrap();
            assert_wallet_fixture_request(
                &request,
                &host_session,
                &service_session,
                restart_generation,
                1,
                json!({
                    "operation": "wallet",
                    "request": { "operation": "status" }
                }),
            );
            write_wallet_fixture_result(
                &mut service,
                deadline,
                (&host_session, &service_session, restart_generation),
                1,
                &request,
                json!({
                    "result": "status",
                    "status": {
                        "locked": false,
                        "activeWallet": vec![7_u8; 16],
                        "enabledModules": ["handshake"],
                        "mainnetSettlementEnabled": true
                    }
                }),
            );
        });

        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            22,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(controller);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_read_models_reject_non_hns_noncanonical_and_incoherent_values() {
        assert_eq!(
            serde_json::from_value::<WalletReadOnlyBaseUnits>(json!("0"))
                .unwrap()
                .get(),
            0
        );
        assert!(serde_json::from_value::<WalletReadOnlyBaseUnits>(json!("00")).is_err());
        assert!(serde_json::from_value::<WalletReadOnlyBaseUnits>(json!("+1")).is_err());
        assert!(
            serde_json::from_value::<WalletReadOnlyBaseUnits>(json!(
                "340282366920938463463374607431768211456"
            ))
            .is_err()
        );

        let bitcoin_amount = serde_json::from_value::<WalletReadOnlyAmount>(json!({
            "asset": "BTC",
            "base_units": "42"
        }))
        .unwrap();
        assert!(!bitcoin_amount.validate());
        assert!(
            serde_json::from_value::<WalletReadOnlyAmount>(json!({
                "asset": "HNS",
                "baseUnits": "42"
            }))
            .is_err()
        );

        let zero_account = serde_json::from_value::<WalletReadOnlyAccountSummary>(json!({
            "accountId": vec![0_u8; 16],
            "module": "handshake",
            "label": "Primary HNS",
            "receiveDisplay": null
        }))
        .unwrap();
        assert!(!zero_account.validate());
        let non_hns_account = serde_json::from_value::<WalletReadOnlyAccountSummary>(json!({
            "accountId": vec![9_u8; 16],
            "module": "bitcoin",
            "label": "Primary HNS",
            "receiveDisplay": null
        }))
        .unwrap();
        assert!(!non_hns_account.validate());
        let maximum_account_display =
            serde_json::from_value::<WalletReadOnlyAccountSummary>(json!({
                "accountId": vec![9_u8; 16],
                "module": "handshake",
                "label": "Primary HNS",
                "receiveDisplay": "x".repeat(MAX_WALLET_PUBLIC_STRING_BYTES)
            }))
            .unwrap();
        assert!(maximum_account_display.validate());
        let oversized_account_display =
            serde_json::from_value::<WalletReadOnlyAccountSummary>(json!({
                "accountId": vec![9_u8; 16],
                "module": "handshake",
                "label": "Primary HNS",
                "receiveDisplay": "x".repeat(MAX_WALLET_PUBLIC_STRING_BYTES + 1)
            }))
            .unwrap();
        assert!(!oversized_account_display.validate());

        let wrong_target = serde_json::from_value::<WalletReadOnlyReceiveTarget>(json!({
            "module": "handshake",
            "account": vec![8_u8; 16],
            "display": "rs1qwrongaccount",
            "derivation_index": 0
        }))
        .unwrap();
        assert!(!wrong_target.validate([9_u8; 16]));
        let spaced_target = serde_json::from_value::<WalletReadOnlyReceiveTarget>(json!({
            "module": "handshake",
            "account": vec![9_u8; 16],
            "display": "rs1q invalid",
            "derivation_index": 0
        }))
        .unwrap();
        assert!(!spaced_target.validate([9_u8; 16]));
        assert!(
            serde_json::from_value::<WalletReadOnlyReceiveTarget>(json!({
                "module": "handshake",
                "account": vec![9_u8; 16],
                "display": "rs1qwirecase",
                "derivationIndex": 0
            }))
            .is_err()
        );

        let negative_zero = serde_json::from_value::<WalletReadOnlyTransactionSummary>(json!({
            "module": "handshake",
            "txid": vec![1_u8; 32],
            "status": "mempool",
            "net_amount": { "negative": true, "magnitude": "0" },
            "fee": null,
            "block_height": null,
            "first_seen_unix": 1,
            "confirmation_count": 0
        }))
        .unwrap();
        assert!(!negative_zero.validate());
        let valid_transaction = serde_json::from_value::<WalletReadOnlyTransactionSummary>(
            hns_transaction_json(1, "mempool", false),
        )
        .unwrap();
        assert!(valid_transaction.validate());
        assert!(!validate_wallet_transaction_history(&[
            valid_transaction.clone(),
            valid_transaction
        ]));
        let structurally_valid_unconfirmed = serde_json::from_value::<
            WalletReadOnlyTransactionSummary,
        >(hns_transaction_json(2, "confirmed", false))
        .unwrap();
        assert!(structurally_valid_unconfirmed.validate());
        let oversized_history = (1_u8..=129)
            .map(|txid| {
                serde_json::from_value::<WalletReadOnlyTransactionSummary>(hns_transaction_json(
                    txid, "mempool", false,
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(!validate_wallet_transaction_history(&oversized_history));
        assert!(
            serde_json::from_value::<WalletReadOnlyTransactionSummary>(json!({
                "module": "handshake",
                "txid": vec![1_u8; 32],
                "status": "mempool",
                "netAmount": { "negative": false, "magnitude": "1" },
                "fee": null,
                "blockHeight": null,
                "firstSeenUnix": 1,
                "confirmationCount": 0
            }))
            .is_err()
        );

        let not_ready = serde_json::from_value::<WalletReadOnlySyncStatus>(json!({
            "phase": "headers",
            "validated_height": 100,
            "scanned_height": 100,
            "target_height": 100,
            "last_error": null
        }))
        .unwrap();
        assert!(!not_ready.validate());
        let mismatched_height = serde_json::from_value::<WalletReadOnlySyncStatus>(json!({
            "phase": "ready",
            "validated_height": 100,
            "scanned_height": 99,
            "target_height": 100,
            "last_error": null
        }))
        .unwrap();
        assert!(!mismatched_height.validate());
        let reported_error = serde_json::from_value::<WalletReadOnlySyncStatus>(json!({
            "phase": "ready",
            "validated_height": 100,
            "scanned_height": 100,
            "target_height": 100,
            "last_error": "backend unavailable"
        }))
        .unwrap();
        assert!(!reported_error.validate());
        assert!(
            serde_json::from_value::<WalletReadOnlySyncStatus>(json!({
                "phase": "ready",
                "validatedHeight": 100,
                "scannedHeight": 100,
                "targetHeight": 100,
                "lastError": null
            }))
            .is_err()
        );

        let missing_active_wallet = serde_json::from_value::<WalletReadOnlyStatus>(json!({
            "locked": false,
            "activeWallet": null,
            "enabledModules": ["handshake"],
            "mainnetSettlementEnabled": false
        }))
        .unwrap();
        assert!(!missing_active_wallet.validate());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_wallet_failure_advances_the_correlated_session() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 4);

            let first = read_wallet_payload(&mut service, deadline).unwrap();
            let first = serde_json::from_slice::<Value>(&first).unwrap();
            assert_eq!(first["envelope"]["channelSequence"], 1);
            assert_eq!(
                first["envelope"]["body"],
                json!({
                    "operation": "wallet",
                    "request": { "operation": "listAccounts" }
                })
            );
            let failure = json!({
                "frameType": "response",
                "envelope": {
                    "protocolVersion": 2,
                    "hostSessionId": host_session,
                    "serviceSessionId": service_session,
                    "restartGeneration": restart_generation,
                    "channelSequence": 1,
                    "requestId": first["envelope"]["requestId"],
                    "body": {
                        "result": "failure",
                        "failure": {
                            "code": "persistenceFailure",
                            "message": "internal store detail must not cross the browser boundary",
                            "unsupportedCapability": null
                        }
                    }
                }
            });
            write_wallet_payload(
                &mut service,
                &serde_json::to_vec(&failure).unwrap(),
                deadline,
            )
            .unwrap();

            let second = read_wallet_payload(&mut service, deadline).unwrap();
            let second = serde_json::from_slice::<Value>(&second).unwrap();
            assert_eq!(second["envelope"]["channelSequence"], 2);
            assert_eq!(
                second["envelope"]["body"],
                json!({
                    "operation": "wallet",
                    "request": { "operation": "status" }
                })
            );
            let status = json!({
                "frameType": "response",
                "envelope": {
                    "protocolVersion": 2,
                    "hostSessionId": host_session,
                    "serviceSessionId": service_session,
                    "restartGeneration": restart_generation,
                    "channelSequence": 2,
                    "requestId": second["envelope"]["requestId"],
                    "body": {
                        "result": "wallet",
                        "response": {
                            "result": "status",
                            "status": {
                                "locked": true,
                                "activeWallet": null,
                                "enabledModules": [],
                                "mainnetSettlementEnabled": false
                            }
                        }
                    }
                }
            });
            write_wallet_payload(
                &mut service,
                &serde_json::to_vec(&status).unwrap(),
                deadline,
            )
            .unwrap();
        });

        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            10,
            Duration::from_secs(2),
        )
        .unwrap();
        let failure = controller.list_accounts().unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::Other);
        assert_eq!(failure.to_string(), "wallet service persistence failed");
        assert!(controller.read_status().unwrap().locked);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protocol_wallet_failure_poisons_the_correlated_session() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (host_session, restart_generation, service_session) =
                negotiate_fixture_service(&mut service, deadline, 5);
            let request = read_wallet_payload(&mut service, deadline).unwrap();
            let request = serde_json::from_slice::<Value>(&request).unwrap();
            let failure = json!({
                "frameType": "response",
                "envelope": {
                    "protocolVersion": 2,
                    "hostSessionId": host_session,
                    "serviceSessionId": service_session,
                    "restartGeneration": restart_generation,
                    "channelSequence": 1,
                    "requestId": request["envelope"]["requestId"],
                    "body": {
                        "result": "failure",
                        "failure": {
                            "code": "invalidFrame",
                            "message": "invalid frame",
                            "unsupportedCapability": null
                        }
                    }
                }
            });
            write_wallet_payload(
                &mut service,
                &serde_json::to_vec(&failure).unwrap(),
                deadline,
            )
            .unwrap();
        });

        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            11,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_failure_shape_and_protocol_classification_are_exact() {
        let protocol_codes = [
            WalletServiceErrorCode::InvalidFrame,
            WalletServiceErrorCode::VersionMismatch,
            WalletServiceErrorCode::SessionMismatch,
            WalletServiceErrorCode::SequenceMismatch,
            WalletServiceErrorCode::Replay,
            WalletServiceErrorCode::UnsupportedCapability,
        ];
        for code in protocol_codes {
            assert!(code.is_protocol_failure());
        }
        assert!(!WalletServiceErrorCode::PersistenceFailure.is_protocol_failure());
        assert!(!WalletServiceErrorCode::RuntimeFailure.is_protocol_failure());

        let missing_nullable = json!({
            "result": "failure",
            "failure": {
                "code": "persistenceFailure",
                "message": "store failed"
            }
        });
        assert!(serde_json::from_value::<WalletReadOnlyServiceResponse>(missing_nullable).is_err());

        let inconsistent = json!({
            "result": "failure",
            "failure": {
                "code": "unsupportedCapability",
                "message": "unsupported",
                "unsupportedCapability": null
            }
        });
        let WalletReadOnlyServiceResponse::Failure { failure } =
            serde_json::from_value(inconsistent).unwrap()
        else {
            panic!("expected failure response");
        };
        assert!(!failure.validate());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_capabilities_cannot_exceed_the_qualified_manifest_ceiling() {
        let (host, service) = status_service_fixture(0);
        let reader = host.try_clone().unwrap();
        let admitted_capabilities = REQUIRED_BASE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect();
        let error = WalletServiceController::negotiate(
            reader,
            host,
            None,
            admitted_capabilities,
            8,
            Duration::from_secs(2),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        service.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_ceiling_with_both_markers_rejects_hello_without_hns_read_v1() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            write_fixture_service_hello(
                &mut service,
                Instant::now() + Duration::from_secs(2),
                24,
                json!([
                    "canonicalFraming",
                    "restartIsolation",
                    "opaqueAuthorityRegistry",
                    "persistentPermissions",
                    "structuredApprovals",
                    "typedEvents",
                    "walletOperations",
                    "providerDispatch"
                ]),
            );
        });
        let reader = host.try_clone().unwrap();
        let admitted_capabilities = WALLET_READ_SESSION_ALLOWED_CAPABILITIES
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert!(
            admitted_capabilities.contains(&NegotiatedWalletServiceCapability::WalletOperations)
        );
        assert!(
            admitted_capabilities.contains(&NegotiatedWalletServiceCapability::HnsReadOperationsV1)
        );
        let error = WalletServiceController::negotiate(
            reader,
            host,
            None,
            admitted_capabilities,
            24,
            Duration::from_secs(2),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_wallet_read_requires_both_operation_capability_markers() {
        let make_controller = |capabilities| {
            let (host, peer) = UnixStream::pair().unwrap();
            drop(peer);
            let reader = host.try_clone().unwrap();
            WalletServiceController {
                reader,
                writer: host,
                process: None,
                timeout: Duration::from_secs(1),
                host_session_id: URL_SAFE_NO_PAD.encode([25_u8; 32]),
                service_session_id: URL_SAFE_NO_PAD.encode([26_u8; 32]),
                restart_generation: 1,
                next_host_sequence: 1,
                next_service_sequence: 1,
                capabilities,
                selected_active_wallet: None,
                selected_hns_account: None,
                poisoned: false,
            }
        };
        for missing in [
            NegotiatedWalletServiceCapability::WalletOperations,
            NegotiatedWalletServiceCapability::HnsReadOperationsV1,
        ] {
            let mut capabilities = WALLET_READ_SESSION_REQUIRED_CAPABILITIES
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert!(capabilities.remove(&missing));
            let mut controller = make_controller(capabilities);
            assert_eq!(
                controller.read_status().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_service_hello_poisons_the_controller() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            read_wallet_payload(&mut service, deadline).unwrap();
            write_wallet_payload(&mut service, b"{}", deadline).unwrap();
        });
        let reader = host.try_clone().unwrap();
        let error = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            1,
            Duration::from_secs(1),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_required_nullable_status_field_poisons_the_negotiated_session() {
        let (host, mut service) = UnixStream::pair().unwrap();
        set_nonblocking_fd(service.as_raw_fd()).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            let hello = read_wallet_payload(&mut service, deadline).unwrap();
            let hello = serde_json::from_slice::<Value>(&hello).unwrap();
            let host_session = hello["hello"]["hostSessionId"].as_str().unwrap();
            let restart_generation = hello["hello"]["restartGeneration"].as_u64().unwrap();
            let service_session = URL_SAFE_NO_PAD.encode([3_u8; 32]);
            let service_hello = json!({
                "frameType": "hello",
                "hello": {
                    "protocolVersion": 2,
                    "platform": "chromiumNativeHost",
                    "hostSessionId": host_session,
                    "serviceSessionId": service_session,
                    "restartGeneration": restart_generation,
                    "capabilities": [
                        "canonicalFraming",
                        "restartIsolation",
                        "opaqueAuthorityRegistry",
                        "structuredApprovals",
                        "typedEvents",
                        "walletOperations",
                        "hnsReadOperationsV1"
                    ],
                    "limits": {
                        "outerFrameBytes": 1_048_576,
                        "providerRequestBytes": 65_536,
                        "providerResultBytes": 262_144,
                        "providerEventBytes": 65_536,
                        "approvalFrameBytes": 16_384,
                        "approvalLifetimeMs": 90_000
                    }
                }
            });
            write_wallet_payload(
                &mut service,
                &serde_json::to_vec(&service_hello).unwrap(),
                deadline,
            )
            .unwrap();
            let request = read_wallet_payload(&mut service, deadline).unwrap();
            let request = serde_json::from_slice::<Value>(&request).unwrap();
            let malformed = json!({
                "frameType": "response",
                "envelope": {
                    "protocolVersion": 2,
                    "hostSessionId": host_session,
                    "serviceSessionId": service_session,
                    "restartGeneration": restart_generation,
                    "channelSequence": 1,
                    "requestId": request["envelope"]["requestId"],
                    "body": {
                        "result": "wallet",
                        "response": {
                            "result": "status",
                            "status": {
                                "locked": true,
                                "enabledModules": [],
                                "mainnetSettlementEnabled": false
                            }
                        }
                    }
                }
            });
            write_wallet_payload(
                &mut service,
                &serde_json::to_vec(&malformed).unwrap(),
                deadline,
            )
            .unwrap();
        });
        let reader = host.try_clone().unwrap();
        let mut controller = WalletServiceController::negotiate(
            reader,
            host,
            None,
            test_capability_ceiling(),
            9,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            controller.read_status().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        task.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_child_guard_kills_and_reaps_the_service() {
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let process_id = child.id() as libc::pid_t;
        let mut process = WalletServiceProcess::new(child);
        process.terminate();
        assert!(process.child.is_none());
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_namespace_claim_uses_canonical_magic_and_exact_u64_generation() {
        assert_eq!(
            WalletNamespaceLeaseClaim::new(NetworkKind::Regtest, [0_u8; 16], 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            WalletNamespaceLeaseClaim::new(NetworkKind::Regtest, [1_u8; 16], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let generation = 9_007_199_254_740_997_u64;
        for network in [
            NetworkKind::Mainnet,
            NetworkKind::Testnet,
            NetworkKind::Regtest,
        ] {
            let claim =
                WalletNamespaceLeaseClaim::new(network, TEST_WALLET_NAMESPACE_ID, generation)
                    .unwrap();
            assert_eq!(claim.network, network);
            assert_eq!(claim.network_magic, network.network().magic);
            assert_eq!(claim.namespace_id, TEST_WALLET_NAMESPACE_ID);
            assert_eq!(claim.generation, generation);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn namespace_guard_loss_and_callback_misuse_kill_reap_and_remove_session() {
        let cases: [(&str, Box<dyn WalletNamespaceLeaseGuard>, usize); 3] = [
            (
                "deny-after-use",
                Box::new(DenyAfterUseWalletNamespaceGuard),
                1,
            ),
            ("skip-use", Box::new(SkipUseWalletNamespaceGuard), 0),
            ("double-use", Box::new(DoubleUseWalletNamespaceGuard), 1),
        ];
        for (label, guard, expected_operation_count) in cases {
            let root = test_root(label);
            let (_, database) = install_test_wallet_database(&root);
            let child = spawn_test_wallet_child_with_database(&database.database_file);
            let process_id = child.id() as libc::pid_t;
            let controller = test_spawned_wallet_controller(child, 12, Duration::from_secs(1));
            let namespace_lease = test_wallet_namespace_lease_with_guard(
                NetworkKind::Regtest,
                TEST_WALLET_NAMESPACE_ID,
                9_007_199_254_740_997,
                guard,
            );
            let session =
                AdmittedWalletReadSession::new(controller, database, namespace_lease, 12).unwrap();
            let mut lifecycle = WalletReadSessionLifecycle {
                next_restart_generation: 13,
                active: Some(session),
            };
            let mut operation_count = 0_usize;
            let error = lifecycle
                .execute_active(12, |session| {
                    session.execute(|_| {
                        operation_count += 1;
                        Ok(())
                    })
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(operation_count, expected_operation_count);
            assert!(lifecycle.active.is_none());
            assert_wallet_child_killed_and_reaped(process_id);
            cleanup(&root);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn caught_namespace_guard_panics_kill_reap_and_remove_before_resuming() {
        let cases: [(&str, Box<dyn WalletNamespaceLeaseGuard>, usize); 2] = [
            (
                "panic-before-use",
                Box::new(PanicBeforeUseWalletNamespaceGuard),
                0,
            ),
            (
                "panic-after-use",
                Box::new(PanicAfterUseWalletNamespaceGuard),
                1,
            ),
        ];
        for (label, guard, expected_operation_count) in cases {
            let root = test_root(label);
            let (_, database) = install_test_wallet_database(&root);
            let child = spawn_test_wallet_child_with_database(&database.database_file);
            let process_id = child.id() as libc::pid_t;
            let controller = test_spawned_wallet_controller(child, 12, Duration::from_secs(1));
            let namespace_lease = test_wallet_namespace_lease_with_guard(
                NetworkKind::Regtest,
                TEST_WALLET_NAMESPACE_ID,
                9_007_199_254_740_997,
                guard,
            );
            let session =
                AdmittedWalletReadSession::new(controller, database, namespace_lease, 12).unwrap();
            let mut lifecycle = WalletReadSessionLifecycle {
                next_restart_generation: 13,
                active: Some(session),
            };
            let mut operation_count = 0_usize;
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = lifecycle.execute_active(12, |session| {
                    session.execute(|_| {
                        operation_count += 1;
                        Ok(())
                    })
                });
            }));
            assert!(panic.is_err());
            assert_eq!(operation_count, expected_operation_count);
            assert!(lifecycle.active.is_none());
            assert_wallet_child_killed_and_reaped(process_id);
            assert_eq!(
                lifecycle.read_status(12).unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
            cleanup(&root);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_spawned_negotiation_kills_and_reaps_the_service() {
        let child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let process_id = child.id() as libc::pid_t;
        let admitted = WALLET_READ_SESSION_ALLOWED_CAPABILITIES
            .into_iter()
            .collect::<BTreeSet<_>>();
        let error = SpawnedWalletServiceController::negotiate_spawned(
            child,
            admitted,
            1,
            Duration::from_secs(1),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_read_lifecycle_requires_one_generation_bound_bootstrap_lease() {
        let root = test_root("required-bootstrap-lease");
        let wallet_root = test_root("required-bootstrap-lease-wallet");
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        let mut discovery = WalletAbiDiscovery::discover(&root);
        let (_, database) = install_test_wallet_database(&wallet_root);
        let (mut source, bootstrap_write) = test_wallet_bootstrap_source(1, database);
        let mut lifecycle = WalletReadSessionLifecycle::new();

        assert_eq!(
            lifecycle
                .start(
                    &mut discovery,
                    &mut source,
                    NetworkKind::Regtest,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_pipe_has_no_readers(&bootstrap_write);
        assert_eq!(
            lifecycle
                .start(
                    &mut discovery,
                    &mut source,
                    NetworkKind::Regtest,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(source.claimed_generations, [1, 2]);
        assert_eq!(lifecycle.next_restart_generation, 3);
        assert!(lifecycle.active.is_none());

        let mut unavailable = UnavailableWalletBootstrapSource;
        assert!(
            unavailable
                .take_lease(3, NetworkKind::Regtest)
                .unwrap()
                .is_none()
        );
        cleanup(&root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_bootstrap_lease_rejects_zero_stale_and_future_restart_generations() {
        let root = test_root("generation-bound-bootstrap-lease");
        let wallet_root = test_root("generation-bound-bootstrap-lease-wallet");
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        let mut discovery = WalletAbiDiscovery::discover(&root);
        let (database_path, database) = install_test_wallet_database(&wallet_root);
        let (bootstrap_read, bootstrap_write) = test_wallet_bootstrap_pipe();
        assert_eq!(
            WalletBootstrapLease::new(
                0,
                database,
                test_wallet_namespace_lease(NetworkKind::Regtest, 1),
                bootstrap_read,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_pipe_has_no_readers(&bootstrap_write);

        for lease_generation in [1, 3] {
            let database = TrustedWalletDatabaseConfiguration::open(&database_path).unwrap();
            let (bootstrap_read, bootstrap_write) = test_wallet_bootstrap_pipe();
            let lease = WalletBootstrapLease::new(
                lease_generation,
                database,
                test_wallet_namespace_lease(NetworkKind::Regtest, lease_generation),
                bootstrap_read,
            )
            .unwrap();
            let error = discovery
                .compose_admitted_read_session(
                    lease,
                    2,
                    NetworkKind::Regtest,
                    Duration::from_secs(1),
                )
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                "wallet bootstrap lease restart generation mismatch"
            );
            assert_pipe_has_no_readers(&bootstrap_write);
        }

        cleanup(&root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wallet_bootstrap_lease_is_opaque_and_requires_a_private_pipe_read_end() {
        use std::os::unix::fs::PermissionsExt;

        let wallet_root = test_root("opaque-bootstrap-lease");
        let (database_path, database) = install_test_wallet_database(&wallet_root);
        let (bootstrap_read, mut bootstrap_write) = test_wallet_bootstrap_pipe();
        let secret = "bootstrap-secret-must-not-appear";
        bootstrap_write.write_all(secret.as_bytes()).unwrap();
        let lease = WalletBootstrapLease::new(
            7,
            database,
            test_wallet_namespace_lease(NetworkKind::Regtest, 7),
            bootstrap_read,
        )
        .unwrap();
        let debug = format!("{lease:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains(database_path.to_str().unwrap()));
        assert!(!debug.contains("fd:"));
        assert!(!debug.contains("7"));
        assert!(debug.contains("<bound>"));
        assert!(debug.contains("<retained identity>"));
        assert!(debug.contains("<opaque single-use descriptor>"));
        drop(lease);
        assert_pipe_has_no_readers(&bootstrap_write);

        let regular = File::open(&database_path).unwrap();
        assert_eq!(
            require_wallet_bootstrap_read_descriptor(&regular)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let (read, write) = test_wallet_bootstrap_pipe();
        assert_eq!(
            require_wallet_bootstrap_read_descriptor(&write)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let descriptor = read.as_raw_fd();
        // SAFETY: fcntl mutates only the live test descriptor's close-on-exec
        // flag and retains no pointer.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) }, 0);
        assert_eq!(
            require_wallet_bootstrap_read_descriptor(&read)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::metadata(&database_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_child_descriptor_collision_is_duplicated_close_on_exec() {
        use std::os::unix::fs::MetadataExt;

        let (read, _write) = test_wallet_bootstrap_pipe();
        let reserved = read.as_raw_fd();
        let expected = read.metadata().unwrap();
        let duplicated = duplicate_file_at_or_above(read, reserved + 1).unwrap();
        assert!(duplicated.as_raw_fd() > reserved);
        let actual = duplicated.metadata().unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
        // SAFETY: fcntl inspects the live duplicate and retains no pointer.
        let flags = unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_mapping_inherits_only_fixed_bootstrap_fd_and_keeps_stdin_separate() {
        use std::os::unix::fs::MetadataExt;

        let sealed = duplicate_file_at_or_above(
            File::open("/bin/true").unwrap(),
            FIRST_WALLET_CHILD_AUXILIARY_DESCRIPTOR,
        )
        .unwrap();
        let (bootstrap_read, mut bootstrap_write) = test_wallet_bootstrap_pipe();
        let bootstrap_read =
            duplicate_file_at_or_above(bootstrap_read, FIRST_WALLET_CHILD_AUXILIARY_DESCRIPTOR)
                .unwrap();
        let expected_bootstrap = bootstrap_read.metadata().unwrap();
        bootstrap_write
            .write_all(b"opaque-wallet-bootstrap")
            .unwrap();
        let (abi_stdin_read, _abi_stdin_write) = test_wallet_bootstrap_pipe();
        let (result_read, result_write) = test_wallet_bootstrap_pipe();
        let sealed_descriptor = sealed.as_raw_fd();
        let original_bootstrap_descriptor = bootstrap_read.as_raw_fd();
        let abi_stdin_descriptor = abi_stdin_read.as_raw_fd();
        let expected_device = expected_bootstrap.dev();
        let expected_inode = expected_bootstrap.ino();

        // SAFETY: after fork, the child executes only async-signal-safe libc
        // calls before _exit. It does not touch allocator or lock state.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: the forked child performs only async-signal-safe libc
            // calls, uses valid inherited descriptors, and exits without
            // unwinding or touching allocator-backed state.
            unsafe {
                let mut success = libc::dup2(abi_stdin_descriptor, 0) == 0;
                success &= install_wallet_child_descriptors(
                    sealed_descriptor,
                    original_bootstrap_descriptor,
                )
                .is_ok();
                let mut fixed = std::mem::MaybeUninit::<libc::stat>::uninit();
                let mut stdin = std::mem::MaybeUninit::<libc::stat>::uninit();
                success &= libc::fstat(WALLET_BOOTSTRAP_DESCRIPTOR, fixed.as_mut_ptr()) == 0;
                success &= libc::fstat(0, stdin.as_mut_ptr()) == 0;
                if success {
                    let fixed = fixed.assume_init();
                    let stdin = stdin.assume_init();
                    success &= (fixed.st_dev, fixed.st_ino) == (expected_device, expected_inode);
                    success &= (stdin.st_dev, stdin.st_ino) != (expected_device, expected_inode);
                    let fixed_flags = libc::fcntl(WALLET_BOOTSTRAP_DESCRIPTOR, libc::F_GETFD);
                    let sealed_flags = libc::fcntl(sealed_descriptor, libc::F_GETFD);
                    success &= fixed_flags >= 0 && fixed_flags & libc::FD_CLOEXEC == 0;
                    success &= sealed_flags >= 0 && sealed_flags & libc::FD_CLOEXEC == 0;
                    if original_bootstrap_descriptor != WALLET_BOOTSTRAP_DESCRIPTOR {
                        let original_flags =
                            libc::fcntl(original_bootstrap_descriptor, libc::F_GETFD);
                        success &= original_flags >= 0 && original_flags & libc::FD_CLOEXEC != 0;
                    }
                }
                let result = u8::from(success);
                let _ = libc::write(result_write.as_raw_fd(), (&result as *const u8).cast(), 1);
                libc::_exit(i32::from(!success));
            }
        }

        drop(result_write);
        drop(bootstrap_read);
        let mut result_read = result_read;
        let mut result = [0_u8; 1];
        result_read.read_exact(&mut result).unwrap();
        let mut status = 0;
        // SAFETY: child is the live PID returned by fork and status points to
        // one initialized integer for the duration of waitpid.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(result, [1]);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_pipe_has_no_readers(&bootstrap_write);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn low_fd_command_spawn_preserves_stdio_and_fixed_bootstrap_descriptor() {
        const EXACT_TEST_NAME: &str = "wallet_abi::tests::low_fd_command_spawn_preserves_stdio_and_fixed_bootstrap_descriptor";

        if std::env::var_os(LOW_FD_SPAWN_HELPER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            let output = Command::new(std::env::current_exe().unwrap())
                .env(LOW_FD_SPAWN_HELPER_ENV, "1")
                .args([
                    "--exact",
                    EXACT_TEST_NAME,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated low-FD helper failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let root = test_root("low-fd-wallet-bootstrap-spawn");
        fs::create_dir_all(&root).unwrap();
        let executable_path = root.join("wallet-bootstrap-fd-fixture");
        let database_path = root.join("wallet.sqlite3");
        fs::write(
            &executable_path,
            b"#!/bin/sh\n\
              [ \"$#\" -eq 2 ] || exit 91\n\
              [ \"$1\" = \"--database\" ] || exit 92\n\
              [ \"${HNS_WALLET_LOW_FD_SPAWN_HELPER+x}\" != x ] || exit 93\n\
              IFS= read -r bootstrap <&3 || exit 94\n\
              IFS= read -r abi <&0 || exit 95\n\
              printf '%s\\n%s\\n%s\\n' \"$2\" \"$bootstrap\" \"$abi\"\n",
        )
        .unwrap();
        set_mode(&executable_path, 0o500);

        // Run this branch only in the isolated re-exec above. Making FD 3
        // vacant forces Rust Command's first stdin-pipe end into that slot.
        // Rust duplicates it to FD 0 before invoking our pre_exec callback,
        // which then replaces FD 3 with the opaque bootstrap pipe.
        let vacant = TemporarilyVacantDescriptor::new(WALLET_BOOTSTRAP_DESCRIPTOR);
        let sealed = File::open(&executable_path).unwrap();
        assert_eq!(sealed.as_raw_fd(), WALLET_BOOTSTRAP_DESCRIPTOR);
        let (bootstrap_read, mut bootstrap_write) = test_wallet_bootstrap_pipe();
        bootstrap_write.write_all(b"opaque-bootstrap\n").unwrap();
        drop(bootstrap_write);

        let mut child =
            spawn_sealed_linux_executable(sealed, &database_path, bootstrap_read).unwrap();
        drop(vacant);
        let mut child_stdin = child.stdin.take().unwrap();
        child_stdin.write_all(b"abi-stdin\n").unwrap();
        drop(child_stdin);
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{}\nopaque-bootstrap\nabi-stdin\n", database_path.display())
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_spawn_closes_the_consumed_bootstrap_read_end() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = test_root("failed-wallet-bootstrap-exec");
        fs::create_dir_all(&root).unwrap();
        let non_executable = root.join("not-an-executable");
        fs::write(&non_executable, b"not an executable image").unwrap();
        set_mode(&non_executable, 0o600);
        let sealed = File::open(&non_executable).unwrap();
        let (bootstrap_read, bootstrap_write) = test_wallet_bootstrap_pipe();
        assert_eq!(
            spawn_sealed_linux_executable(
                sealed,
                Path::new("/tmp/wallet-bootstrap.sqlite3"),
                bootstrap_read,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_pipe_has_no_readers(&bootstrap_write);

        let sealed = File::open("/bin/true").unwrap();
        let (bootstrap_read, bootstrap_write) = test_wallet_bootstrap_pipe();
        let invalid_path = PathBuf::from(OsString::from_vec(
            b"/tmp/wallet-bootstrap\0invalid.sqlite3".to_vec(),
        ));
        assert_eq!(
            spawn_sealed_linux_executable(sealed, &invalid_path, bootstrap_read)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_pipe_has_no_readers(&bootstrap_write);
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_session_capability_ceiling_is_closed_and_requires_wallet_reads() {
        let admitted = SERVICE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect::<BTreeSet<_>>();
        let ceiling = wallet_read_session_capability_ceiling(&admitted).unwrap();
        assert_eq!(
            ceiling,
            WALLET_READ_SESSION_ALLOWED_CAPABILITIES
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(!ceiling.contains(&NegotiatedWalletServiceCapability::ValueMovement));
        assert!(!ceiling.contains(&NegotiatedWalletServiceCapability::BrowserIntegration));

        let without_wallet_reads = REQUIRED_BASE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            wallet_read_session_capability_ceiling(&without_wallet_reads)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manifest_ceiling_rejects_coarse_wallet_operations_without_hns_read_v1() {
        let mut admitted = REQUIRED_BASE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect::<BTreeSet<_>>();
        admitted.insert(NegotiatedWalletServiceCapability::WalletOperations);
        assert_eq!(
            wallet_read_session_capability_ceiling(&admitted)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manifest_ceiling_rejects_hns_read_v1_without_coarse_wallet_operations() {
        let mut admitted = REQUIRED_BASE_CAPABILITIES
            .iter()
            .map(|capability| {
                NegotiatedWalletServiceCapability::from_wire_name(capability).unwrap()
            })
            .collect::<BTreeSet<_>>();
        admitted.insert(NegotiatedWalletServiceCapability::HnsReadOperationsV1);
        assert_eq!(
            wallet_read_session_capability_ceiling(&admitted)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn admitted_launch_capability_and_negotiation_composition_fails_closed() {
        let root = test_root("read-composition");
        let wallet_root = test_root("read-composition-wallet");
        let signer = test_signer();
        let artifact_bytes = fs::read("/bin/echo").unwrap();
        let mut manifest = fixture_manifest(&artifact_bytes, 1, None);
        manifest.target.capabilities = SERVICE_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect();
        sign_manifest(&mut manifest, &signer);
        let manifest_bytes = jcs_bytes(&manifest).unwrap();
        let release = InstalledRelease {
            manifest,
            manifest_bytes,
            artifact_bytes,
        };
        install_raw_release(&root, &release, true);
        let mut discovery = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let (_, database) = install_test_wallet_database(&wallet_root);
        let (mut bootstrap_source, _bootstrap_write) = test_wallet_bootstrap_source(1, database);
        let mut lifecycle = WalletReadSessionLifecycle::new();

        let error = lifecycle
            .start(
                &mut discovery,
                &mut bootstrap_source,
                NetworkKind::Regtest,
                Duration::from_secs(1),
            )
            .unwrap_err();
        // The intentionally incompatible /bin/echo fixture may either exit
        // before the hello write or return its non-ABI argv bytes first.
        // Both outcomes must fail closed and consume the generation.
        assert!(matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::InvalidData
        ));
        assert!(lifecycle.active.is_none());
        assert_eq!(lifecycle.next_restart_generation, 2);
        assert_eq!(bootstrap_source.claimed_generations, [1]);
        assert!(!lifecycle.provider_available());
        assert!(!lifecycle.value_available());
        cleanup(&root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_fixture_completes_the_exact_hns_read_session_and_fails_closed() {
        let root = test_root("positive-read-composition");
        let wallet_root = test_root("positive-read-composition-wallet");
        let fixture_root = test_root("positive-read-composition-fixture");
        let signer = test_signer();
        let artifact_bytes = compile_linux_wallet_read_fixture(&fixture_root);
        let mut manifest = fixture_manifest(&artifact_bytes, 1, None);
        manifest.target.capabilities = POSITIVE_WALLET_READ_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect();
        sign_manifest(&mut manifest, &signer);
        let manifest_bytes = jcs_bytes(&manifest).unwrap();
        let release = InstalledRelease {
            manifest,
            manifest_bytes,
            artifact_bytes,
        };
        install_raw_release(&root, &release, true);
        let mut discovery = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(discovery.status_json()["artifactState"], "launchAdmitted");

        let (database_path, first_database) = install_test_wallet_database(&wallet_root);
        let (mut first_source, mut first_bootstrap_write) =
            test_wallet_bootstrap_source(1, first_database);
        first_bootstrap_write
            .write_all(&positive_wallet_read_bootstrap(1))
            .unwrap();
        drop(first_bootstrap_write);

        let mut lifecycle = WalletReadSessionLifecycle::new();
        let first_generation = lifecycle
            .start(
                &mut discovery,
                &mut first_source,
                NetworkKind::Regtest,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(first_generation, 1);
        assert_eq!(first_source.claimed_generations, [first_generation]);
        let first_process_id = active_wallet_child_pid(&lifecycle);
        assert!(lifecycle.authority_context_available_with_release_qualification(true));
        assert!(!lifecycle.authority_context_available());

        let view = lifecycle.read_all(first_generation).unwrap();
        assert!(!view.status.locked);
        assert_eq!(view.status.active_wallet, Some([7_u8; 16]));
        assert_eq!(
            view.status.enabled_modules(),
            &[WalletReadOnlyModule::Handshake]
        );
        assert!(!view.status.mainnet_settlement_enabled);
        assert_eq!(view.account.account_id, [9_u8; 16]);
        assert_eq!(view.account.module, WalletReadOnlyModule::Handshake);
        assert_eq!(view.account.label, "Fixture HNS");
        assert_eq!(view.balance.asset, WalletReadOnlyAsset::Hns);
        assert_eq!(view.balance.base_units.get(), 42);
        assert_eq!(view.receive_target.account, [9_u8; 16]);
        assert_eq!(view.receive_target.display, "rs1qsealedfixture");
        assert_eq!(view.receive_target.derivation_index, 3);
        assert!(view.transactions.is_empty());
        assert_eq!(view.module_status.phase, WalletReadOnlySyncPhase::Ready);
        assert_eq!(view.module_status.validated_height, 144);
        assert_eq!(view.module_status.scanned_height, 144);
        assert_eq!(view.module_status.target_height, Some(144));
        let exact_revision = lifecycle
            .use_current_hns_authority(first_generation, |authority| {
                assert_eq!(authority.network, NetworkKind::Regtest);
                assert_eq!(authority.network_magic, 2_922_943_951);
                assert_eq!(authority.namespace_id, TEST_WALLET_NAMESPACE_ID);
                assert_eq!(authority.namespace_lease_generation, 1);
                assert_ne!(authority.database_device, 0);
                assert_ne!(authority.database_inode, 0);
                assert_eq!(authority.restart_generation, first_generation);
                assert_eq!(authority.active_wallet, [7_u8; 16]);
                assert_eq!(authority.account, [9_u8; 16]);
                assert_eq!(authority.wallet_authority_revision, 9_007_199_254_740_993);
                assert_eq!(authority.account_authority_revision, 9_007_199_254_740_995);
                let debug = format!("{authority:?}");
                assert!(!debug.contains(&authority.host_session_id));
                assert!(!debug.contains(&authority.service_session_id));
                assert!(!debug.contains("9007199254740993"));
                Ok(authority.wallet_authority_revision)
            })
            .unwrap();
        assert_eq!(exact_revision, 9_007_199_254_740_993);
        assert!(!lifecycle.authority_context_available());
        assert!(!lifecycle.provider_available());
        assert!(!lifecycle.value_available());

        let second_database = TrustedWalletDatabaseConfiguration::open(&database_path).unwrap();
        let (mut second_source, mut second_bootstrap_write) =
            test_wallet_bootstrap_source(2, second_database);
        second_bootstrap_write
            .write_all(&positive_wallet_read_bootstrap(2))
            .unwrap();
        drop(second_bootstrap_write);
        let second_generation = lifecycle
            .start(
                &mut discovery,
                &mut second_source,
                NetworkKind::Regtest,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(second_generation, 2);
        assert_eq!(second_source.claimed_generations, [second_generation]);
        let second_process_id = active_wallet_child_pid(&lifecycle);
        assert_ne!(first_process_id, second_process_id);
        assert_wallet_child_killed_and_reaped(first_process_id);

        assert_eq!(
            lifecycle.read_status(first_generation).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!lifecycle.invalidate(first_generation));
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(second_process_id, 0) }, 0);

        let detached_database = wallet_root.join("wallet.sqlite3.detached");
        fs::rename(&database_path, &detached_database).unwrap();
        fs::write(&database_path, b"replacement wallet database fixture").unwrap();
        set_mode(&database_path, 0o600);
        assert_eq!(
            lifecycle.read_status(second_generation).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(lifecycle.active.is_none());
        assert_wallet_child_killed_and_reaped(second_process_id);
        assert_eq!(
            lifecycle.read_status(second_generation).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(!lifecycle.provider_available());
        assert!(!lifecycle.value_available());

        cleanup(&root);
        cleanup(&wallet_root);
        cleanup(&fixture_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_context_mismatch_and_final_revision_change_kill_and_reap() {
        let root = test_root("authority-context-negative");
        let fixture_root = test_root("authority-context-negative-fixture");
        let signer = test_signer();
        let artifact_bytes = compile_linux_wallet_read_fixture(&fixture_root);
        let mut manifest = fixture_manifest(&artifact_bytes, 1, None);
        manifest.target.capabilities = POSITIVE_WALLET_READ_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect();
        sign_manifest(&mut manifest, &signer);
        let manifest_bytes = jcs_bytes(&manifest).unwrap();
        let release = InstalledRelease {
            manifest,
            manifest_bytes,
            artifact_bytes,
        };
        install_raw_release(&root, &release, true);
        let mut discovery = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );

        for (namespace_byte, callback_expected) in [(7_u8, false), (8_u8, true)] {
            let wallet_root = test_root(&format!("authority-context-negative-{namespace_byte}"));
            let (_, database) = install_test_wallet_database(&wallet_root);
            let namespace_id = [namespace_byte; 16];
            let namespace_lease_generation = 9_007_199_254_740_997_u64 + u64::from(namespace_byte);
            let (mut source, mut bootstrap_write) = test_wallet_bootstrap_source_with_authority(
                1,
                database,
                namespace_id,
                namespace_lease_generation,
                Box::new(AlwaysCurrentWalletNamespaceGuard),
            );
            bootstrap_write
                .write_all(&wallet_read_bootstrap(
                    namespace_id,
                    namespace_lease_generation,
                ))
                .unwrap();
            drop(bootstrap_write);
            let mut lifecycle = WalletReadSessionLifecycle::new();
            let generation = lifecycle
                .start(
                    &mut discovery,
                    &mut source,
                    NetworkKind::Regtest,
                    Duration::from_secs(2),
                )
                .unwrap();
            lifecycle.read_all(generation).unwrap();
            let process_id = active_wallet_child_pid(&lifecycle);
            let mut callback_used = false;
            let error = lifecycle
                .use_current_hns_authority(generation, |authority| {
                    callback_used = true;
                    assert_eq!(
                        authority.namespace_lease_generation,
                        namespace_lease_generation
                    );
                    assert_eq!(authority.namespace_id, namespace_id);
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(callback_used, callback_expected);
            assert!(lifecycle.active.is_none());
            assert_wallet_child_killed_and_reaped(process_id);
            assert!(!lifecycle.authority_context_available());
            assert!(!lifecycle.provider_available());
            assert!(!lifecycle.value_available());
            cleanup(&wallet_root);
        }

        let wallet_root = test_root("authority-context-consumer-panic");
        let (_, database) = install_test_wallet_database(&wallet_root);
        let namespace_id = [10_u8; 16];
        let namespace_lease_generation = 9_007_199_254_741_111_u64;
        let (mut source, mut bootstrap_write) = test_wallet_bootstrap_source_with_authority(
            1,
            database,
            namespace_id,
            namespace_lease_generation,
            Box::new(AlwaysCurrentWalletNamespaceGuard),
        );
        bootstrap_write
            .write_all(&wallet_read_bootstrap(
                namespace_id,
                namespace_lease_generation,
            ))
            .unwrap();
        drop(bootstrap_write);
        let mut lifecycle = WalletReadSessionLifecycle::new();
        let generation = lifecycle
            .start(
                &mut discovery,
                &mut source,
                NetworkKind::Regtest,
                Duration::from_secs(2),
            )
            .unwrap();
        lifecycle.read_all(generation).unwrap();
        let process_id = active_wallet_child_pid(&lifecycle);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: io::Result<()> = lifecycle.use_current_hns_authority(generation, |_authority| {
                panic!("fixture authority consumer panic")
            });
        }));
        assert!(panic.is_err());
        assert!(lifecycle.active.is_none());
        assert_wallet_child_killed_and_reaped(process_id);
        assert_eq!(
            lifecycle.read_status(generation).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        cleanup(&wallet_root);

        cleanup(&root);
        cleanup(&fixture_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_wallet_database_rejects_aliases_permissions_and_replacement() {
        use std::os::unix::fs::symlink;

        let root = test_root("trusted-database");
        let (database_path, configuration) = install_test_wallet_database(&root);
        configuration.revalidate().unwrap();

        assert_eq!(
            TrustedWalletDatabaseConfiguration::open(Path::new("wallet.sqlite3"))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let alias = root.join("wallet-alias.sqlite3");
        symlink(&database_path, &alias).unwrap();
        assert!(TrustedWalletDatabaseConfiguration::open(&alias).is_err());
        fs::remove_file(&alias).unwrap();

        let hard_link = root.join("wallet-hard-link.sqlite3");
        fs::hard_link(&database_path, &hard_link).unwrap();
        assert_eq!(
            TrustedWalletDatabaseConfiguration::open(&database_path)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            configuration.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(&hard_link).unwrap();
        configuration.revalidate().unwrap();

        set_mode(&database_path, 0o640);
        assert_eq!(
            TrustedWalletDatabaseConfiguration::open(&database_path)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        set_mode(&database_path, 0o600);

        let detached = root.join("wallet.sqlite3.detached");
        fs::rename(&database_path, &detached).unwrap();
        fs::write(&database_path, b"replacement wallet database").unwrap();
        set_mode(&database_path, 0o600);
        assert_eq!(
            configuration.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_wallet_database_rejects_parent_directory_replacement() {
        let root = test_root("trusted-database-parent");
        let detached = root.with_extension("detached");
        let (_, configuration) = install_test_wallet_database(&root);
        fs::rename(&root, &detached).unwrap();
        let _ = install_test_wallet_database(&root);
        assert_eq!(
            configuration.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        cleanup(&root);
        cleanup(&detached);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_session_rejects_a_replace_restore_launch_race() {
        let root = test_root("wallet-read-replace-restore");
        let (database_path, database) = install_test_wallet_database(&root);
        let detached = root.join("wallet.sqlite3.detached");
        fs::rename(&database_path, &detached).unwrap();
        fs::write(&database_path, b"replacement wallet database").unwrap();
        set_mode(&database_path, 0o600);
        let replacement = File::open(&database_path).unwrap();
        let child = spawn_test_wallet_child_with_database(&replacement);
        let process_id = child.id() as libc::pid_t;
        fs::remove_file(&database_path).unwrap();
        fs::rename(&detached, &database_path).unwrap();
        database.revalidate().unwrap();

        let controller = test_spawned_wallet_controller(child, 12, Duration::from_secs(1));
        let error = AdmittedWalletReadSession::new(
            controller,
            database,
            test_wallet_namespace_lease(NetworkKind::Regtest, 12),
            12,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        drop(replacement);
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_session_rejects_a_child_without_the_admitted_database_descriptor() {
        let root = test_root("wallet-read-missing-database-fd");
        let (_, database) = install_test_wallet_database(&root);
        let child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let process_id = child.id() as libc::pid_t;
        let controller = test_spawned_wallet_controller(child, 12, Duration::from_secs(1));

        let error = AdmittedWalletReadSession::new(
            controller,
            database,
            test_wallet_namespace_lease(NetworkKind::Regtest, 12),
            12,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_generation_cannot_read_or_invalidate_a_newer_wallet_session() {
        let root = test_root("wallet-read-generation");
        let (_, database) = install_test_wallet_database(&root);
        let child = spawn_test_wallet_child_with_database(&database.database_file);
        let process_id = child.id() as libc::pid_t;
        let controller = test_spawned_wallet_controller(child, 12, Duration::from_secs(1));
        let session = AdmittedWalletReadSession::new(
            controller,
            database,
            test_wallet_namespace_lease(NetworkKind::Regtest, 12),
            12,
        )
        .unwrap();
        let mut lifecycle = WalletReadSessionLifecycle {
            next_restart_generation: 13,
            active: Some(session),
        };

        assert!(!lifecycle.authority_context_available_with_release_qualification(true));
        assert!(!lifecycle.authority_context_available());
        assert_eq!(
            lifecycle.read_status(11).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!lifecycle.invalidate(11));
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, 0);
        assert!(!lifecycle.provider_available());
        assert!(!lifecycle.value_available());

        assert!(lifecycle.invalidate(12));
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        assert_eq!(
            lifecycle.read_status(12).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn poisoned_read_session_is_killed_reaped_and_removed_from_the_lifecycle() {
        let root = test_root("wallet-read-poisoned-lifecycle");
        let (_, database) = install_test_wallet_database(&root);
        let child = spawn_test_wallet_child_with_database(&database.database_file);
        let process_id = child.id() as libc::pid_t;
        let controller = test_spawned_wallet_controller(child, 12, Duration::from_millis(20));
        let session = AdmittedWalletReadSession::new(
            controller,
            database,
            test_wallet_namespace_lease(NetworkKind::Regtest, 12),
            12,
        )
        .unwrap();
        let mut lifecycle = WalletReadSessionLifecycle {
            next_restart_generation: 13,
            active: Some(session),
        };

        assert_eq!(
            lifecycle.read_status(12).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(lifecycle.active.is_none());
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        assert_eq!(
            lifecycle.read_status(12).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        cleanup(&root);
    }

    #[test]
    fn jcs_literal_fixes_lexicographic_key_order_and_json_escaping() {
        let value = json!({
            "z": "line\nquote\"slash\\",
            "control": "\u{000f}",
            "a": [true, null, 7]
        });
        assert_eq!(
            jcs_value_bytes(&value).unwrap(),
            br#"{"a":[true,null,7],"control":"\u000f","z":"line\nquote\"slash\\"}"#
        );
    }

    #[test]
    fn signature_base64url_accepts_only_the_four_canonical_final_characters() {
        for suffix in ['A', 'Q', 'g', 'w'] {
            let value = format!("{}{suffix}", "A".repeat(85));
            assert!(valid_base64url_signature(&value));
        }

        let noncanonical = format!("{}B", "A".repeat(85));
        let permissive = base64::engine::GeneralPurpose::new(
            &base64::alphabet::URL_SAFE,
            base64::engine::GeneralPurposeConfig::new()
                .with_encode_padding(false)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
                .with_decode_allow_trailing_bits(true),
        );
        assert_eq!(permissive.decode(&noncanonical).unwrap().len(), 64);
        assert!(!valid_base64url_signature(&noncanonical));
    }

    #[test]
    fn artifact_manifest_fixture_requires_approval_schema_v3() {
        let mut manifest = fixture_manifest(b"wallet-service-fixture", 1, None);
        assert_eq!(manifest.target.approval_schema_version, 3);
        assert!(valid_manifest_contract(
            &manifest,
            current_unix_ms().unwrap()
        ));

        manifest.target.approval_schema_version = 2;
        assert!(!valid_manifest_contract(
            &manifest,
            current_unix_ms().unwrap()
        ));
    }

    #[test]
    fn noncanonical_complete_manifest_bytes_fail_before_trust_lookup() {
        let root = test_root("noncanonical");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let manifest_path = artifact_directory(&root).join(WALLET_ARTIFACT_MANIFEST);
        make_writable(&manifest_path);
        let mut noncanonical = release.manifest_bytes.clone();
        noncanonical.push(b'\n');
        fs::write(&manifest_path, noncanonical).unwrap();
        make_read_only(&manifest_path);

        let discovery = WalletAbiDiscovery::discover(&root);
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactManifestNotCanonical"
        );
        cleanup(&root);
    }

    #[test]
    fn trusted_key_mismatch_rejects_signature_instead_of_falling_back_to_hash() {
        let root = test_root("wrong-trust-root");
        let signer = test_signer();
        let wrong_signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let configuration = verifier_configuration(&wrong_signer, &release, 1, true, true);
        let discovery = WalletAbiDiscovery::discover_with_configuration(&root, configuration);
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactSignatureInvalid"
        );
        cleanup(&root);
    }

    #[test]
    fn known_signer_with_tampered_signature_fails_closed() {
        let root = test_root("signature-tamper");
        let signer = test_signer();
        let mut release = install_signed_release(&root, &signer, 1, None, true, None);
        let configuration = verifier_configuration(&signer, &release, 1, true, true);
        let mut signature = URL_SAFE_NO_PAD
            .decode(release.manifest.signature.value.as_bytes())
            .unwrap();
        signature[0] ^= 1;
        release.manifest.signature.value = URL_SAFE_NO_PAD.encode(signature);
        rewrite_manifest(&root, &release.manifest);

        let discovery = WalletAbiDiscovery::discover_with_configuration(&root, configuration);
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactSignatureInvalid"
        );
        cleanup(&root);
    }

    #[test]
    fn trusted_signature_without_exact_release_pin_stays_unavailable() {
        let root = test_root("unqualified");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let discovery = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, false),
        );
        assert_eq!(
            discovery.status_json()["artifactState"],
            "authenticityVerified"
        );
        assert_eq!(
            discovery.status_json()["artifactAuthenticityVerified"],
            true
        );
        assert_eq!(discovery.status_json()["artifactReleaseQualified"], false);
        assert_eq!(discovery.status_json()["available"], false);
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_and_pinned_owner_writable_files_are_never_launch_admitted() {
        let root = test_root("mutable");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, false, None);
        let configuration = verifier_configuration(&signer, &release, 1, true, true);
        let discovery = WalletAbiDiscovery::discover_with_configuration(&root, configuration);
        assert_eq!(discovery.unavailable_code(), "walletArtifactMutable");
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_and_pinned_relocatable_elf_is_not_launch_admitted() {
        let root = test_root("elf-relocatable");
        let signer = test_signer();
        let mut artifact = native_fixture_bytes();
        artifact[16..18].copy_from_slice(&1_u16.to_le_bytes());
        let release = install_signed_release(&root, &signer, 1, None, true, Some(artifact));
        let discovery = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(
            discovery.unavailable_code(),
            "walletArtifactPlatformMismatch"
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_release_admission_survives_restart_and_keeps_provider_gates_false() {
        let root = test_root("restart");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let first = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(first.status_json()["artifactState"], "launchAdmitted");
        assert_eq!(first.status_json()["artifactLaunchAdmitted"], true);
        assert_eq!(first.status_json()["serviceTransportAvailable"], false);
        assert_eq!(first.status_json()["available"], false);
        drop(first);

        let restarted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(restarted.status_json()["artifactState"], "launchAdmitted");
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_high_water_rejects_downgrade_after_artifact_directory_replacement() {
        let root = test_root("directory-replacement-downgrade");
        let signer = test_signer();
        let first = install_signed_release(&root, &signer, 1, None, true, None);
        let admitted_first = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &first, 1, true, true),
        );
        assert_eq!(
            admitted_first.status_json()["artifactState"],
            "launchAdmitted"
        );
        drop(admitted_first);

        let first_manifest_sha256 = sha256_bytes(&first.manifest_bytes);
        let second =
            install_signed_release(&root, &signer, 2, Some(first_manifest_sha256), true, None);
        let admitted_second = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &second, 1, false, true),
        );
        assert_eq!(
            admitted_second.status_json()["artifactState"],
            "launchAdmitted"
        );
        drop(admitted_second);

        let replaced = root.join("wallet-abi-v2.replaced");
        fs::rename(artifact_directory(&root), &replaced).unwrap();
        install_raw_release(&root, &first, true);
        let downgraded = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &first, 1, true, true),
        );
        assert_eq!(
            downgraded.unavailable_code(),
            "walletArtifactRollbackRejected"
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn anti_rollback_state_tamper_fails_closed_on_restart() {
        let root = test_root("state-tamper");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");
        drop(admitted);

        let state_path = root.join(WALLET_ANTI_ROLLBACK_STATE);
        make_writable(&state_path);
        fs::write(&state_path, b"{}").unwrap();
        make_read_only(&state_path);
        let restarted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(
            restarted.unavailable_code(),
            "walletArtifactRollbackRejected"
        );
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_sequences_serialize_without_regressing_the_high_water() {
        let root = test_root("concurrent-sequences");
        let signer = test_signer();
        let first = install_signed_release(&root, &signer, 1, None, true, None);
        let admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &first, 1, true, true),
        );
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");
        drop(admitted);

        let predecessor = sha256_bytes(&first.manifest_bytes);
        let mut second = fixture_manifest(&first.artifact_bytes, 2, Some(predecessor.clone()));
        sign_manifest(&mut second, &signer);
        let second_sha256 = sha256_bytes(&jcs_bytes(&second).unwrap());
        let mut third = fixture_manifest(&first.artifact_bytes, 3, Some(predecessor));
        sign_manifest(&mut third, &signer);
        let third_sha256 = sha256_bytes(&jcs_bytes(&third).unwrap());

        let barrier = Arc::new(Barrier::new(3));
        let second_root = root.clone();
        let second_barrier = Arc::clone(&barrier);
        let second_commit = std::thread::spawn(move || {
            let data_directory = open_directory_nofollow(&second_root).unwrap();
            second_barrier.wait();
            commit_anti_rollback(&data_directory, &second, &second_sha256, false).is_ok()
        });
        let third_root = root.clone();
        let third_barrier = Arc::clone(&barrier);
        let third_commit = std::thread::spawn(move || {
            let data_directory = open_directory_nofollow(&third_root).unwrap();
            third_barrier.wait();
            commit_anti_rollback(&data_directory, &third, &third_sha256, false).is_ok()
        });
        barrier.wait();
        let second_committed = second_commit.join().unwrap();
        let third_committed = third_commit.join().unwrap();
        assert_eq!(
            [second_committed, third_committed]
                .into_iter()
                .filter(|committed| *committed)
                .count(),
            1
        );

        let data_directory = open_directory_nofollow(&root).unwrap();
        let lock = acquire_anti_rollback_lock(&data_directory).unwrap();
        let state = read_anti_rollback_state_locked(&data_directory, &lock)
            .unwrap()
            .unwrap();
        let entry = state
            .entries
            .iter()
            .find(|entry| entry.release_line == TEST_RELEASE_LINE)
            .unwrap();
        assert_eq!(entry.highest_sequence, if second_committed { 2 } else { 3 });
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cached_admission_rechecks_expiry_and_clock_rollback_before_launch() {
        let root = test_root("cached-time-window");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let expiry = release.manifest.anti_rollback.expires_at_unix_ms.unwrap();
        let before_publication = release.manifest.release.published_at_unix_ms - 1;
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let artifact = match &mut admitted.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact,
            state => panic!("expected launch admission, got {state:?}"),
        };
        let lock = acquire_anti_rollback_lock(&artifact.data_directory).unwrap();
        assert!(matches!(
            artifact.revalidate_for_launch_while_locked_at(expiry, &lock),
            Err(WalletArtifactRejection::ReleaseTimeWindow)
        ));
        assert!(matches!(
            artifact.revalidate_for_launch_while_locked_at(before_publication, &lock),
            Err(WalletArtifactRejection::ReleaseTimeWindow)
        ));
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_parent_binding_rejects_replaced_artifact_directory_at_launch() {
        let root = test_root("launch-path-binding");
        let wallet_root = test_root("launch-path-binding-wallet");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let (_, database) = install_test_wallet_database(&wallet_root);
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");

        let replaced = root.join("wallet-abi-v2.detached");
        fs::rename(artifact_directory(&root), &replaced).unwrap();
        install_raw_release(&root, &release, true);
        let artifact = match &mut admitted.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact,
            state => panic!("expected launch admission, got {state:?}"),
        };
        let (bootstrap_read, _bootstrap_write) = test_wallet_bootstrap_pipe();
        let error = artifact
            .launch_for_database(&database, bootstrap_read)
            .unwrap_err();
        assert_eq!(error.to_string(), "walletArtifactPathBindingChanged");
        cleanup(&root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_stable_root_binding_rejects_replaced_data_directory_at_launch() {
        let root = test_root("stable-root-path-binding");
        let wallet_root = test_root("stable-root-path-binding-wallet");
        let detached_root = root.with_extension("detached");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let (_, database) = install_test_wallet_database(&wallet_root);
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");

        fs::rename(&root, &detached_root).unwrap();
        install_raw_release(&root, &release, true);
        let artifact = match &mut admitted.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact,
            state => panic!("expected launch admission, got {state:?}"),
        };
        let (bootstrap_read, _bootstrap_write) = test_wallet_bootstrap_pipe();
        let error = artifact
            .launch_for_database(&database, bootstrap_read)
            .unwrap_err();
        assert_eq!(error.to_string(), "walletArtifactPathBindingChanged");
        cleanup(&root);
        cleanup(&detached_root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn first_admission_immediately_launches_only_from_a_sealed_copy() {
        let root = test_root("sealed-launch");
        let wallet_root = test_root("sealed-launch-wallet");
        let signer = test_signer();
        let artifact_bytes = fs::read("/bin/true").unwrap();
        let release = install_signed_release(&root, &signer, 1, None, true, Some(artifact_bytes));
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let (_, database) = install_test_wallet_database(&wallet_root);
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");
        assert!(root.join(WALLET_ANTI_ROLLBACK_STATE).is_file());
        let artifact = match &mut admitted.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact,
            state => panic!("expected launch admission, got {state:?}"),
        };
        let (bootstrap_read, _bootstrap_write) = test_wallet_bootstrap_pipe();
        let mut child = artifact
            .launch_for_database(&database, bootstrap_read)
            .unwrap();
        assert!(child.wait().unwrap().success());
        cleanup(&root);
        cleanup(&wallet_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn admitted_launcher_passes_only_the_exact_trusted_database_arguments() {
        let root = test_root("sealed-database-argv");
        let wallet_root = test_root("sealed-database-argv-wallet");
        let signer = test_signer();
        let artifact_bytes = fs::read("/bin/echo").unwrap();
        let release = install_signed_release(&root, &signer, 1, None, true, Some(artifact_bytes));
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        let (database_path, database) = install_test_wallet_database(&wallet_root);
        let artifact = match &mut admitted.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact,
            state => panic!("expected launch admission, got {state:?}"),
        };
        let (bootstrap_read, _bootstrap_write) = test_wallet_bootstrap_pipe();

        let output = artifact
            .launch_for_database(&database, bootstrap_read)
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("--database {}\n", database_path.display())
        );
        assert!(output.stderr.is_empty());
        cleanup(&root);
        cleanup(&wallet_root);
    }

    fn test_signer() -> Ed25519KeyPair {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn install_signed_release(
        root: &Path,
        signer: &Ed25519KeyPair,
        sequence: u64,
        previous_manifest_sha256: Option<String>,
        immutable: bool,
        artifact_override: Option<Vec<u8>>,
    ) -> InstalledRelease {
        let artifact_bytes = artifact_override.unwrap_or_else(native_fixture_bytes);
        let mut manifest = fixture_manifest(&artifact_bytes, sequence, previous_manifest_sha256);
        sign_manifest(&mut manifest, signer);
        let manifest_bytes = jcs_bytes(&manifest).unwrap();
        let release = InstalledRelease {
            manifest,
            manifest_bytes,
            artifact_bytes,
        };
        install_raw_release(root, &release, immutable);
        release
    }

    fn install_raw_release(root: &Path, release: &InstalledRelease, immutable: bool) {
        let directory = create_private_artifact_directory(root);
        let artifact_path = directory.join(TEST_ARTIFACT_NAME);
        if artifact_path.exists() {
            make_writable(&artifact_path);
        }
        fs::write(&artifact_path, &release.artifact_bytes).unwrap();
        set_mode(&artifact_path, if immutable { 0o500 } else { 0o700 });

        let manifest_path = directory.join(WALLET_ARTIFACT_MANIFEST);
        if manifest_path.exists() {
            make_writable(&manifest_path);
        }
        fs::write(&manifest_path, &release.manifest_bytes).unwrap();
        set_mode(&manifest_path, if immutable { 0o400 } else { 0o600 });
    }

    fn create_private_artifact_directory(root: &Path) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        set_mode(root, 0o700);
        let directory = artifact_directory(root);
        fs::create_dir_all(&directory).unwrap();
        set_mode(&directory, 0o700);
        directory
    }

    fn rewrite_manifest(root: &Path, manifest: &WalletArtifactManifest) {
        let manifest_path = artifact_directory(root).join(WALLET_ARTIFACT_MANIFEST);
        make_writable(&manifest_path);
        fs::write(&manifest_path, jcs_bytes(manifest).unwrap()).unwrap();
        make_read_only(&manifest_path);
    }

    fn fixture_manifest(
        artifact_bytes: &[u8],
        sequence: u64,
        previous_manifest_sha256: Option<String>,
    ) -> WalletArtifactManifest {
        let now = current_unix_ms().unwrap();
        let (target_triple, executable_format) = current_target_contract().unwrap();
        WalletArtifactManifest {
            manifest_schema_version: WALLET_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            target: WalletArtifactTarget {
                artifact_kind: "walletService".to_owned(),
                target_triple: target_triple.to_owned(),
                executable_format: executable_format.to_owned(),
                wallet_abi_version: WALLET_ABI_VERSION,
                service_protocol_version: WALLET_SERVICE_PROTOCOL_VERSION,
                provider_schema_version: WALLET_PROVIDER_SCHEMA_VERSION,
                approval_schema_version: WALLET_APPROVAL_SCHEMA_VERSION,
                maximum_frame_bytes: WALLET_ABI_MAX_FRAME_BYTES,
                capabilities: REQUIRED_BASE_CAPABILITIES
                    .iter()
                    .map(|capability| (*capability).to_owned())
                    .collect(),
            },
            source: WalletArtifactSource {
                repository: WALLET_SOURCE_REPOSITORY.to_owned(),
                commit_id: "11".repeat(20),
                tree_id: "22".repeat(20),
                source_archive_sha256: "33".repeat(32),
                dirty: false,
            },
            release: WalletArtifactRelease {
                release_id: format!("wallet-service-0.1.{sequence}"),
                version: format!("0.1.{sequence}"),
                artifact: TEST_ARTIFACT_NAME.to_owned(),
                artifact_sha256: sha256_bytes(artifact_bytes),
                artifact_size_bytes: artifact_bytes.len() as u64,
                published_at_unix_ms: now.saturating_sub(2_000).max(1),
            },
            anti_rollback: WalletArtifactAntiRollback {
                release_line: TEST_RELEASE_LINE.to_owned(),
                sequence,
                previous_manifest_sha256,
                not_before_unix_ms: now.saturating_sub(1_000).max(1),
                expires_at_unix_ms: Some(now + 600_000),
            },
            signature: WalletArtifactSignature {
                algorithm: SIGNATURE_ALGORITHM.to_owned(),
                key_id: TEST_KEY_ID.to_owned(),
                payload_canonicalization: SIGNATURE_CANONICALIZATION.to_owned(),
                signed_payload_sha256: "00".repeat(32),
                value: URL_SAFE_NO_PAD.encode([0_u8; 64]),
            },
        }
    }

    fn sign_manifest(manifest: &mut WalletArtifactManifest, signer: &Ed25519KeyPair) {
        let payload = signed_manifest_payload(manifest).unwrap();
        manifest.signature.signed_payload_sha256 = sha256_bytes(&payload);
        let payload = signed_manifest_payload(manifest).unwrap();
        manifest.signature.value = URL_SAFE_NO_PAD.encode(signer.sign(&payload).as_ref());
    }

    fn verifier_configuration(
        signer: &Ed25519KeyPair,
        release: &InstalledRelease,
        minimum_sequence: u64,
        trusted_genesis: bool,
        qualified: bool,
    ) -> WalletAbiVerifierConfiguration {
        WalletAbiVerifierConfiguration {
            trust_roots: vec![WalletTrustRoot {
                key_id: TEST_KEY_ID.to_owned(),
                release_line: TEST_RELEASE_LINE.to_owned(),
                public_key: signer.public_key().as_ref().to_vec(),
                first_sequence: 1,
                last_sequence: MAX_SAFE_INTEGER,
            }],
            qualified_releases: qualified
                .then(|| QualifiedWalletRelease {
                    key_id: TEST_KEY_ID.to_owned(),
                    release_line: TEST_RELEASE_LINE.to_owned(),
                    sequence: release.manifest.anti_rollback.sequence,
                    release_id: release.manifest.release.release_id.clone(),
                    target_triple: release.manifest.target.target_triple.clone(),
                    manifest_sha256: sha256_bytes(&release.manifest_bytes),
                    artifact_sha256: release.manifest.release.artifact_sha256.clone(),
                    trusted_genesis,
                })
                .into_iter()
                .collect(),
            release_floors: vec![WalletReleaseFloor {
                release_line: TEST_RELEASE_LINE.to_owned(),
                minimum_sequence,
            }],
        }
    }

    fn native_fixture_bytes() -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
            bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
            bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
            bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
            bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
            bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
            bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            bytes[..4].copy_from_slice(&0xfeedfacf_u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&0x01000007_u32.to_le_bytes());
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            bytes[..4].copy_from_slice(&0xfeedfacf_u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&0x0100000c_u32.to_le_bytes());
        }
        bytes
    }

    #[cfg(target_os = "linux")]
    fn compile_linux_wallet_read_fixture(root: &Path) -> Vec<u8> {
        fs::create_dir_all(root).unwrap();
        set_mode(root, 0o700);
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wallet-read-service.c");
        let executable = root.join("wallet-read-service");
        let output = Command::new("cc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "unable to compile the Linux wallet read fixture\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read(executable).unwrap()
    }

    fn artifact_directory(root: &Path) -> PathBuf {
        root.join(WALLET_ARTIFACT_DIRECTORY)
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hns-wallet-abi-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn make_writable(path: &Path) {
        set_mode(path, 0o600);
    }

    fn make_read_only(path: &Path) {
        set_mode(path, 0o400);
    }

    #[cfg(target_os = "linux")]
    fn install_test_wallet_database(root: &Path) -> (PathBuf, TrustedWalletDatabaseConfiguration) {
        fs::create_dir_all(root).unwrap();
        set_mode(root, 0o700);
        let database_path = root.join("wallet.sqlite3");
        fs::write(&database_path, b"pre-existing wallet database fixture").unwrap();
        set_mode(&database_path, 0o600);
        let configuration = TrustedWalletDatabaseConfiguration::open(&database_path).unwrap();
        (database_path, configuration)
    }

    #[cfg(target_os = "linux")]
    fn spawn_test_wallet_child_with_database(database_file: &File) -> Child {
        use std::os::unix::process::CommandExt;

        let descriptor = database_file.as_raw_fd();
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: the child hook performs only async-signal-safe fcntl calls
        // against a descriptor inherited from the live fixture file.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn test_spawned_wallet_controller(
        mut child: Child,
        restart_generation: u64,
        timeout: Duration,
    ) -> SpawnedWalletServiceController {
        let reader = child.stdout.take().unwrap();
        let writer = child.stdin.take().unwrap();
        set_nonblocking_fd(reader.as_raw_fd()).unwrap();
        set_nonblocking_fd(writer.as_raw_fd()).unwrap();
        WalletServiceController {
            reader,
            writer,
            process: Some(WalletServiceProcess::new(child)),
            timeout,
            host_session_id: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            service_session_id: URL_SAFE_NO_PAD.encode([8_u8; 32]),
            restart_generation,
            next_host_sequence: 1,
            next_service_sequence: 1,
            capabilities: WALLET_READ_SESSION_REQUIRED_CAPABILITIES
                .into_iter()
                .collect(),
            selected_active_wallet: None,
            selected_hns_account: None,
            poisoned: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn active_wallet_child_pid(lifecycle: &WalletReadSessionLifecycle) -> libc::pid_t {
        lifecycle
            .active
            .as_ref()
            .and_then(|session| session.controller.process.as_ref())
            .and_then(|process| process.child.as_ref())
            .map(|child| child.id() as libc::pid_t)
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn assert_wallet_child_killed_and_reaped(process_id: libc::pid_t) {
        // SAFETY: signal zero performs only an existence check for this PID.
        assert_eq!(unsafe { libc::kill(process_id, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        let mut status = 0;
        // SAFETY: process_id was the immediate child owned and synchronously
        // waited by the lifecycle, and status remains live for this call.
        assert_eq!(
            unsafe { libc::waitpid(process_id, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    fn cleanup(root: &Path) {
        let state = root.join(WALLET_ANTI_ROLLBACK_STATE);
        if state.exists() {
            make_writable(&state);
        }
        for directory in [
            artifact_directory(root),
            root.join("wallet-abi-v2.replaced"),
            root.join("wallet-abi-v2.detached"),
        ] {
            for name in [WALLET_ARTIFACT_MANIFEST, TEST_ARTIFACT_NAME] {
                let path = directory.join(name);
                if path.exists() {
                    make_writable(&path);
                }
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
