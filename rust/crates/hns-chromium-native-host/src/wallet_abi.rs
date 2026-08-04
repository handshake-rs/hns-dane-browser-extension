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
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Child;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const WALLET_ABI_VERSION: u16 = 2;
pub(crate) const WALLET_SERVICE_PROTOCOL_VERSION: u16 = 2;
pub(crate) const WALLET_PROVIDER_SCHEMA_VERSION: u16 = 1;
pub(crate) const WALLET_ABI_MAX_FRAME_BYTES: u32 = 1_048_576;
const WALLET_APPROVAL_SCHEMA_VERSION: u16 = 2;
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
const SERVICE_CAPABILITIES: [&str; 10] = [
    "canonicalFraming",
    "restartIsolation",
    "opaqueAuthorityRegistry",
    "persistentPermissions",
    "structuredApprovals",
    "typedEvents",
    "walletOperations",
    "providerDispatch",
    "valueMovement",
    "browserIntegration",
];
#[cfg(unix)]
const SIGNATURE_ALGORITHM: &str = "ed25519";
#[cfg(unix)]
const SIGNATURE_CANONICALIZATION: &str = "JCS-RFC8785";
#[cfg(unix)]
const ANTI_ROLLBACK_CHECKSUM_CONTEXT: &[u8] =
    b"hns-dane-browser-wallet-anti-rollback-state-v1\0";

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
        let (artifact_state, reason, summary) = match &self.state {
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
            WalletArtifactState::IntegrityChecked(_) => {
                "walletArtifactAuthenticityUnavailable"
            }
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

    /// The controller intentionally does not call this until transport,
    /// negotiation, projection, and browser authority are independently
    /// released. When called, only an admitted retained handle can reach the
    /// platform launcher.
    #[cfg(unix)]
    #[allow(dead_code)]
    pub(crate) fn launch_admitted_service(&mut self) -> io::Result<Child> {
        match &mut self.state {
            WalletArtifactState::LaunchAdmitted(artifact) => artifact.launch(),
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
    LaunchAdmitted(LaunchAdmittedWalletArtifact),
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

#[cfg(unix)]
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
    fn launch(&mut self) -> io::Result<Child> {
        let anti_rollback_lock = acquire_anti_rollback_lock(&self.data_directory)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason.code()))?;
        self.revalidate_for_launch_while_locked(&anti_rollback_lock)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason.code()))?;
        #[cfg(target_os = "linux")]
        {
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
            self.revalidate_for_launch_while_locked(&anti_rollback_lock).map_err(|reason| {
                io::Error::new(io::ErrorKind::PermissionDenied, reason.code())
            })?;
            spawn_sealed_linux_executable(sealed)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "reviewed sealed wallet execution is not available on this platform",
            ))
        }
    }

    fn revalidate_for_launch_while_locked(
        &mut self,
        anti_rollback_lock: &WalletAntiRollbackLock,
    ) -> Result<(), WalletArtifactRejection> {
        let initial_unix_ms =
            current_unix_ms().ok_or(WalletArtifactRejection::ReleaseTimeWindow)?;
        self.revalidate_for_launch_while_locked_at(initial_unix_ms, anti_rollback_lock)?;
        let final_unix_ms =
            current_unix_ms().ok_or(WalletArtifactRejection::ReleaseTimeWindow)?;
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
        let manifest_bytes =
            read_manifest(&mut self.manifest_file).map_err(|_| WalletArtifactRejection::PathBinding)?;
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
    let (artifact_sha256, bytes_read) =
        match sha256_reader(&mut artifact_file, MAX_ARTIFACT_BYTES) {
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
    let Some(qualified_release) =
        configuration.qualified_release(&manifest, &manifest_sha256)
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
    WalletArtifactState::LaunchAdmitted(LaunchAdmittedWalletArtifact {
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
            configuration.trust_root(
                &release.key_id,
                &release.release_line,
                release.sequence,
            ).is_some()
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
        SERVICE_CAPABILITIES.contains(&capability.as_str())
            && unique.insert(capability.as_str())
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
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })
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
    let mut state = read_anti_rollback_state_locked(data_directory, &anti_rollback_lock)?.unwrap_or(
        WalletAntiRollbackState {
            state_schema_version: WALLET_ANTI_ROLLBACK_STATE_SCHEMA_VERSION,
            entries: Vec::new(),
            checksum_sha256: String::new(),
        },
    );
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
    state.checksum_sha256 = anti_rollback_checksum(&state)
        .ok_or(WalletArtifactRejection::AntiRollback)?;
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
        rename_at(
            data_directory,
            &temporary_name,
            WALLET_ANTI_ROLLBACK_STATE,
        )?;
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
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
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

#[cfg(unix)]
fn private_regular_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.is_file()
        && metadata.nlink() == 1
        && source_is_owned_and_not_shared_writable(metadata)
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

    let name = CString::new("hns-wallet-service")
        .expect("static sealed executable name contains no NUL");
    // SAFETY: name is a valid C string and a successful descriptor is
    // transferred immediately to File.
    let descriptor = unsafe {
        libc::memfd_create(
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
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
    let seals =
        libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
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
fn spawn_sealed_linux_executable(sealed: File) -> io::Result<Child> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let descriptor = sealed.as_raw_fd();
    let executable = format!("/proc/self/fd/{descriptor}");
    let mut command = Command::new(executable);
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: the child hook performs only async-signal-safe fcntl calls. It
    // clears close-on-exec on the inherited sealed memfd so the proc-fd path is
    // resolvable by exec and the immutable image remains retained afterward.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Barrier};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_KEY_ID: &str = "wallet-release-test";
    const TEST_RELEASE_LINE: &str = "wallet-service-stable";
    const TEST_ARTIFACT_NAME: &str = "hns-wallet-service";

    struct InstalledRelease {
        manifest: WalletArtifactManifest,
        manifest_bytes: Vec<u8>,
        artifact_bytes: Vec<u8>,
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
        assert_eq!(discovery.status_json()["artifactAuthenticityVerified"], false);
        cleanup(&root);
        drop(release);
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
        let configuration =
            verifier_configuration(&wrong_signer, &release, 1, true, true);
        let discovery =
            WalletAbiDiscovery::discover_with_configuration(&root, configuration);
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

        let discovery =
            WalletAbiDiscovery::discover_with_configuration(&root, configuration);
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
        assert_eq!(discovery.status_json()["artifactAuthenticityVerified"], true);
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
        let discovery =
            WalletAbiDiscovery::discover_with_configuration(&root, configuration);
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
        let release =
            install_signed_release(&root, &signer, 1, None, true, Some(artifact));
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
        assert_eq!(admitted_first.status_json()["artifactState"], "launchAdmitted");
        drop(admitted_first);

        let first_manifest_sha256 = sha256_bytes(&first.manifest_bytes);
        let second = install_signed_release(
            &root,
            &signer,
            2,
            Some(first_manifest_sha256),
            true,
            None,
        );
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
        let mut second =
            fixture_manifest(&first.artifact_bytes, 2, Some(predecessor.clone()));
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
            commit_anti_rollback(
                &data_directory,
                &second,
                &second_sha256,
                false,
            )
            .is_ok()
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
        assert_eq!(
            entry.highest_sequence,
            if second_committed { 2 } else { 3 }
        );
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
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");

        let replaced = root.join("wallet-abi-v2.detached");
        fs::rename(artifact_directory(&root), &replaced).unwrap();
        install_raw_release(&root, &release, true);
        let error = admitted.launch_admitted_service().unwrap_err();
        assert_eq!(error.to_string(), "walletArtifactPathBindingChanged");
        cleanup(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_stable_root_binding_rejects_replaced_data_directory_at_launch() {
        let root = test_root("stable-root-path-binding");
        let detached_root = root.with_extension("detached");
        let signer = test_signer();
        let release = install_signed_release(&root, &signer, 1, None, true, None);
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");

        fs::rename(&root, &detached_root).unwrap();
        install_raw_release(&root, &release, true);
        let error = admitted.launch_admitted_service().unwrap_err();
        assert_eq!(error.to_string(), "walletArtifactPathBindingChanged");
        cleanup(&root);
        cleanup(&detached_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn first_admission_immediately_launches_only_from_a_sealed_copy() {
        let root = test_root("sealed-launch");
        let signer = test_signer();
        let artifact_bytes = fs::read("/bin/true").unwrap();
        let release =
            install_signed_release(&root, &signer, 1, None, true, Some(artifact_bytes));
        let mut admitted = WalletAbiDiscovery::discover_with_configuration(
            &root,
            verifier_configuration(&signer, &release, 1, true, true),
        );
        assert_eq!(admitted.status_json()["artifactState"], "launchAdmitted");
        assert!(root.join(WALLET_ANTI_ROLLBACK_STATE).is_file());
        let mut child = admitted.launch_admitted_service().unwrap();
        assert!(child.wait().unwrap().success());
        cleanup(&root);
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
        fs::create_dir_all(artifact_directory(root)).unwrap();
        let artifact_path = artifact_directory(root).join(TEST_ARTIFACT_NAME);
        if artifact_path.exists() {
            make_writable(&artifact_path);
        }
        fs::write(&artifact_path, &artifact_bytes).unwrap();
        set_mode(&artifact_path, if immutable { 0o500 } else { 0o700 });

        let mut manifest = fixture_manifest(
            &artifact_bytes,
            sequence,
            previous_manifest_sha256,
        );
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
        fs::create_dir_all(artifact_directory(root)).unwrap();
        let artifact_path = artifact_directory(root).join(TEST_ARTIFACT_NAME);
        if artifact_path.exists() {
            make_writable(&artifact_path);
        }
        fs::write(&artifact_path, &release.artifact_bytes).unwrap();
        set_mode(&artifact_path, if immutable { 0o500 } else { 0o700 });

        let manifest_path = artifact_directory(root).join(WALLET_ARTIFACT_MANIFEST);
        if manifest_path.exists() {
            make_writable(&manifest_path);
        }
        fs::write(&manifest_path, &release.manifest_bytes).unwrap();
        set_mode(&manifest_path, if immutable { 0o400 } else { 0o600 });
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
