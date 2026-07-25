//! Rust-owned Chromium native-messaging and proxy lifecycle boundary.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::fill as fill_random;
use hns_browser_runtime::{
    BrowserHostClass, BrowserProxy, BrowserRuntime, NetworkKind, ResolutionMode,
    RuntimeConfiguration, RuntimePolicy, chromium_hns_only_pac_script, classify_browser_host,
    diagnostics_json,
};
use hns_loopback_proxy::LocalCertificateAuthority;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const NATIVE_MESSAGING_SCHEMA_VERSION: u32 = 1;
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 256 * 1024;
pub const NATIVE_MESSAGING_HOST_NAME: &str = "com.denuoweb.hns_dane_browser";
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_EXTENSION_ORIGINS: usize = 16;
const HOST_SESSION_RANDOM_BYTES: usize = 16;
const LOCAL_CA_SCHEMA_VERSION: u32 = 1;
const MAX_LOCAL_CA_BUNDLE_BYTES: u64 = 128 * 1024;
const MAX_LOCAL_CA_MARKER_BYTES: u64 = 4 * 1024;
const LOCAL_CA_LOCK_ATTEMPTS: usize = 40;
const LOCAL_CA_LOCK_INTERVAL: Duration = Duration::from_millis(25);
const STALE_LOCAL_CA_LOCK_AGE: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum NativeHostError {
    #[error("native-messaging input ended inside a frame length")]
    TruncatedLength,
    #[error("native-messaging input ended inside a frame")]
    TruncatedMessage,
    #[error("native-messaging frame is empty")]
    EmptyMessage,
    #[error("native-messaging frame exceeds the bounded message size")]
    MessageTooLarge,
    #[error("unable to read native-messaging input")]
    Read(#[source] io::Error),
    #[error("unable to write native-messaging output")]
    Write(#[source] io::Error),
    #[error("unable to serialize a native-messaging response")]
    Serialize(#[source] serde_json::Error),
    #[error("unable to initialize the browser runtime: {0}")]
    Runtime(String),
    #[error("unable to generate a native-host session")]
    SessionGeneration,
    #[error("unable to initialize the per-install local CA: {0}")]
    LocalCa(String),
    #[error("unable to construct the native-messaging host manifest: {0}")]
    Manifest(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPolicy {
    #[serde(default)]
    pub p2p_dns_relay: bool,
    #[serde(default)]
    pub p2p_odoh: P2pOdohMode,
    #[serde(default)]
    pub privacy_downgrade: PrivacyDowngradePolicy,
    #[serde(default)]
    pub hnsr: HnsrMode,
    #[serde(default)]
    pub experimental_wire_profile: ExperimentalWireProfile,
}

impl Default for ExtensionPolicy {
    fn default() -> Self {
        Self {
            p2p_dns_relay: false,
            p2p_odoh: P2pOdohMode::Off,
            privacy_downgrade: PrivacyDowngradePolicy::FailClosed,
            hnsr: HnsrMode::Off,
            experimental_wire_profile: ExperimentalWireProfile::Stable,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum P2pOdohMode {
    #[default]
    Off,
    Preferred,
    Required,
    DirectAllowed,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyDowngradePolicy {
    #[default]
    FailClosed,
    AllowDirect,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HnsrMode {
    #[default]
    Off,
    Client,
    Endpoint,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExperimentalWireProfile {
    #[default]
    Stable,
    HipDrafts,
    DenuoExtension,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeRequest {
    Hello {
        schema_version: u32,
        request_id: String,
    },
    Start {
        schema_version: u32,
        request_id: String,
        #[serde(default)]
        policy: ExtensionPolicy,
    },
    SetPolicy {
        schema_version: u32,
        request_id: String,
        policy: ExtensionPolicy,
    },
    Status {
        schema_version: u32,
        request_id: String,
    },
    SyncOnce {
        schema_version: u32,
        request_id: String,
    },
    Classify {
        schema_version: u32,
        request_id: String,
        host: String,
    },
    Diagnostics {
        schema_version: u32,
        request_id: String,
    },
    Stop {
        schema_version: u32,
        request_id: String,
    },
    Shutdown {
        schema_version: u32,
        request_id: String,
    },
}

impl NativeRequest {
    fn schema_version(&self) -> u32 {
        match self {
            Self::Hello { schema_version, .. }
            | Self::Start { schema_version, .. }
            | Self::SetPolicy { schema_version, .. }
            | Self::Status { schema_version, .. }
            | Self::SyncOnce { schema_version, .. }
            | Self::Classify { schema_version, .. }
            | Self::Diagnostics { schema_version, .. }
            | Self::Stop { schema_version, .. }
            | Self::Shutdown { schema_version, .. } => *schema_version,
        }
    }

    fn request_id(&self) -> &str {
        match self {
            Self::Hello { request_id, .. }
            | Self::Start { request_id, .. }
            | Self::SetPolicy { request_id, .. }
            | Self::Status { request_id, .. }
            | Self::SyncOnce { request_id, .. }
            | Self::Classify { request_id, .. }
            | Self::Diagnostics { request_id, .. }
            | Self::Stop { request_id, .. }
            | Self::Shutdown { request_id, .. } => request_id,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeResponse {
    schema_version: u32,
    request_id: String,
    ok: bool,
    runtime_session: String,
    runtime_generation: Option<u64>,
    policy_generation: u64,
    event_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<NativeProtocolError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeProtocolError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedLocalCa {
    schema_version: u32,
    certificate_der_base64: String,
    private_key_der_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalCaInstallationMarker {
    schema_version: u32,
    certificate_sha256: String,
}

#[derive(Debug, Serialize)]
struct NativeMessagingHostManifest<'a> {
    name: &'static str,
    description: &'static str,
    path: &'a Path,
    r#type: &'static str,
    allowed_origins: Vec<String>,
}

/// Serializes the browser-owned native-messaging registration manifest.
///
/// Extension IDs are deliberately constrained to Chromium's 32-character
/// `a` through `p` alphabet. Callers cannot inject arbitrary origins or JSON.
pub fn native_messaging_host_manifest_json(
    executable: &Path,
    extension_ids: &[String],
) -> Result<String, NativeHostError> {
    if !executable.is_absolute() {
        return Err(NativeHostError::Manifest(
            "the native-host executable path must be absolute".to_owned(),
        ));
    }
    if extension_ids.is_empty() || extension_ids.len() > MAX_EXTENSION_ORIGINS {
        return Err(NativeHostError::Manifest(
            "one through sixteen extension IDs are required".to_owned(),
        ));
    }
    let mut allowed_origins = Vec::with_capacity(extension_ids.len());
    for extension_id in extension_ids {
        if extension_id.len() != 32 || !extension_id.bytes().all(|byte| matches!(byte, b'a'..=b'p'))
        {
            return Err(NativeHostError::Manifest(
                "extension IDs must use Chromium's 32-character a-p alphabet".to_owned(),
            ));
        }
        let origin = format!("chrome-extension://{extension_id}/");
        if !allowed_origins.contains(&origin) {
            allowed_origins.push(origin);
        }
    }
    let manifest = NativeMessagingHostManifest {
        name: NATIVE_MESSAGING_HOST_NAME,
        description: "HNS DANE Browser Rust native host",
        path: executable,
        r#type: "stdio",
        allowed_origins,
    };
    serde_json::to_string_pretty(&manifest)
        .map(|json| format!("{json}\n"))
        .map_err(|error| NativeHostError::Manifest(error.to_string()))
}

pub struct LocalCaStore {
    authority: LocalCertificateAuthority,
    certificate_path: PathBuf,
    marker_path: PathBuf,
}

impl LocalCaStore {
    pub fn open(data_dir: &Path) -> Result<Self, NativeHostError> {
        let directory = data_dir.join("chromium-ca");
        fs::create_dir_all(&directory).map_err(local_ca_io)?;
        secure_directory(&directory)?;
        let directory = fs::canonicalize(&directory).map_err(local_ca_io)?;
        let bundle_path = directory.join("ca-bundle.json");
        if !bundle_path.exists() {
            create_local_ca_bundle(&directory, &bundle_path)?;
        }
        let authority = load_local_ca_bundle(&bundle_path)?;
        let certificate_path = directory.join("hns-dane-browser-local-ca.pem");
        ensure_public_certificate(&certificate_path, &authority.certificate_pem())?;
        Ok(Self {
            authority,
            certificate_path,
            marker_path: directory.join("ca-installed.json"),
        })
    }

    pub fn authority(&self) -> &LocalCertificateAuthority {
        &self.authority
    }

    pub fn certificate_path(&self) -> &Path {
        &self.certificate_path
    }

    pub fn certificate_sha256(&self) -> String {
        self.authority.certificate_sha256_hex()
    }

    pub fn certificate_sha1(&self) -> String {
        self.authority.certificate_sha1_hex()
    }

    pub fn is_marked_installed(&self) -> bool {
        read_bounded(&self.marker_path, MAX_LOCAL_CA_MARKER_BYTES)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LocalCaInstallationMarker>(&bytes).ok())
            .is_some_and(|marker| {
                marker.schema_version == LOCAL_CA_SCHEMA_VERSION
                    && marker.certificate_sha256 == self.certificate_sha256()
            })
    }

    pub fn mark_installed(&self) -> Result<(), NativeHostError> {
        if self.is_marked_installed() {
            return Ok(());
        }
        let marker = LocalCaInstallationMarker {
            schema_version: LOCAL_CA_SCHEMA_VERSION,
            certificate_sha256: self.certificate_sha256(),
        };
        let bytes = serde_json::to_vec_pretty(&marker)
            .map_err(|error| NativeHostError::LocalCa(error.to_string()))?;
        write_atomic(&self.marker_path, &bytes, true)
    }

    pub fn clear_installed_marker(&self) -> Result<(), NativeHostError> {
        match fs::remove_file(&self.marker_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(local_ca_io(error)),
        }
    }

    pub fn status_json(&self) -> Value {
        json!({
            "schemaVersion": LOCAL_CA_SCHEMA_VERSION,
            "state": if self.is_marked_installed() {
                "installed"
            } else {
                "needsInstallation"
            },
            "certificatePath": self.certificate_path,
            "certificateSha1": self.certificate_sha1(),
            "certificateSha256": self.certificate_sha256()
        })
    }
}

fn create_local_ca_bundle(directory: &Path, bundle_path: &Path) -> Result<(), NativeHostError> {
    let lock_path = directory.join("ca-generation.lock");
    let Some(_lock) = acquire_ca_lock(&lock_path, bundle_path)? else {
        return Ok(());
    };
    if bundle_path.exists() {
        return Ok(());
    }
    let generated = LocalCertificateAuthority::generate()
        .map_err(|error| NativeHostError::LocalCa(error.to_string()))?;
    let mut bundle = PersistedLocalCa {
        schema_version: LOCAL_CA_SCHEMA_VERSION,
        certificate_der_base64: STANDARD.encode(generated.authority().certificate_der()),
        private_key_der_base64: STANDARD.encode(generated.private_key_der()),
    };
    let bytes = serde_json::to_vec_pretty(&bundle);
    bundle.private_key_der_base64.zeroize();
    let bytes = Zeroizing::new(bytes.map_err(|error| NativeHostError::LocalCa(error.to_string()))?);
    write_atomic(bundle_path, &bytes, true)
}

fn load_local_ca_bundle(path: &Path) -> Result<LocalCertificateAuthority, NativeHostError> {
    require_private_file(path)?;
    let bytes = Zeroizing::new(read_bounded(path, MAX_LOCAL_CA_BUNDLE_BYTES)?);
    let mut bundle = serde_json::from_slice::<PersistedLocalCa>(&bytes)
        .map_err(|error| NativeHostError::LocalCa(error.to_string()))?;
    if bundle.schema_version != LOCAL_CA_SCHEMA_VERSION {
        return Err(NativeHostError::LocalCa(
            "unsupported local CA bundle schema".to_owned(),
        ));
    }
    let certificate_der = STANDARD
        .decode(bundle.certificate_der_base64)
        .map_err(|error| NativeHostError::LocalCa(error.to_string()))?;
    let private_key_der = STANDARD.decode(&bundle.private_key_der_base64);
    bundle.private_key_der_base64.zeroize();
    let private_key_der = Zeroizing::new(
        private_key_der.map_err(|error| NativeHostError::LocalCa(error.to_string()))?,
    );
    LocalCertificateAuthority::from_der(certificate_der, &private_key_der)
        .map_err(|error| NativeHostError::LocalCa(error.to_string()))
}

fn ensure_public_certificate(path: &Path, pem: &str) -> Result<(), NativeHostError> {
    if fs::read(path).is_ok_and(|existing| existing == pem.as_bytes()) {
        return Ok(());
    }
    write_atomic(path, pem.as_bytes(), false)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, NativeHostError> {
    let metadata = fs::metadata(path).map_err(local_ca_io)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(NativeHostError::LocalCa(
            "local CA file violates its size bound".to_owned(),
        ));
    }
    fs::read(path).map_err(local_ca_io)
}

fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<(), NativeHostError> {
    let parent = path
        .parent()
        .ok_or_else(|| NativeHostError::LocalCa("local CA path has no parent".to_owned()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NativeHostError::LocalCa("local CA path is invalid".to_owned()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", generate_host_session()?));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_created_file(&mut options, private);
        let mut file = options.open(&temporary).map_err(local_ca_io)?;
        file.write_all(bytes).map_err(local_ca_io)?;
        file.sync_all().map_err(local_ca_io)?;
        fs::rename(&temporary, path).map_err(local_ca_io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct LocalCaLock {
    path: PathBuf,
    _file: File,
}

impl Drop for LocalCaLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_ca_lock(
    lock_path: &Path,
    bundle_path: &Path,
) -> Result<Option<LocalCaLock>, NativeHostError> {
    for _ in 0..LOCAL_CA_LOCK_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_created_file(&mut options, true);
        match options.open(lock_path) {
            Ok(mut file) => {
                file.write_all(b"hns-dane-browser local CA generation\n")
                    .map_err(local_ca_io)?;
                file.sync_all().map_err(local_ca_io)?;
                return Ok(Some(LocalCaLock {
                    path: lock_path.to_owned(),
                    _file: file,
                }));
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if bundle_path.exists() {
                    return Ok(None);
                }
                if lock_is_stale(lock_path) {
                    match fs::remove_file(lock_path) {
                        Ok(()) => continue,
                        Err(remove_error) if remove_error.kind() == ErrorKind::NotFound => continue,
                        Err(remove_error) => return Err(local_ca_io(remove_error)),
                    }
                }
                thread::sleep(LOCAL_CA_LOCK_INTERVAL);
            }
            Err(error) => return Err(local_ca_io(error)),
        }
    }
    Err(NativeHostError::LocalCa(
        "timed out waiting for local CA generation".to_owned(),
    ))
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age >= STALE_LOCAL_CA_LOCK_AGE)
}

#[cfg(unix)]
fn configure_created_file(options: &mut OpenOptions, private: bool) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(if private { 0o600 } else { 0o644 });
}

#[cfg(not(unix))]
fn configure_created_file(_options: &mut OpenOptions, _private: bool) {}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), NativeHostError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(local_ca_io)
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), NativeHostError> {
    Ok(())
}

#[cfg(unix)]
fn require_private_file(path: &Path) -> Result<(), NativeHostError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(local_ca_io)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(NativeHostError::LocalCa(
            "local CA private bundle permissions are too broad".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file(_path: &Path) -> Result<(), NativeHostError> {
    Ok(())
}

fn local_ca_io(error: io::Error) -> NativeHostError {
    NativeHostError::LocalCa(error.to_string())
}

pub struct NativeHostController {
    runtime: BrowserRuntime,
    proxy: Option<BrowserProxy>,
    local_ca: LocalCaStore,
    host_session: String,
    event_sequence: u64,
    policy: ExtensionPolicy,
}

impl NativeHostController {
    pub fn open(data_dir: &Path, network: NetworkKind) -> Result<Self, NativeHostError> {
        let local_ca = LocalCaStore::open(data_dir)?;
        let runtime = BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .map_err(|error| NativeHostError::Runtime(error.to_string()))?;
        Ok(Self {
            runtime,
            proxy: None,
            local_ca,
            host_session: generate_host_session()?,
            event_sequence: 0,
            policy: ExtensionPolicy::default(),
        })
    }

    pub fn handle_json(&mut self, message: &[u8]) -> (NativeResponse, bool) {
        let request = match serde_json::from_slice::<NativeRequest>(message) {
            Ok(request) => request,
            Err(error) => {
                return (
                    self.error_response(
                        String::new(),
                        "invalidRequest",
                        format!("invalid native request: {error}"),
                    ),
                    false,
                );
            }
        };
        let request_id = request.request_id().to_owned();
        if request.schema_version() != NATIVE_MESSAGING_SCHEMA_VERSION {
            return (
                self.error_response(
                    request_id,
                    "unsupportedSchema",
                    format!(
                        "schema {} is unsupported; expected {}",
                        request.schema_version(),
                        NATIVE_MESSAGING_SCHEMA_VERSION
                    ),
                ),
                false,
            );
        }
        if !valid_request_id(&request_id) {
            return (
                self.error_response(
                    String::new(),
                    "invalidRequestId",
                    "requestId must be 1-128 URL-safe ASCII bytes".to_owned(),
                ),
                false,
            );
        }

        match request {
            NativeRequest::Hello { .. } => (
                self.success_response(
                    request_id,
                    json!({
                        "nativeHost": env!("CARGO_PKG_VERSION"),
                        "network": self.runtime.network().as_str(),
                        "capabilities": {
                            "manifestV3": true,
                            "nativeMessaging": true,
                            "authenticatedLoopbackProxy": true,
                            "hnsOnlyPac": true,
                            "proxyAuthentication": true,
                            "perInstallLocalCa": true,
                            "p2pDnsRelay": true,
                            "p2pOdoh": false,
                            "hnsr": false
                        }
                    }),
                ),
                false,
            ),
            NativeRequest::Start { policy, .. } | NativeRequest::SetPolicy { policy, .. } => {
                let result = self.start(policy);
                (self.response_from_result(request_id, result), false)
            }
            NativeRequest::Status { .. } => {
                let result = self.status_result();
                (self.success_response(request_id, result), false)
            }
            NativeRequest::SyncOnce { .. } => {
                let result = self
                    .runtime
                    .sync_once()
                    .map(|status| {
                        serde_json::from_str(&status.to_json())
                            .unwrap_or_else(|_| Value::String(status.to_json()))
                    })
                    .map_err(|error| ("runtimeError", error.to_string()));
                (self.response_from_result(request_id, result), false)
            }
            NativeRequest::Classify { host, .. } => (
                self.success_response(
                    request_id,
                    json!({
                        "host": host,
                        "class": browser_host_class_name(classify_browser_host(&host))
                    }),
                ),
                false,
            ),
            NativeRequest::Diagnostics { .. } => {
                let diagnostics = diagnostics_json();
                let value = serde_json::from_str(&diagnostics)
                    .unwrap_or_else(|_| Value::String(diagnostics.to_owned()));
                (self.success_response(request_id, value), false)
            }
            NativeRequest::Stop { .. } => {
                self.stop_proxy();
                (
                    self.success_response(request_id, self.status_result()),
                    false,
                )
            }
            NativeRequest::Shutdown { .. } => {
                self.stop_proxy();
                (
                    self.success_response(request_id, self.status_result()),
                    true,
                )
            }
        }
    }

    fn start(&mut self, policy: ExtensionPolicy) -> ProtocolResult {
        let runtime_policy = runtime_policy(&policy)?;
        self.stop_proxy();
        let policy_generation = self
            .runtime
            .set_policy(runtime_policy)
            .map_err(|error| ("runtimeError", error.to_string()))?;
        let proxy = self
            .runtime
            .start_hns_only_proxy_with_certificate_authority(self.local_ca.authority().clone())
            .map_err(|error| ("proxyStartFailed", error.to_string()))?;
        let pac_script = chromium_hns_only_pac_script(proxy.port())
            .map_err(|error| ("pacGenerationFailed", error.to_string()))?;
        let result = json!({
            "state": "active",
            "proxy": {
                "host": "127.0.0.1",
                "port": proxy.port(),
                "realm": proxy.authorization_realm(),
                "username": proxy.authorization_username(),
                "password": proxy.authorization_password()
            },
            "pacScript": pac_script,
            "ca": self.local_ca.status_json(),
            "runtimeSession": proxy.session_id(),
            "runtimeGeneration": proxy.generation(),
            "policyGeneration": policy_generation,
            "policy": policy
        });
        self.policy = policy;
        self.proxy = Some(proxy);
        Ok(result)
    }

    fn status_result(&self) -> Value {
        let proxy = self.proxy.as_ref();
        json!({
            "state": if proxy.is_some_and(|proxy| !proxy.is_stop_requested()) {
                "active"
            } else {
                "stopped"
            },
            "runtimeSession": proxy.map(BrowserProxy::session_id),
            "runtimeGeneration": proxy.map(BrowserProxy::generation),
            "policyGeneration": self.runtime.policy_revision(),
            "policy": self.policy,
            "caReady": self.local_ca.is_marked_installed(),
            "ca": self.local_ca.status_json()
        })
    }

    fn stop_proxy(&mut self) {
        if let Some(proxy) = self.proxy.take() {
            proxy.stop();
        }
    }

    fn response_from_result(
        &mut self,
        request_id: String,
        result: ProtocolResult,
    ) -> NativeResponse {
        match result {
            Ok(value) => self.success_response(request_id, value),
            Err((code, message)) => self.error_response(request_id, code, message),
        }
    }

    fn success_response(&mut self, request_id: String, result: Value) -> NativeResponse {
        self.event_sequence = self.event_sequence.saturating_add(1);
        NativeResponse {
            schema_version: NATIVE_MESSAGING_SCHEMA_VERSION,
            request_id,
            ok: true,
            runtime_session: self.current_runtime_session(),
            runtime_generation: self.proxy.as_ref().map(BrowserProxy::generation),
            policy_generation: self.runtime.policy_revision(),
            event_sequence: self.event_sequence,
            result: Some(result),
            error: None,
        }
    }

    fn error_response(
        &mut self,
        request_id: String,
        code: &'static str,
        message: String,
    ) -> NativeResponse {
        self.event_sequence = self.event_sequence.saturating_add(1);
        NativeResponse {
            schema_version: NATIVE_MESSAGING_SCHEMA_VERSION,
            request_id,
            ok: false,
            runtime_session: self.current_runtime_session(),
            runtime_generation: self.proxy.as_ref().map(BrowserProxy::generation),
            policy_generation: self.runtime.policy_revision(),
            event_sequence: self.event_sequence,
            result: None,
            error: Some(NativeProtocolError { code, message }),
        }
    }

    fn current_runtime_session(&self) -> String {
        self.proxy
            .as_ref()
            .map(|proxy| proxy.session_id().to_owned())
            .unwrap_or_else(|| self.host_session.clone())
    }
}

impl Drop for NativeHostController {
    fn drop(&mut self) {
        self.stop_proxy();
    }
}

type ProtocolResult = Result<Value, (&'static str, String)>;

fn runtime_policy(policy: &ExtensionPolicy) -> Result<RuntimePolicy, (&'static str, String)> {
    if policy.p2p_odoh != P2pOdohMode::Off {
        return Err((
            "unsupportedPolicy",
            "P2P ODoH is not implemented by this native host".to_owned(),
        ));
    }
    if policy.privacy_downgrade != PrivacyDowngradePolicy::FailClosed {
        return Err((
            "unsupportedPolicy",
            "direct privacy downgrade is not implemented by this native host".to_owned(),
        ));
    }
    if policy.hnsr != HnsrMode::Off {
        return Err((
            "unsupportedPolicy",
            "HNSR is not implemented by this native host".to_owned(),
        ));
    }
    if policy.experimental_wire_profile != ExperimentalWireProfile::Stable {
        return Err((
            "unsupportedPolicy",
            "experimental wire profiles are not implemented by this native host".to_owned(),
        ));
    }
    Ok(RuntimePolicy {
        resolution_mode: ResolutionMode::Strict,
        hns_doh_resolver: None,
        experimental_p2p_dns_relay: policy.p2p_dns_relay,
        legacy_hns_doh_compatibility: false,
        stateless_dane_certificates: false,
    })
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn browser_host_class_name(class: BrowserHostClass) -> &'static str {
    match class {
        BrowserHostClass::Hns => "hns",
        BrowserHostClass::Icann => "icann",
        BrowserHostClass::Search => "search",
        BrowserHostClass::NativeGateway => "nativeGateway",
    }
}

fn generate_host_session() -> Result<String, NativeHostError> {
    let mut bytes = [0_u8; HOST_SESSION_RANDOM_BYTES];
    fill_random(&mut bytes).map_err(|_| NativeHostError::SessionGeneration)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn read_native_message(reader: &mut impl Read) -> Result<Option<Vec<u8>>, NativeHostError> {
    let mut length_bytes = [0_u8; 4];
    let mut offset = 0;
    while offset < length_bytes.len() {
        match reader.read(&mut length_bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(None),
            Ok(0) => return Err(NativeHostError::TruncatedLength),
            Ok(read) => offset += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(NativeHostError::Read(error)),
        }
    }
    let length = u32::from_ne_bytes(length_bytes) as usize;
    if length == 0 {
        return Err(NativeHostError::EmptyMessage);
    }
    if length > MAX_NATIVE_MESSAGE_BYTES {
        return Err(NativeHostError::MessageTooLarge);
    }
    let mut message = vec![0_u8; length];
    match reader.read_exact(&mut message) {
        Ok(()) => Ok(Some(message)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
            Err(NativeHostError::TruncatedMessage)
        }
        Err(error) => Err(NativeHostError::Read(error)),
    }
}

pub fn write_native_message(
    writer: &mut impl Write,
    response: &NativeResponse,
) -> Result<(), NativeHostError> {
    let message = serde_json::to_vec(response).map_err(NativeHostError::Serialize)?;
    if message.is_empty() {
        return Err(NativeHostError::EmptyMessage);
    }
    if message.len() > MAX_NATIVE_MESSAGE_BYTES {
        return Err(NativeHostError::MessageTooLarge);
    }
    let length = u32::try_from(message.len()).map_err(|_| NativeHostError::MessageTooLarge)?;
    writer
        .write_all(&length.to_ne_bytes())
        .and_then(|()| writer.write_all(&message))
        .and_then(|()| writer.flush())
        .map_err(NativeHostError::Write)
}

pub fn serve_native_messaging(
    controller: &mut NativeHostController,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), NativeHostError> {
    while let Some(message) = read_native_message(reader)? {
        let (response, shutdown) = controller.handle_json(&message);
        write_native_message(writer, &response)?;
        if shutdown {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn native_messaging_frame_round_trip_is_native_endian_and_bounded() {
        let payload = br#"{"command":"hello"}"#;
        let mut frame = (payload.len() as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(payload);
        assert_eq!(
            read_native_message(&mut Cursor::new(frame)).unwrap(),
            Some(payload.to_vec())
        );
        assert_eq!(
            read_native_message(&mut Cursor::new(Vec::<u8>::new())).unwrap(),
            None
        );
        assert!(matches!(
            read_native_message(&mut Cursor::new(vec![1, 0])),
            Err(NativeHostError::TruncatedLength)
        ));
        assert!(matches!(
            read_native_message(&mut Cursor::new(0_u32.to_ne_bytes())),
            Err(NativeHostError::EmptyMessage)
        ));
        assert!(matches!(
            read_native_message(&mut Cursor::new(
                ((MAX_NATIVE_MESSAGE_BYTES as u32) + 1).to_ne_bytes()
            )),
            Err(NativeHostError::MessageTooLarge)
        ));
    }

    #[test]
    fn protocol_schema_and_policy_are_strictly_typed() {
        let hello = serde_json::from_str::<NativeRequest>(
            r#"{"command":"hello","schemaVersion":1,"requestId":"request-1"}"#,
        )
        .unwrap();
        assert_eq!(hello.schema_version(), 1);
        assert_eq!(hello.request_id(), "request-1");

        assert!(
            serde_json::from_str::<NativeRequest>(
                r#"{"command":"hello","schemaVersion":1,"requestId":"x","extra":true}"#
            )
            .is_err()
        );
        let request = serde_json::from_str::<NativeRequest>(
            r#"{"command":"start","schemaVersion":1,"requestId":"x","policy":{"p2pDnsRelay":true}}"#,
        )
        .unwrap();
        let NativeRequest::Start { policy, .. } = request else {
            panic!("start request expected");
        };
        assert!(policy.p2p_dns_relay);
        assert_eq!(policy.p2p_odoh, P2pOdohMode::Off);
    }

    #[test]
    fn unsupported_features_fail_closed_instead_of_silently_downgrading() {
        let mut policy = ExtensionPolicy::default();
        assert!(runtime_policy(&policy).is_ok());
        policy.hnsr = HnsrMode::Client;
        assert_eq!(runtime_policy(&policy).unwrap_err().0, "unsupportedPolicy");
        policy.hnsr = HnsrMode::Off;
        policy.p2p_odoh = P2pOdohMode::Preferred;
        assert_eq!(runtime_policy(&policy).unwrap_err().0, "unsupportedPolicy");
    }

    #[test]
    fn request_ids_are_bounded_and_log_safe() {
        assert!(valid_request_id("request-1:retry_2"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("contains space"));
        assert!(!valid_request_id(&"a".repeat(MAX_REQUEST_ID_BYTES + 1)));
    }

    #[test]
    fn native_host_manifest_accepts_only_exact_chromium_extension_ids() {
        let executable = if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\HNS DANE Browser\host.exe")
        } else {
            PathBuf::from("/opt/hns-dane-browser/host")
        };
        let extension_id = "abcdefghijklmnopabcdefghijklmnop".to_owned();
        let manifest =
            native_messaging_host_manifest_json(&executable, std::slice::from_ref(&extension_id))
                .unwrap();
        let value: Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(value["name"], NATIVE_MESSAGING_HOST_NAME);
        assert_eq!(
            value["allowed_origins"],
            json!([format!("chrome-extension://{extension_id}/")])
        );
        assert!(native_messaging_host_manifest_json(&executable, &[]).is_err());
        assert!(
            native_messaging_host_manifest_json(&executable, &["invalid-extension-id".to_owned()])
                .is_err()
        );
        assert!(
            native_messaging_host_manifest_json(
                Path::new("relative-host"),
                &["abcdefghijklmnopabcdefghijklmnop".to_owned()]
            )
            .is_err()
        );
    }

    #[test]
    fn local_ca_store_is_stable_private_and_explicitly_marked() {
        let path = std::env::temp_dir().join(format!(
            "hns-chromium-local-ca-test-{}",
            generate_host_session().unwrap()
        ));
        let first = LocalCaStore::open(&path).unwrap();
        let fingerprint = first.certificate_sha256();
        assert!(!first.is_marked_installed());
        assert!(first.certificate_path().is_file());
        assert!(
            fs::read_to_string(first.certificate_path())
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        first.mark_installed().unwrap();
        assert!(first.is_marked_installed());

        let second = LocalCaStore::open(&path).unwrap();
        assert_eq!(second.certificate_sha256(), fingerprint);
        assert!(second.is_marked_installed());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bundle = path.join("chromium-ca/ca-bundle.json");
            assert_eq!(
                fs::metadata(bundle).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        second.clear_installed_marker().unwrap();
        assert!(!second.is_marked_installed());

        drop(first);
        drop(second);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn controller_lifecycle_returns_pac_credentials_and_monotonic_observability() {
        let path = std::env::temp_dir().join(format!(
            "hns-chromium-native-host-test-{}",
            generate_host_session().unwrap()
        ));
        let mut controller = NativeHostController::open(&path, NetworkKind::Regtest).unwrap();
        let start = br#"{"command":"start","schemaVersion":1,"requestId":"start-1","policy":{}}"#;
        let (response, shutdown) = controller.handle_json(start);

        assert!(!shutdown);
        assert!(response.ok);
        assert_eq!(response.event_sequence, 1);
        assert_eq!(response.runtime_generation, Some(1));
        let result = response.result.unwrap();
        assert_eq!(result["state"], "active");
        assert_eq!(result["ca"]["state"], "needsInstallation");
        assert!(
            result["pacScript"]
                .as_str()
                .is_some_and(|script| script.contains("PROXY 127.0.0.1:"))
        );
        assert!(
            result["proxy"]["password"]
                .as_str()
                .is_some_and(|password| !password.is_empty())
        );

        let shutdown_request =
            br#"{"command":"shutdown","schemaVersion":1,"requestId":"shutdown-1"}"#;
        let (response, shutdown) = controller.handle_json(shutdown_request);
        assert!(shutdown);
        assert!(response.ok);
        assert_eq!(response.event_sequence, 2);
        assert_eq!(response.runtime_generation, None);
        assert_eq!(response.result.unwrap()["state"], "stopped");

        drop(controller);
        std::fs::remove_dir_all(path).unwrap();
    }
}
