//! Chromium product runtime and platform adapter for the native browser host.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use hns_browser_observability::{
    BrowserStatus as CanonicalBrowserStatus, IcannDnssecStatus as CanonicalIcannDnssecStatus,
    IcannTlsAction as CanonicalIcannTlsAction, NameTreeCurrentness as CanonicalNameTreeCurrentness,
    ProviderReadiness as CanonicalProviderReadiness, RateLimitState as CanonicalRateLimitState,
    StatusInput as CanonicalStatusInput, TransportIdentities as CanonicalTransportIdentities,
    name_tree_interval as canonical_name_tree_interval,
};
use hns_browser_runtime::{
    AuthorityState as CanonicalAuthorityState, BrowserRuntime as CanonicalBrowserRuntime,
    RuntimeSessionId as CanonicalRuntimeSessionId, RuntimeStamp as CanonicalRuntimeStamp,
};
use hns_chain::{
    DifficultyPolicy, HeaderChain, HeaderStore, SqliteHeaderStore, mainnet_sync_checkpoints,
};
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord, SVCB_PARAM_ALPN, SVCB_PARAM_MANDATORY, SVCB_PARAM_NO_DEFAULT_ALPN,
    SVCB_PARAM_PORT, SvcbRecord,
};
pub use hns_core::network::NetworkKind;
use hns_core::network_policy::{
    browser_special_use_suffixes, is_browser_blocked_port, is_browser_special_use_host,
    is_publicly_routable,
};
use hns_core::{BlockHeader, HEADER_SIZE, Height, NameHash};
use hns_dane::{
    DaneDecision, MAX_STATELESS_DANE_ROOTS, StatelessDaneConfig, TlsaMatching, TlsaRecord,
    TlsaSelector, TlsaUsage,
};
use hns_gateway::{
    Gateway, GatewayConfig, GatewayConnectDisposition, GatewayError, GatewayFailure,
    GatewayRequest, HnsHttpsMode,
};
use hns_loopback_proxy::{
    BackendError as ProxyBackendError, CancellationToken as ProxyCancellationToken, HostScopeError,
    InternalResponseMetadata, LocalCertificateAuthority, NoopProxyObserver, ProxyBackend,
    ProxyConfig, ProxyConnectOpen, ProxyConnectShutdown, ProxyConnectTunnel, ProxyError,
    ProxyHeader, ProxyInstanceId, ProxyMetadataObservationKind, ProxyPublicationAuthority,
    ProxyPublicationPermit, ProxyRequest as LoopbackProxyRequest, ProxyRequestBody, ProxyResponse,
    ProxyResponseBody, ProxyResponseHead, ProxyResponseMetadataObservation,
    ProxyResponseMetadataObserver, ProxySessionId, ProxyTunnel, ProxyTunnelOpen, RunningProxy,
    SessionIdGenerationError,
};
pub use hns_namespace_resolution::RootResolutionDisposition;
use hns_namespace_resolution::{
    AbsenceKind, AliasKind, AliasStep, ApplicationProtocol, CanonicalHost, CanonicalTlsa,
    ClassificationError, DefaultPrecedence, EvidenceProvenance, Freshness, HnsNetwork,
    IcannChainState, Namespace, NamespaceDecision, NamespaceOutcome, OriginPlanInput, OriginQuery,
    OutcomeKind, RootFailure, RootFailureKind, RootLookup, RootResolutionState, SelectionPolicy,
    SelectionReason, ServiceBinding, ServiceBindingInput, ServiceParameter, ServiceTransport,
    TlsTrustPolicy, ValidatedAbsence, ValidatedOriginPlan, decide_namespace, decision_fingerprint,
};
use hns_p2p::{
    DnsRelayClient, DnsRelayClientError, DnsSeedPeerSource, EXPERIMENTAL_DNS_RELAY_SERVICE,
    HeaderSyncSession, PeerAddressGroup, PeerConnection, PeerSource, SERVICE_NETWORK,
    SqlitePeerStore, StaticPeerSource, VersionPacket, is_allowed_peer_endpoint,
};
use hns_resolution_policy::{
    ChainAnchor as CanonicalChainAnchor,
    DnsRelayRequesterPolicy as CanonicalDnsRelayRequesterPolicy,
    EvidenceState as CanonicalEvidenceState, HnsrPolicy as CanonicalHnsrPolicy,
    Network as CanonicalNetwork, ObliviousDnsPolicy as CanonicalObliviousDnsPolicy,
    PolicyConfig as CanonicalPolicyConfig, PolicySnapshot as CanonicalPolicySnapshot,
    ProviderPolicy as CanonicalProviderPolicy, ResolutionTransport as CanonicalResolutionTransport,
    TransportPlan as CanonicalTransportPlan, ValidationEvidence as CanonicalValidationEvidence,
    WireProfile as CanonicalWireProfile,
};
use hns_resolver::{
    AuthoritativeDnssecResolver, AuthoritativeDohEndpoint, AuthoritativeDohTlsAuthentication,
    DelegatedResolver, DelegatingResolver, DnsEndpointPolicy, DnsInterceptionStatus, DnsTransport,
    HnsDelegation, HnsProofProvider, HnsResourceValueProvider, PreparedNamespaceResolution,
    ProvenNameRecords, ResolutionAnswer, ResolutionRequest, Resolver, ResolverError,
    ResourceValueAnchor, SqliteResourceValueProvider, SystemDnssecVerifier, UdpTcpDnsTransport,
    VerifiedResourceValue as ResolverVerifiedResourceValue, hns_root_label,
};
use hns_sync::{
    HeaderSyncCoordinator, HeaderSyncRunner, HeaderSyncRunnerConfig, ProofScheduler, SyncError,
    TcpHeaderPeerConnector, VerifiedResourceValue as SyncVerifiedResourceValue,
    VerifiedResourceValueSink,
};

struct ResolverResourceSink<'a>(&'a SqliteResourceValueProvider);

impl VerifiedResourceValueSink for ResolverResourceSink<'_> {
    type Error = ResolverError;

    fn insert_verified_resource_value(
        &self,
        value: SyncVerifiedResourceValue,
    ) -> Result<(), Self::Error> {
        self.0.insert(ResolverVerifiedResourceValue {
            root_name: value.root_name,
            name_hash: value.name_hash,
            value: value.value,
            secure: value.secure,
            anchor: value.anchor.map(|anchor| ResourceValueAnchor {
                tree_root: anchor.tree_root,
                height: anchor.height,
            }),
        })
    }
}
pub use hns_transport::DEFAULT_MAX_REQUEST_BODY_BYTES;
use hns_transport::{
    BrowserTlsDecision, OriginPassthroughShutdown, OriginProtocol, OriginRequest, OriginResponse,
    OriginResponseHead, OriginTransport, OriginTunnel, OriginWebPkiPassthrough, ReadWrite,
    SelectedOriginWebPkiPassthrough, TcpHttpTransport, TlsCertificateInspection, TlsValidation,
    TlsaOwner, TlsaRecordSource, TlsaTransport, TransportError,
};
use hns_urkel::UrkelProofVerifier;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions, TryLockError as FileTryLockError};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{
    Arc, Condvar, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, Weak,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_RESOURCE_CACHE_LIMIT_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_GATEWAY_HEADER_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_BROWSER_PROXY_RESOLUTION_TRACE_JSON_BYTES: usize = 64 * 1024;
pub const CHROMIUM_PAC_SCHEMA_VERSION: u32 = 3;
pub const MAX_CONFIGURED_HNS_DOH_URL_BYTES: usize = 2_048;
const MAX_STATIC_RELAY_PEER_ENDPOINT_BYTES: usize = 320;
const MAX_PENDING_CANONICAL_STATUSES: usize = 128;
static GATEWAY_BODY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static HEADER_SYNC_STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const HEADER_STATE_RECORD_MAGIC: &[u8; 8] = b"HNSHS01\0";
const HEADER_STATE_RECORD_BYTES: usize = 58;
const HEADER_STATE_UPDATING: u8 = 0;
const HEADER_STATE_READY: u8 = 1;
const HEADER_SYNC_STAGE_STALE_AFTER_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChromiumPacError {
    #[error("the Chromium HNS proxy port must be nonzero")]
    ZeroProxyPort,
}

/// Generates Chromium's mandatory DNS-name gateway PAC. Every canonical DNS
/// host used by HTTP(S) or WebSocket traffic is sent through the authenticated
/// Rust proxy so the complete host can be resolved through both HNS and ICANN
/// at the request boundary. The PAC is deliberately syntax-only: the vendored
/// IANA snapshot may be a resolver performance hint, but it never determines
/// which namespace is authoritative or whether a request bypasses Rust.
///
/// IP literals, special-use hosts, malformed names, and non-web schemes remain
/// direct. The native proxy independently rejects those classes if they reach
/// its defense-in-depth admission boundary.
pub fn chromium_dane_pac_script(proxy_port: u16) -> Result<String, ChromiumPacError> {
    if proxy_port == 0 {
        return Err(ChromiumPacError::ZeroProxyPort);
    }

    let special_use = pac_lookup_object(browser_special_use_suffixes().iter().copied());
    Ok(format!(
        r#"// Generated by hns-browser-runtime; schema {CHROMIUM_PAC_SCHEMA_VERSION}.
var HNS_SPECIAL_USE = {{{special_use}}};

function hnsNormalizeHost(host) {{
  return String(host || "").replace(/^\[/, "").replace(/\]$/, "").replace(/\.+$/, "").toLowerCase();
}}

function hnsIsIpLiteral(host) {{
  if (!host) return false;
  if (host.indexOf(":") !== -1) return /^[0-9a-f:.]+$/i.test(host);
  var parts = host.split(".");
  if (parts.length !== 4) return false;
  for (var index = 0; index < parts.length; index += 1) {{
    if (!/^[0-9]{{1,3}}$/.test(parts[index])) return false;
    var value = Number(parts[index]);
    if (value < 0 || value > 255) return false;
  }}
  return true;
}}

function hnsIsValidDnsHost(host) {{
  if (!host || host.length > 253) return false;
  var labels = host.split(".");
  for (var index = 0; index < labels.length; index += 1) {{
    var label = labels[index];
    if (!label || label.length > 63 || label.charAt(0) === "-" ||
        label.charAt(label.length - 1) === "-" || !/^[a-z0-9-]+$/i.test(label)) {{
      return false;
    }}
  }}
  return true;
}}

function hnsRequiresNativeGateway(url, host) {{
  if (!/^(http|https|ws|wss):/i.test(String(url || ""))) return false;
  host = hnsNormalizeHost(host);
  if (!hnsIsValidDnsHost(host) || hnsIsIpLiteral(host)) return false;
  var labels = host.split(".");
  var suffix = labels[labels.length - 1];
  if (HNS_SPECIAL_USE[suffix] === 1) return false;
  return true;
}}

function FindProxyForURL(url, host) {{
  return hnsRequiresNativeGateway(url, host)
    ? "PROXY 127.0.0.1:{proxy_port}"
    : "DIRECT";
}}
"#
    ))
}

fn pac_lookup_object<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .map(|value| format!(r#""{value}":1"#))
        .collect::<Vec<_>>()
        .join(",")
}

const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const NAMESPACE_EVIDENCE_MAX_TTL_SECONDS: u64 = 3_600;
const HNS_NAMESPACE_EVIDENCE_TTL_SECONDS: u64 = 30;
const HNS_DELEGATED_DNS_EVIDENCE_TTL_SECONDS: u64 = 1;
const DNS_RECURSION_DESIRED_FLAG: u16 = 0x0100;
const DNS_AUTHENTIC_DATA_FLAG: u16 = 0x0020;
const DNSSEC_DO_FLAG: u32 = 0x8000;
const DEFAULT_DNS_UDP_PAYLOAD: usize = 1232;
const DEFAULT_GATEWAY_PROOF_PEERS: usize = 8;
const DEFAULT_GATEWAY_PROOF_TIMEOUT: Duration = Duration::from_secs(3);
const ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT: Duration = Duration::from_millis(900);
const DNS_INTERCEPTION_PROBE_TIMEOUT: Duration = Duration::from_millis(350);
const DNS_INTERCEPTION_PROBE_ID: u16 = 0x484a;
const DNS_INTERCEPTION_PROBE_NAME: &str = "hns-dns-interception-probe.invalid";
// Retain proof anchors across a conservative reorganization window. This is a
// cache invalidation policy, not a statement that a 144-block-old browser view
// is current enough to authorize name resolution.
const RESOURCE_PROOF_CACHE_CANONICAL_WINDOW: u32 = 144;
// A browser name decision may trail a corroborated network target by at most
// two blocks. Peer version heights are advisory and unauthenticated, so a
// currentness target requires recent agreement across independent address
// groups instead of trusting the raw maximum claim.
const LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG: u32 = 2;
const LOCAL_CHAIN_TARGET_MIN_PEER_GROUPS: usize = 3;
const LOCAL_CHAIN_TARGET_OBSERVATION_MAX_AGE_SECONDS: u64 = 2 * 10 * 60;
const ANDROID_HEADER_SYNC_PEERS: usize = 12;
const ANDROID_HEADER_SYNC_BATCHES_PER_PEER: usize = 16;
const ANDROID_PARALLEL_PEER_PROBES: usize = 32;
const ANDROID_PARALLEL_HEADER_FETCH_PEERS: usize = 4;
const ANDROID_MIN_PEER_TARGET: usize = 64;
const ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS: u64 = 10 * 60;
const HEADER_SNAPSHOT_MAGIC: &[u8] = b"HNSHDRSNAP1";
const HEADER_SNAPSHOT_IMPORT_BATCH: usize = 2_000;
const HEADER_SNAPSHOT_MAX_HEIGHT: u32 = 1_000_000;
const MAINNET_GENESIS_TIME: u64 = 1_580_745_078;
const MAINNET_TARGET_SPACING_SECONDS: u64 = 10 * 60;
const ICANN_DOH_HOST: &str = "cloudflare-dns.com";
const ICANN_DOH_PATH: &str = "/dns-query";
// Cloudflare's documented 1.1.1.1 resolver endpoints. Connecting to these
// explicit addresses prevents the bounded resolver from recursively invoking
// the operating-system name resolver; SNI/WebPKI still use ICANN_DOH_HOST.
const ICANN_DOH_BOOTSTRAP_ADDRESSES: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];
const HNS_GATEWAY_STRICT_MODE_HEADER: &str = "X-HNS-Browser-Strict-Mode";
const HNS_GATEWAY_DOH_RESOLVER_HEADER: &str = "X-HNS-Browser-DoH-Resolver";
const HNS_GATEWAY_P2P_DNS_RELAY_HEADER: &str = "X-HNS-Browser-P2P-DNS-Relay";
const HNS_GATEWAY_LEGACY_DOH_HEADER: &str = "X-HNS-Browser-Legacy-HNS-DoH";
const HNS_GATEWAY_STATELESS_DANE_HEADER: &str = "X-HNS-Browser-Stateless-DANE";
const HNS_GATEWAY_NETWORK_HEADER: &str = "X-HNS-Browser-Network";
const HNS_RESOLUTION_TRACE_HEADER: &str = "X-HNS-Resolution-Trace";
const HNS_RESOLVER_MODE_HEADER: &str = "X-HNS-Resolver-Mode";
const HNS_DOH_FALLBACK_HEADER: &str = "X-HNS-DoH-Fallback";
const HNS_SECURITY_PATH_HEADER: &str = "X-HNS-Security-Path";
const HNS_TLS_POLICY_HEADER: &str = "X-HNS-TLS-Policy";
const HNS_RESOLVER_POLICY_HEADER: &str = "X-HNS-Resolver-Policy";
const HNS_PORT53_INTERCEPTION_REASON: &str = "HNS Port 53 Interception Detected";
const HNS_DANE_GENERATOR_URL: &str = "https://hns.denuoweb.com/dane-generator/";
const INTERCEPTION_ERROR_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const PROXY_MAINTENANCE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_PROXY_UPGRADE_HEADERS: usize = 256;
const DOH_DNS_ID: u16 = 0;
#[cfg(test)]
static SHARED_HTTP_TRANSPORT: OnceLock<TcpHttpTransport> = OnceLock::new();

#[cfg(test)]
fn shared_http_transport() -> TcpHttpTransport {
    SHARED_HTTP_TRANSPORT
        .get_or_init(TcpHttpTransport::default)
        .clone()
}

#[derive(Clone, Copy)]
struct GatewayHttpRequestInput<'a> {
    data_dir: &'a str,
    method: &'a str,
    scheme: &'a str,
    host: &'a str,
    port: u16,
    path_and_query: &'a str,
    header_text: &'a str,
    body: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawGatewayHttpRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: i32,
    pub path_and_query: String,
    pub header_text: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfiguration {
    data_dir: PathBuf,
    network: NetworkKind,
    sync: SyncOptions,
    initial_policy: RuntimePolicy,
}

impl RuntimeConfiguration {
    pub fn new(data_dir: impl Into<PathBuf>, network: NetworkKind) -> Self {
        Self {
            data_dir: data_dir.into(),
            network,
            sync: SyncOptions::default(),
            initial_policy: RuntimePolicy::compatibility(),
        }
    }

    pub fn with_sync_options(mut self, sync: SyncOptions) -> Self {
        self.sync = sync;
        self
    }

    pub fn with_initial_policy(mut self, policy: RuntimePolicy) -> Self {
        self.initial_policy = policy;
        self
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn network(&self) -> NetworkKind {
        self.network
    }

    pub fn sync_options(&self) -> &SyncOptions {
        &self.sync
    }

    pub fn initial_policy(&self) -> &RuntimePolicy {
        &self.initial_policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOptions {
    pub seed_peers: bool,
    pub timeout: Duration,
    pub resource_cache_limit_bytes: usize,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            seed_peers: true,
            timeout: Duration::from_secs(3),
            resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub resolution_mode: ResolutionMode,
    /// Optional, explicitly user-configured recursive HNS DoH recovery
    /// endpoint. An empty setting is represented as `None`; it is never
    /// populated from historical compatibility settings or a built-in default.
    pub hns_doh_resolver: Option<String>,
    /// Enables the private, proof-backed HNS peer DNS-relay transport.
    pub experimental_p2p_dns_relay: bool,
    /// Retained only for one-way migration. It is always normalized to false.
    pub legacy_hns_doh_compatibility: bool,
    pub stateless_dane_certificates: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionMode {
    Strict,
    Compatibility,
}

impl RuntimePolicy {
    pub fn compatibility() -> Self {
        Self {
            resolution_mode: ResolutionMode::Compatibility,
            hns_doh_resolver: None,
            experimental_p2p_dns_relay: false,
            legacy_hns_doh_compatibility: false,
            stateless_dane_certificates: false,
        }
    }
}

fn normalize_runtime_policy(policy: &mut RuntimePolicy) -> Result<(), RuntimeError> {
    policy.hns_doh_resolver =
        normalize_configured_hns_doh_resolver(policy.hns_doh_resolver.as_deref())
            .map_err(RuntimeError::InvalidConfiguration)?;
    policy.legacy_hns_doh_compatibility = false;
    Ok(())
}

fn canonical_policy_snapshot(
    policy: &RuntimePolicy,
    generation: u64,
) -> Result<CanonicalPolicySnapshot, RuntimeError> {
    let config = CanonicalPolicyConfig {
        dns_relay_requester: if policy.experimental_p2p_dns_relay {
            CanonicalDnsRelayRequesterPolicy::Auto
        } else {
            CanonicalDnsRelayRequesterPolicy::Disabled
        },
        oblivious_dns: CanonicalObliviousDnsPolicy::Disabled,
        hnsr: CanonicalHnsrPolicy::disabled(),
        authenticated_authoritative_doh: true,
        user_configured_recursive_hns_doh: policy.hns_doh_resolver.is_some(),
        // This browser is a requester, not a background provider. It opts out
        // of the ecosystem's default-on opaque relay role. Output/target roles
        // remain independently opt-in and are not enabled by this product.
        providers: CanonicalProviderPolicy {
            dns_relay: false,
            odoh_proxy: false,
            odoh_target: false,
            market_gossip: false,
        },
        wire_profile: CanonicalWireProfile::DenuoV1,
        allow_legacy_regtest_compatibility: false,
    };
    CanonicalPolicySnapshot::new(generation.max(1), config)
        .map_err(|error| RuntimeError::Operation(format!("canonical resolution policy: {error}")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpResponse {
    pub encoded_http: Vec<u8>,
}

impl GatewayHttpResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        self.encoded_http
    }
}

struct RawGatewayRequestRejection {
    status: u16,
    reason: &'static str,
    detail: &'static str,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("invalid runtime configuration: {0}")]
    InvalidConfiguration(String),
    #[error("runtime operation failed: {0}")]
    Operation(String),
    #[error("runtime synchronization state is poisoned: {0}")]
    Synchronization(&'static str),
}

/// Failure to start one authenticated, immutable-scope browser proxy
/// generation from a shared runtime.
#[derive(Debug, Error)]
pub enum BrowserProxyError {
    #[error("invalid browser proxy scope")]
    Scope(#[from] HostScopeError),
    #[error("unable to generate a browser proxy session identifier")]
    Session(#[from] SessionIdGenerationError),
    #[error("browser proxy generation counter is exhausted")]
    GenerationExhausted,
    #[error("canonical browser authority rejected the proxy generation: {0}")]
    Authority(String),
    #[error("unable to start the browser proxy")]
    Start(#[from] ProxyError),
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserProxyTlsPolicy {
    Dane,
    WebPkiFallback,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserProxyResolverPolicy {
    UserConfiguredRecursiveHnsDoh,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserProxySecurityPath {
    DaneAuthoritativeDoh,
    DaneAuthoritativeDns53,
    DaneP2pDnsRelay,
    DaneUserConfiguredRecursiveHnsDoh,
    DaneLocalHnsProof,
    StatelessDane,
    DaneIcannDoh,
    HnsAuthoritativeDoh,
    HnsAuthoritativeDns53,
    HnsP2pDnsRelay,
    HnsUserConfiguredRecursiveHnsDoh,
    HnsLocalHnsProof,
}

/// Why one successful response could not be represented by the shared,
/// checked schema-v2 browser status.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStatusUnavailableReason {
    /// The legacy P2P DNS-relay client does not retain the exact negotiated
    /// registry fingerprint and protocol version required by schema v2.
    P2pRegistryIdentityUnavailable,
    /// The successful legacy DNS path has no honest shared transport variant.
    TransportNotRepresentable,
    /// Required typed namespace, transport, or trust evidence was unavailable.
    EvidenceUnavailable,
    /// Shared schema validation rejected the assembled typed evidence.
    SchemaValidationRejected,
}

/// Bounded per-root dispositions retained beside one checked canonical status.
///
/// Successful root lookups are reduced to present or absent, so this value
/// never carries origin plans, addresses, TLSA records, or proof payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalRootResolutionStates {
    hns: RootResolutionDisposition,
    icann: RootResolutionDisposition,
}

impl CanonicalRootResolutionStates {
    /// Creates a bounded pair from independently completed root lookups.
    #[must_use]
    pub const fn new(hns: RootResolutionDisposition, icann: RootResolutionDisposition) -> Self {
        Self { hns, icann }
    }

    /// Bounded HNS lookup disposition.
    #[must_use]
    pub const fn hns(self) -> RootResolutionDisposition {
        self.hns
    }

    /// Bounded ICANN lookup disposition.
    #[must_use]
    pub const fn icann(self) -> RootResolutionDisposition {
        self.icann
    }
}

/// Platform-local availability of the shared, name-free browser status.
///
/// This Rust-only diagnostic does not alter the native-message JSON schema.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalStatusAvailability {
    /// No qualifying stamped origin response has been published yet.
    Pending,
    /// A checked schema-v2 status constructed from typed origin evidence.
    Available(Box<CanonicalBrowserStatus>),
    /// A checked schema-v2 status plus the bounded root dispositions retained
    /// from an indeterminate dual-root classification.
    AvailableWithRootStates {
        /// Checked canonical browser status.
        status: Box<CanonicalBrowserStatus>,
        /// Typed states copied directly from the classification failure.
        root_states: CanonicalRootResolutionStates,
    },
    /// A successful response was intentionally not misrepresented.
    Unavailable(CanonicalStatusUnavailableReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserProxyObservationKind {
    OriginResponse,
    WebPkiConnectDecision,
}

/// Exact canonical authority tuple used to bind native security results to
/// the same runtime and policy generations as the checked browser status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBrowserAuthorityTuple {
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
}

impl CanonicalBrowserAuthorityTuple {
    pub const fn runtime_session(self) -> [u8; 16] {
        self.runtime_session
    }

    pub const fn runtime_generation(self) -> u64 {
        self.runtime_generation
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

/// Exact admitted request tuple carried with every canonical status
/// observation, including an explicitly unavailable status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBrowserObservationTuple {
    runtime_session: [u8; 16],
    runtime_generation: u64,
    event_sequence: u64,
    policy_generation: u64,
}

impl CanonicalBrowserObservationTuple {
    pub fn new(
        runtime_session: [u8; 16],
        runtime_generation: u64,
        event_sequence: u64,
        policy_generation: u64,
    ) -> Option<Self> {
        if runtime_session == [0; 16]
            || runtime_generation == 0
            || event_sequence == 0
            || policy_generation == 0
        {
            return None;
        }
        Some(Self {
            runtime_session,
            runtime_generation,
            event_sequence,
            policy_generation,
        })
    }

    pub const fn runtime_session(self) -> [u8; 16] {
        self.runtime_session
    }

    pub const fn runtime_generation(self) -> u64 {
        self.runtime_generation
    }

    pub const fn event_sequence(self) -> u64 {
        self.event_sequence
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

/// Bounded, typed security status observed before the loopback proxy removes
/// internal runtime metadata from the browser-visible response.
///
/// This status is sensitive rather than privacy-bounded: its trace can contain
/// navigation details and must not be written to ordinary platform logs.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserProxyStatus {
    generation: u64,
    host: String,
    status_code: u16,
    likely_main_frame: bool,
    observation_kind: BrowserProxyObservationKind,
    port: Option<u16>,
    correlation_epoch: Option<u64>,
    tls_policy: Option<BrowserProxyTlsPolicy>,
    resolver_policy: Option<BrowserProxyResolverPolicy>,
    security_path: Option<BrowserProxySecurityPath>,
    resolution_trace_json: Option<String>,
    canonical_observation: Option<CanonicalBrowserObservationTuple>,
    canonical_status: CanonicalStatusAvailability,
}

impl BrowserProxyStatus {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn is_likely_main_frame(&self) -> bool {
        self.likely_main_frame
    }

    pub const fn observation_kind(&self) -> BrowserProxyObservationKind {
        self.observation_kind
    }

    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    pub const fn correlation_epoch(&self) -> Option<u64> {
        self.correlation_epoch
    }

    pub fn tls_policy(&self) -> Option<BrowserProxyTlsPolicy> {
        self.tls_policy
    }

    pub fn resolver_policy(&self) -> Option<BrowserProxyResolverPolicy> {
        self.resolver_policy
    }

    pub fn security_path(&self) -> Option<BrowserProxySecurityPath> {
        self.security_path
    }

    /// Returns a sensitive, bounded resolution trace for in-memory browser UI.
    /// Callers must not write this value to ordinary logs.
    pub fn resolution_trace_json(&self) -> Option<&str> {
        self.resolution_trace_json.as_deref()
    }

    /// Exact request admission tuple for ordering available and unavailable
    /// canonical observations without using callback completion time.
    pub const fn canonical_observation_tuple(&self) -> Option<CanonicalBrowserObservationTuple> {
        self.canonical_observation
    }

    /// Canonical, name-free authority status built from typed resolver and
    /// trust decisions. This is never reconstructed from the diagnostic JSON
    /// trace.
    pub fn canonical_status(&self) -> Option<&CanonicalBrowserStatus> {
        match &self.canonical_status {
            CanonicalStatusAvailability::Available(status) => Some(status),
            CanonicalStatusAvailability::AvailableWithRootStates { status, .. } => Some(status),
            CanonicalStatusAvailability::Pending | CanonicalStatusAvailability::Unavailable(_) => {
                None
            }
        }
    }

    /// Bounded per-root dispositions for an indeterminate classification.
    ///
    /// These values are carried beside the checked canonical status under the
    /// same admitted observation tuple. They are never reconstructed from the
    /// sensitive diagnostic JSON trace.
    pub const fn canonical_root_resolution_states(&self) -> Option<CanonicalRootResolutionStates> {
        match &self.canonical_status {
            CanonicalStatusAvailability::AvailableWithRootStates { root_states, .. } => {
                Some(*root_states)
            }
            CanonicalStatusAvailability::Pending
            | CanonicalStatusAvailability::Available(_)
            | CanonicalStatusAvailability::Unavailable(_) => None,
        }
    }

    /// Explains an intentional canonical-status omission for this response.
    pub fn canonical_status_unavailable_reason(&self) -> Option<CanonicalStatusUnavailableReason> {
        match &self.canonical_status {
            CanonicalStatusAvailability::Unavailable(reason) => Some(*reason),
            CanonicalStatusAvailability::Pending
            | CanonicalStatusAvailability::Available(_)
            | CanonicalStatusAvailability::AvailableWithRootStates { .. } => None,
        }
    }
}

impl std::fmt::Debug for BrowserProxyStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserProxyStatus")
            .field("generation", &self.generation)
            .field("host", &self.host)
            .field("status_code", &self.status_code)
            .field("likely_main_frame", &self.likely_main_frame)
            .field("observation_kind", &self.observation_kind)
            .field("port", &self.port)
            .field("correlation_epoch", &self.correlation_epoch)
            .field("tls_policy", &self.tls_policy)
            .field("resolver_policy", &self.resolver_policy)
            .field("security_path", &self.security_path)
            .field(
                "resolution_trace_present",
                &self.resolution_trace_json.is_some(),
            )
            .field(
                "resolution_trace_bytes",
                &self.resolution_trace_json.as_ref().map(String::len),
            )
            .field(
                "canonical_status_available",
                &matches!(
                    &self.canonical_status,
                    CanonicalStatusAvailability::Available(_)
                        | CanonicalStatusAvailability::AvailableWithRootStates { .. }
                ),
            )
            .field(
                "canonical_status_unavailable_reason",
                &self.canonical_status_unavailable_reason(),
            )
            .finish()
    }
}

pub trait BrowserProxyStatusObserver: Send + Sync + 'static {
    /// Receives status derived only from the proxy's trusted internal metadata
    /// allowlist. Implementations must return promptly and must not panic.
    fn observe_status(&self, status: &BrowserProxyStatus);
}

impl<F> BrowserProxyStatusObserver for F
where
    F: Fn(&BrowserProxyStatus) + Send + Sync + 'static,
{
    fn observe_status(&self, status: &BrowserProxyStatus) {
        self(status);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopBrowserProxyStatusObserver;

impl BrowserProxyStatusObserver for NoopBrowserProxyStatusObserver {
    fn observe_status(&self, _status: &BrowserProxyStatus) {}
}

fn parse_browser_proxy_tls_policy(value: Option<&str>) -> Option<BrowserProxyTlsPolicy> {
    match value.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("dane") => Some(BrowserProxyTlsPolicy::Dane),
        Some(value) if value.eq_ignore_ascii_case("webpki-fallback") => {
            Some(BrowserProxyTlsPolicy::WebPkiFallback)
        }
        _ => None,
    }
}

fn parse_browser_proxy_resolver_policy(value: Option<&str>) -> Option<BrowserProxyResolverPolicy> {
    match value.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("user-configured-recursive-hns-doh") => {
            Some(BrowserProxyResolverPolicy::UserConfiguredRecursiveHnsDoh)
        }
        _ => None,
    }
}

fn parse_browser_proxy_security_path(value: Option<&str>) -> Option<BrowserProxySecurityPath> {
    let value = value.map(str::trim)?;
    if value.eq_ignore_ascii_case("dane-authoritative-doh") {
        Some(BrowserProxySecurityPath::DaneAuthoritativeDoh)
    } else if value.eq_ignore_ascii_case("dane-authoritative-dns53") {
        Some(BrowserProxySecurityPath::DaneAuthoritativeDns53)
    } else if value.eq_ignore_ascii_case("dane-p2p-dns-relay") {
        Some(BrowserProxySecurityPath::DaneP2pDnsRelay)
    } else if value.eq_ignore_ascii_case("dane-user-configured-recursive-hns-doh") {
        Some(BrowserProxySecurityPath::DaneUserConfiguredRecursiveHnsDoh)
    } else if value.eq_ignore_ascii_case("dane-local-hns-proof") {
        Some(BrowserProxySecurityPath::DaneLocalHnsProof)
    } else if value.eq_ignore_ascii_case("stateless-dane") {
        Some(BrowserProxySecurityPath::StatelessDane)
    } else if value.eq_ignore_ascii_case("dane-icann-doh") {
        Some(BrowserProxySecurityPath::DaneIcannDoh)
    } else if value.eq_ignore_ascii_case("hns-authoritative-doh") {
        Some(BrowserProxySecurityPath::HnsAuthoritativeDoh)
    } else if value.eq_ignore_ascii_case("hns-authoritative-dns53") {
        Some(BrowserProxySecurityPath::HnsAuthoritativeDns53)
    } else if value.eq_ignore_ascii_case("hns-p2p-dns-relay") {
        Some(BrowserProxySecurityPath::HnsP2pDnsRelay)
    } else if value.eq_ignore_ascii_case("hns-user-configured-recursive-hns-doh") {
        Some(BrowserProxySecurityPath::HnsUserConfiguredRecursiveHnsDoh)
    } else if value.eq_ignore_ascii_case("hns-local-hns-proof") {
        Some(BrowserProxySecurityPath::HnsLocalHnsProof)
    } else {
        None
    }
}

fn bounded_browser_proxy_resolution_trace(value: Option<&str>) -> Option<String> {
    value
        .filter(|trace| trace.len() <= MAX_BROWSER_PROXY_RESOLUTION_TRACE_JSON_BYTES)
        .map(str::to_owned)
}

// Keep the complete trusted observation tuple explicit at this conversion
// boundary so review can see every correlation field at each call site.
#[allow(clippy::too_many_arguments)]
fn browser_proxy_status_from_metadata(
    generation: u64,
    host: &str,
    status_code: u16,
    likely_main_frame: bool,
    observation_kind: BrowserProxyObservationKind,
    port: Option<u16>,
    correlation_epoch: Option<u64>,
    metadata: &InternalResponseMetadata,
    canonical_observation: Option<CanonicalBrowserObservationTuple>,
    canonical_status: CanonicalStatusAvailability,
) -> BrowserProxyStatus {
    BrowserProxyStatus {
        generation,
        host: host.to_owned(),
        status_code,
        likely_main_frame,
        observation_kind,
        port,
        correlation_epoch,
        tls_policy: parse_browser_proxy_tls_policy(metadata.get(HNS_TLS_POLICY_HEADER)),
        resolver_policy: parse_browser_proxy_resolver_policy(
            metadata.get(HNS_RESOLVER_POLICY_HEADER),
        ),
        security_path: parse_browser_proxy_security_path(metadata.get(HNS_SECURITY_PATH_HEADER)),
        resolution_trace_json: bounded_browser_proxy_resolution_trace(
            metadata.get(HNS_RESOLUTION_TRACE_HEADER),
        ),
        canonical_observation,
        canonical_status,
    }
}

struct RuntimeProxyStatusMetadataObserver {
    observer: Arc<dyn BrowserProxyStatusObserver>,
    authority: Arc<CanonicalAuthority>,
    authority_generation: u64,
    statuses: Arc<CanonicalStatusRegistry>,
}

impl ProxyResponseMetadataObserver for RuntimeProxyStatusMetadataObserver {
    fn observe(&self, observation: &ProxyResponseMetadataObservation) {
        if observation.generation() != self.authority_generation {
            return;
        }
        let Some(canonical_observation) = observation
            .observation_id()
            .and_then(|id| self.statuses.take(id, &self.authority))
        else {
            return;
        };
        let observation_kind = match observation.kind() {
            ProxyMetadataObservationKind::OriginResponse => {
                if observation.correlation_epoch().is_some() {
                    return;
                }
                BrowserProxyObservationKind::OriginResponse
            }
            ProxyMetadataObservationKind::WebPkiConnectDecision => {
                if observation.correlation_epoch()
                    != Some(canonical_observation.maintenance_epoch.0)
                {
                    return;
                }
                BrowserProxyObservationKind::WebPkiConnectDecision
            }
        };
        let status = browser_proxy_status_from_metadata(
            observation.generation(),
            observation.host().as_str(),
            observation.status_code(),
            observation.is_likely_main_frame(),
            observation_kind,
            observation.port(),
            Some(canonical_observation.maintenance_epoch.0),
            observation.metadata(),
            Some(canonical_observation.tuple),
            canonical_observation.status,
        );
        if self.authority.admits(canonical_observation.stamp) {
            self.observer.observe_status(&status);
        }
    }
}

/// One Rust-owned proxy generation backed by this runtime's resolver,
/// persistent stores, policy, and origin transport.
pub struct BrowserProxy {
    running: RunningProxy,
    authority: Arc<CanonicalAuthority>,
    authority_generation: u64,
    statuses: Arc<CanonicalStatusRegistry>,
}

impl BrowserProxy {
    pub fn port(&self) -> u16 {
        self.running.endpoint().port()
    }

    /// Explicit credential accessors are intended only for a native browser's
    /// in-memory proxy-authentication callback.
    pub fn authorization_realm(&self) -> &str {
        self.running.endpoint().realm()
    }

    pub fn authorization_username(&self) -> &str {
        self.running.endpoint().username()
    }

    pub fn authorization_password(&self) -> &str {
        self.running.endpoint().password()
    }

    pub fn generation(&self) -> u64 {
        self.running.endpoint().instance().generation()
    }

    /// Opaque, non-credential runtime session identity used with
    /// [`Self::generation`] to reject stale native lifecycle callbacks.
    pub fn session_id(&self) -> &str {
        self.running.endpoint().instance().session().as_str()
    }

    pub fn matches_instance(&self, session_id: &str, generation: u64) -> bool {
        self.session_id() == session_id && self.generation() == generation
    }

    pub fn matches_authentication_challenge(&self, host: &str, port: u16, realm: &str) -> bool {
        self.running
            .matches_authentication_challenge(host, port, realm)
    }

    /// Validates challenge DER against the exact host identity retained by
    /// this live generation. Stopped, unknown, malformed, and stale matches
    /// fail closed inside `hns-loopback-proxy`.
    pub fn matches_local_certificate(&self, host: &str, certificate_der: &[u8]) -> bool {
        self.running
            .matches_local_certificate(host, certificate_der)
    }

    pub fn stop(&self) {
        self.running.request_stop();
        self.statuses.clear_generation(self.authority_generation);
        self.authority.revoke_proxy(self.authority_generation);
        self.running.stop();
    }

    /// Revokes credentials and local-certificate authorization, closes active
    /// sockets, and cancels backend work without waiting for worker joins.
    pub fn request_stop(&self) {
        self.running.request_stop();
        self.statuses.clear_generation(self.authority_generation);
        self.authority.revoke_proxy(self.authority_generation);
    }

    pub fn is_stopped(&self) -> bool {
        self.running.is_stopped()
    }

    pub fn is_stop_requested(&self) -> bool {
        self.running.is_stop_requested()
    }
}

impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.running.request_stop();
        self.statuses.clear_generation(self.authority_generation);
        self.authority.revoke_proxy(self.authority_generation);
    }
}

impl std::fmt::Debug for BrowserProxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserProxy")
            .field("generation", &self.generation())
            .field("port", &self.port())
            .field("credentials", &"[REDACTED]")
            .field("stopped", &self.is_stopped())
            .finish()
    }
}

#[derive(Clone)]
pub struct BrowserRuntime {
    inner: Arc<RuntimeInner>,
}

/// Cloneable, platform-neutral adapter from the shared browser runtime into
/// the Rust loopback proxy's typed request and tunnel boundary.
#[derive(Clone)]
pub struct RuntimeProxyBackend {
    runtime: BrowserRuntime,
    authority_generation: u64,
}

impl std::fmt::Debug for RuntimeProxyBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RuntimeProxyBackend(<redacted runtime>)")
    }
}

struct RuntimeInner {
    configuration: RuntimeConfiguration,
    policy: RwLock<RuntimePolicy>,
    data_dir: String,
    transport: TcpHttpTransport,
    coordination: Arc<RuntimeCoordination>,
    policy_revision: AtomicU64,
    proxy_session: ProxySessionId,
    proxy_generation: AtomicU64,
    canonical_authority: Arc<CanonicalAuthority>,
    canonical_statuses: Arc<CanonicalStatusRegistry>,
    operation: Mutex<()>,
}

#[derive(Clone, Copy, Debug)]
struct CanonicalWorkStamp {
    runtime: CanonicalRuntimeStamp,
    admitted_snapshot: hns_browser_runtime::RuntimeSnapshot,
    proxy_generation: u64,
    storage_identity: Option<HeaderSyncStorageIdentity>,
}

impl CanonicalWorkStamp {
    fn with_storage_identity(mut self, identity: HeaderSyncStorageIdentity) -> Self {
        self.storage_identity = Some(identity);
        self
    }
}

struct CanonicalReadiness {
    _private: (),
}

trait CanonicalTransportReadinessProbe: Send + Sync {
    fn verify(&self, plan: &CanonicalTransportPlan) -> std::io::Result<()>;
}

struct LocalSocketTransportReadinessProbe;

impl CanonicalTransportReadinessProbe for LocalSocketTransportReadinessProbe {
    fn verify(&self, plan: &CanonicalTransportPlan) -> std::io::Result<()> {
        let mut last_error = None;
        if plan.contains(CanonicalResolutionTransport::DirectAuthoritativeUdp) {
            match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
                Ok(socket) => {
                    drop(socket);
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        if plan.contains(CanonicalResolutionTransport::DirectAuthoritativeTcp) {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
                Ok(listener) => {
                    drop(listener);
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                ErrorKind::Unsupported,
                "canonical policy has no locally verifiable DNS transport",
            )
        }))
    }
}

struct CanonicalAuthority {
    runtime: Mutex<CanonicalBrowserRuntime>,
    policy: RwLock<CanonicalPolicySnapshot>,
    prepared_proxy_generation: AtomicU64,
    active_proxy_generation: AtomicU64,
    readiness_base: PathBuf,
    readiness_network: NetworkKind,
    transport_readiness: Arc<dyn CanonicalTransportReadinessProbe>,
}

impl CanonicalAuthority {
    fn new(
        session: CanonicalRuntimeSessionId,
        policy: CanonicalPolicySnapshot,
        readiness_base: PathBuf,
        readiness_network: NetworkKind,
    ) -> Result<Self, RuntimeError> {
        Self::new_with_transport_readiness(
            session,
            policy,
            readiness_base,
            readiness_network,
            Arc::new(LocalSocketTransportReadinessProbe),
        )
    }

    fn new_with_transport_readiness(
        session: CanonicalRuntimeSessionId,
        policy: CanonicalPolicySnapshot,
        readiness_base: PathBuf,
        readiness_network: NetworkKind,
        transport_readiness: Arc<dyn CanonicalTransportReadinessProbe>,
    ) -> Result<Self, RuntimeError> {
        let mut runtime = CanonicalBrowserRuntime::new(session);
        runtime
            .transition(CanonicalAuthorityState::LocalStateOpened)
            .map_err(canonical_runtime_error)?;
        Ok(Self {
            runtime: Mutex::new(runtime),
            policy: RwLock::new(policy),
            prepared_proxy_generation: AtomicU64::new(0),
            active_proxy_generation: AtomicU64::new(0),
            readiness_base,
            readiness_network,
            transport_readiness,
        })
    }

    fn verify_readiness(&self) -> Result<CanonicalReadiness, RuntimeError> {
        let currentness = local_chain_currentness(&self.readiness_base, self.readiness_network)
            .map_err(|error| {
                RuntimeError::Operation(format!(
                    "canonical authority could not verify header currentness: {error}"
                ))
            })?;
        if currentness.tree_root_ready != Some(true) {
            return Err(RuntimeError::Operation(
                "canonical authority requires the corroborated name-tree root".to_owned(),
            ));
        }
        SqliteResourceValueProvider::open(self.readiness_base.join("resources.sqlite")).map_err(
            |error| {
                RuntimeError::Operation(format!(
                    "canonical authority proof service is unavailable: {error}"
                ))
            },
        )?;
        let policy = self.policy_snapshot()?;
        let transport_plan = CanonicalTransportPlan::for_policy(policy.config());
        self.transport_readiness
            .verify(&transport_plan)
            .map_err(|error| {
                RuntimeError::Operation(format!(
                    "canonical authority has no usable policy-permitted DNS transport: {error}"
                ))
            })?;
        Ok(CanonicalReadiness { _private: () })
    }

    fn readiness_or_invalidate(&self) -> Result<CanonicalReadiness, RuntimeError> {
        match self.verify_readiness() {
            Ok(readiness) => Ok(readiness),
            Err(error) => {
                if let Ok(mut runtime) = self.runtime.lock()
                    && !matches!(
                        runtime.authority_state(),
                        CanonicalAuthorityState::Degraded
                            | CanonicalAuthorityState::Revoked
                            | CanonicalAuthorityState::Stopped
                    )
                {
                    let _result = runtime.transition(CanonicalAuthorityState::Degraded);
                }
                Err(error)
            }
        }
    }

    fn update_policy(&self, policy: CanonicalPolicySnapshot) -> Result<(), RuntimeError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        runtime.policy_changed().map_err(canonical_runtime_error)?;
        self.prepared_proxy_generation.store(0, Ordering::Release);
        self.active_proxy_generation.store(0, Ordering::Release);
        let mut current = self
            .policy
            .write()
            .map_err(|_| RuntimeError::Synchronization("canonical authority policy"))?;
        *current = policy;
        Ok(())
    }

    fn prepare_proxy(&self, proxy_generation: u64) -> Result<(), RuntimeError> {
        if proxy_generation == 0 {
            return Err(RuntimeError::InvalidConfiguration(
                "proxy generation must be nonzero".to_owned(),
            ));
        }
        // Revoke the previous binding before advancing a replacement. The
        // authority state and invalidation event then make every prior stamp
        // stale even if the old listener has not finished joining yet.
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        self.prepared_proxy_generation.store(0, Ordering::Release);
        self.active_proxy_generation.store(0, Ordering::Release);
        if runtime.authority_state() == CanonicalAuthorityState::Active {
            runtime
                .transition(CanonicalAuthorityState::Revoked)
                .map_err(canonical_runtime_error)?;
        }
        advance_canonical_authority_to_header_syncing(&mut runtime)?;
        self.prepared_proxy_generation
            .store(proxy_generation, Ordering::Release);
        Ok(())
    }

    fn activate_proxy(&self, proxy_generation: u64) -> Result<(), RuntimeError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        if !matches!(
            runtime.authority_state(),
            CanonicalAuthorityState::HeaderSyncing | CanonicalAuthorityState::Degraded
        ) || self.active_proxy_generation.load(Ordering::Acquire) != 0
            || self.prepared_proxy_generation.load(Ordering::Acquire) != proxy_generation
        {
            return Err(RuntimeError::Operation(
                "canonical authority proxy activation is not prepared".to_owned(),
            ));
        }
        self.active_proxy_generation
            .store(proxy_generation, Ordering::Release);
        self.prepared_proxy_generation.store(0, Ordering::Release);
        Ok(())
    }

    fn cancel_prepared_proxy(&self, proxy_generation: u64) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        if self
            .prepared_proxy_generation
            .compare_exchange(proxy_generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && self.active_proxy_generation.load(Ordering::Acquire) == 0
            && !matches!(
                runtime.authority_state(),
                CanonicalAuthorityState::Degraded
                    | CanonicalAuthorityState::Revoked
                    | CanonicalAuthorityState::Stopped
            )
        {
            let _result = runtime.transition(CanonicalAuthorityState::Degraded);
        }
    }

    fn revoke_proxy(&self, proxy_generation: u64) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        if self
            .active_proxy_generation
            .compare_exchange(proxy_generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if runtime.authority_state() != CanonicalAuthorityState::Stopped
            && runtime.authority_state() != CanonicalAuthorityState::Revoked
        {
            let _result = runtime.transition(CanonicalAuthorityState::Revoked);
        }
    }

    fn admit(&self, proxy_generation: u64) -> Result<CanonicalWorkStamp, RuntimeError> {
        if proxy_generation == 0 {
            return Err(RuntimeError::Operation(
                "canonical authority rejected a zero proxy generation".to_owned(),
            ));
        }
        self.admit_binding(proxy_generation)
    }

    fn admit_direct(&self) -> Result<CanonicalWorkStamp, RuntimeError> {
        self.admit_binding(0)
    }

    fn binding_is_current(&self, proxy_generation: u64) -> bool {
        proxy_generation == 0
            || self.active_proxy_generation.load(Ordering::Acquire) == proxy_generation
    }

    fn admit_binding(&self, proxy_generation: u64) -> Result<CanonicalWorkStamp, RuntimeError> {
        if !self.binding_is_current(proxy_generation) {
            return Err(RuntimeError::Operation(
                "canonical authority rejected a stale proxy generation".to_owned(),
            ));
        }
        self.readiness_or_invalidate()?;
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        if !self.binding_is_current(proxy_generation) {
            return Err(RuntimeError::Operation(
                "canonical authority rejected a stale proxy generation".to_owned(),
            ));
        }
        advance_canonical_authority_to_active(&mut runtime)?;
        let stamp = runtime.admit_event().map_err(canonical_runtime_error)?;
        let admitted_snapshot = runtime.snapshot();
        if admitted_snapshot.session_bytes() != stamp.session()
            || admitted_snapshot.generation() != stamp.generation()
            || admitted_snapshot.event_sequence() != stamp.event_sequence()
        {
            return Err(RuntimeError::Operation(
                "canonical authority admission snapshot did not match its stamp".to_owned(),
            ));
        }
        Ok(CanonicalWorkStamp {
            runtime: stamp,
            admitted_snapshot,
            proxy_generation,
            storage_identity: None,
        })
    }

    fn admits(&self, stamp: CanonicalWorkStamp) -> bool {
        self.readiness_or_invalidate().is_ok() && self.admits_without_readiness(stamp)
    }

    fn admits_without_readiness(&self, stamp: CanonicalWorkStamp) -> bool {
        self.binding_is_current(stamp.proxy_generation)
            && self
                .runtime
                .lock()
                .is_ok_and(|runtime| runtime.admits(stamp.runtime))
    }

    fn with_current<T>(
        &self,
        stamp: CanonicalWorkStamp,
        operation: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        self.readiness_or_invalidate()
            .map_err(|_| canonical_authority_transport_error())?;
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| canonical_authority_transport_error())?;
        if !self.binding_is_current(stamp.proxy_generation) || !runtime.admits(stamp.runtime) {
            return Err(canonical_authority_transport_error());
        }
        operation()
    }

    fn publish_current(
        &self,
        stamp: CanonicalWorkStamp,
        operation: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.readiness_or_invalidate()
            .map_err(|_| canonical_authority_publication_error())?;
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| canonical_authority_publication_error())?;
        if !self.binding_is_current(stamp.proxy_generation) || !runtime.admits(stamp.runtime) {
            return Err(canonical_authority_publication_error());
        }
        operation()
    }

    fn publish_direct_result<T>(
        &self,
        stamp: CanonicalWorkStamp,
        store: &NamespaceBindingStore,
        decision: Option<&NamespaceDecision>,
        operation: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        if stamp.proxy_generation != 0 {
            return Err(RuntimeError::Operation(
                "canonical authority rejected a non-direct publication stamp".to_owned(),
            ));
        }
        self.readiness_or_invalidate()?;
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        if !self.binding_is_current(stamp.proxy_generation) || !runtime.admits(stamp.runtime) {
            return Err(RuntimeError::Operation(
                "canonical authority rejected stale direct publication".to_owned(),
            ));
        }
        persist_successful_namespace_decision(store, decision).map_err(|error| {
            RuntimeError::Operation(format!("persist namespace binding: {error}"))
        })?;
        operation()
    }

    fn policy_snapshot(&self) -> Result<CanonicalPolicySnapshot, RuntimeError> {
        self.policy
            .read()
            .map(|policy| *policy)
            .map_err(|_| RuntimeError::Synchronization("canonical authority policy"))
    }

    fn authority_tuple(&self) -> Result<CanonicalBrowserAuthorityTuple, RuntimeError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        let policy = self.policy_snapshot()?;
        let snapshot = runtime.snapshot();
        Ok(CanonicalBrowserAuthorityTuple {
            runtime_session: snapshot.session_bytes(),
            runtime_generation: snapshot.generation(),
            policy_generation: policy.generation(),
        })
    }

    fn observation_tuple(
        &self,
        stamp: CanonicalWorkStamp,
    ) -> Result<CanonicalBrowserObservationTuple, RuntimeError> {
        let (runtime, policy) = self.status_context(stamp)?;
        Ok(CanonicalBrowserObservationTuple {
            runtime_session: runtime.session_bytes(),
            runtime_generation: runtime.generation(),
            event_sequence: runtime.event_sequence(),
            policy_generation: policy.generation(),
        })
    }

    fn status_context(
        &self,
        stamp: CanonicalWorkStamp,
    ) -> Result<
        (
            hns_browser_runtime::RuntimeSnapshot,
            CanonicalPolicySnapshot,
        ),
        RuntimeError,
    > {
        if !self.binding_is_current(stamp.proxy_generation) {
            return Err(RuntimeError::Operation(
                "canonical authority rejected stale status context".to_owned(),
            ));
        }
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| RuntimeError::Synchronization("canonical authority runtime"))?;
        if !runtime.admits(stamp.runtime) {
            return Err(RuntimeError::Operation(
                "canonical authority rejected stale status context".to_owned(),
            ));
        }
        let policy = self.policy_snapshot()?;
        Ok((stamp.admitted_snapshot, policy))
    }
}

struct CanonicalProxyPublicationAuthority {
    authority: Arc<CanonicalAuthority>,
    coordination: Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    stamp: CanonicalWorkStamp,
    namespace_publication: Option<CanonicalNamespacePublication>,
    connect_publication_signal: Option<Arc<AtomicBool>>,
}

struct CanonicalNamespacePublication {
    store: Arc<NamespaceBindingStore>,
    decision: NamespaceDecision,
}

impl ProxyPublicationAuthority for CanonicalProxyPublicationAuthority {
    fn publish(&self, operation: &mut dyn FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
        let maintenance = self
            .coordination
            .maintenance
            .read()
            .map_err(|_| canonical_authority_publication_error())?;
        if self.coordination.publication_epoch(&maintenance) != Some(self.maintenance_epoch) {
            return Err(canonical_authority_publication_error());
        }
        let mut header_state_lock =
            HeaderStateFileLock::try_shared(&self.coordination.header_state_lock_path)
                .map_err(|_| canonical_authority_publication_error())?
                .ok_or_else(canonical_authority_publication_error)?;
        if header_state_lock
            .ready_identity()
            .map_err(|_| canonical_authority_publication_error())?
            != self.storage_identity
        {
            return Err(canonical_authority_publication_error());
        }
        self.authority.publish_current(self.stamp, &mut || {
            if let Some(publication) = &self.namespace_publication {
                persist_successful_namespace_decision(
                    &publication.store,
                    Some(&publication.decision),
                )
                .map_err(|_| {
                    std::io::Error::other(
                        "namespace binding could not be committed at response publication",
                    )
                })?;
            }
            let result = operation();
            if result.is_ok()
                && let Some(signal) = &self.connect_publication_signal
            {
                signal.store(true, Ordering::Release);
            }
            result
        })
    }
}

fn canonical_proxy_publication_permit(
    authority: &Arc<CanonicalAuthority>,
    coordination: &Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    stamp: CanonicalWorkStamp,
) -> ProxyPublicationPermit {
    ProxyPublicationPermit::new(Arc::new(CanonicalProxyPublicationAuthority {
        authority: Arc::clone(authority),
        coordination: Arc::clone(coordination),
        maintenance_epoch,
        storage_identity,
        stamp,
        namespace_publication: None,
        connect_publication_signal: None,
    }))
}

fn canonical_proxy_publication_permit_with_namespace(
    authority: &Arc<CanonicalAuthority>,
    coordination: &Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    stamp: CanonicalWorkStamp,
    store: &Arc<NamespaceBindingStore>,
    decision: Option<NamespaceDecision>,
) -> ProxyPublicationPermit {
    ProxyPublicationPermit::new(Arc::new(CanonicalProxyPublicationAuthority {
        authority: Arc::clone(authority),
        coordination: Arc::clone(coordination),
        maintenance_epoch,
        storage_identity,
        stamp,
        namespace_publication: decision.map(|decision| CanonicalNamespacePublication {
            store: Arc::clone(store),
            decision,
        }),
        connect_publication_signal: None,
    }))
}

#[allow(clippy::too_many_arguments)]
fn canonical_connect_publication_permit(
    authority: &Arc<CanonicalAuthority>,
    coordination: &Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    stamp: CanonicalWorkStamp,
    store: &Arc<NamespaceBindingStore>,
    decision: NamespaceDecision,
    signal: Arc<AtomicBool>,
) -> ProxyPublicationPermit {
    ProxyPublicationPermit::new(Arc::new(CanonicalProxyPublicationAuthority {
        authority: Arc::clone(authority),
        coordination: Arc::clone(coordination),
        maintenance_epoch,
        storage_identity,
        stamp,
        namespace_publication: Some(CanonicalNamespacePublication {
            store: Arc::clone(store),
            decision,
        }),
        connect_publication_signal: Some(signal),
    }))
}

struct PendingCanonicalStatus {
    id: u64,
    maintenance_epoch: MaintenanceEpoch,
    stamp: CanonicalWorkStamp,
    tuple: CanonicalBrowserObservationTuple,
    status: CanonicalStatusAvailability,
}

struct CanonicalStatusObservation {
    maintenance_epoch: MaintenanceEpoch,
    stamp: CanonicalWorkStamp,
    tuple: CanonicalBrowserObservationTuple,
    status: CanonicalStatusAvailability,
}

struct CanonicalStatusRegistry {
    next_id: AtomicU64,
    pending: Mutex<VecDeque<PendingCanonicalStatus>>,
}

impl Default for CanonicalStatusRegistry {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(VecDeque::new()),
        }
    }
}

impl CanonicalStatusRegistry {
    fn insert_with_epoch(
        &self,
        authority: &CanonicalAuthority,
        stamp: CanonicalWorkStamp,
        status: CanonicalStatusAvailability,
        maintenance_epoch: MaintenanceEpoch,
    ) -> Option<u64> {
        let tuple = authority.observation_tuple(stamp).ok()?;
        let id = self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?
            + 1;
        let mut pending = self.pending.lock().ok()?;
        if pending.len() == MAX_PENDING_CANONICAL_STATUSES {
            pending.pop_front();
        }
        pending.push_back(PendingCanonicalStatus {
            id,
            maintenance_epoch,
            stamp,
            tuple,
            status,
        });
        Some(id)
    }

    fn take(&self, id: u64, authority: &CanonicalAuthority) -> Option<CanonicalStatusObservation> {
        let mut pending = self.pending.lock().ok()?;
        let index = pending.iter().position(|entry| entry.id == id)?;
        let entry = pending.remove(index)?;
        authority
            .admits(entry.stamp)
            .then_some(CanonicalStatusObservation {
                maintenance_epoch: entry.maintenance_epoch,
                stamp: entry.stamp,
                tuple: entry.tuple,
                status: entry.status,
            })
    }

    fn clear(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }

    fn clear_generation(&self, proxy_generation: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.retain(|entry| entry.stamp.proxy_generation != proxy_generation);
        }
    }
}

fn advance_canonical_authority_to_header_syncing(
    runtime: &mut CanonicalBrowserRuntime,
) -> Result<(), RuntimeError> {
    match runtime.authority_state() {
        CanonicalAuthorityState::LocalStateOpened
        | CanonicalAuthorityState::Degraded
        | CanonicalAuthorityState::Revoked => {
            runtime
                .transition(CanonicalAuthorityState::HeaderSyncing)
                .map_err(canonical_runtime_error)?;
        }
        CanonicalAuthorityState::HeaderSyncing => {}
        _ => {
            return Err(RuntimeError::Operation(
                "canonical authority is not at a recoverable proxy-start boundary".to_owned(),
            ));
        }
    }
    Ok(())
}

fn advance_canonical_authority_to_active(
    runtime: &mut CanonicalBrowserRuntime,
) -> Result<(), RuntimeError> {
    match runtime.authority_state() {
        CanonicalAuthorityState::LocalStateOpened
        | CanonicalAuthorityState::Degraded
        | CanonicalAuthorityState::Revoked => {
            advance_canonical_authority_to_header_syncing(runtime)?;
        }
        CanonicalAuthorityState::HeaderSyncing => {}
        CanonicalAuthorityState::Active => return Ok(()),
        _ => {
            return Err(RuntimeError::Operation(
                "canonical authority is not at a recoverable admission boundary".to_owned(),
            ));
        }
    }
    for state in [
        CanonicalAuthorityState::HeaderCurrent,
        CanonicalAuthorityState::ProofReady,
        CanonicalAuthorityState::ResolutionTransportReady,
        CanonicalAuthorityState::BrowserBridgeReady,
        CanonicalAuthorityState::Active,
    ] {
        runtime.transition(state).map_err(canonical_runtime_error)?;
    }
    Ok(())
}

fn canonical_runtime_error(error: hns_browser_runtime::RuntimeError) -> RuntimeError {
    RuntimeError::Operation(format!("canonical browser authority: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredNamespace {
    Hns,
    Icann,
}

impl StoredNamespace {
    const fn database_value(self) -> i64 {
        match self {
            Self::Hns => 1,
            Self::Icann => 2,
        }
    }

    fn from_database_value(value: i64) -> Result<Self, ResolverError> {
        match value {
            1 => Ok(Self::Hns),
            2 => Ok(Self::Icann),
            _ => Err(ResolverError::Storage(
                "namespace binding contains an invalid namespace".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NamespaceOriginKey {
    scheme: String,
    host: String,
    port: u16,
}

impl NamespaceOriginKey {
    fn new(scheme: &str, host: &str, port: u16) -> Result<Self, ResolverError> {
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" | "ws" => "http".to_owned(),
            "https" | "wss" => "https".to_owned(),
            _ => return Err(ResolverError::UnsupportedBackend),
        };
        if port == 0 {
            return Err(ResolverError::UnsupportedBackend);
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 253
            || !host.is_ascii()
            || host.chars().any(char::is_whitespace)
        {
            return Err(ResolverError::UnsupportedBackend);
        }
        Ok(Self { scheme, host, port })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredNamespaceBinding {
    namespace: StoredNamespace,
    revision: u64,
}

struct NamespaceBindingStore {
    network: NetworkKind,
    connection: Mutex<Connection>,
}

impl NamespaceBindingStore {
    fn open(path: impl AsRef<Path>, network: NetworkKind) -> Result<Self, ResolverError> {
        let connection =
            Connection::open(path).map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection, network)
    }

    #[cfg(test)]
    fn in_memory(network: NetworkKind) -> Result<Self, ResolverError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection, network)
    }

    fn from_connection(
        connection: Connection,
        network: NetworkKind,
    ) -> Result<Self, ResolverError> {
        connection
            .execute_batch(
                "
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS namespace_bindings (
                    network TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    namespace INTEGER NOT NULL CHECK (namespace IN (1, 2)),
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    bound_at_unix INTEGER NOT NULL CHECK (bound_at_unix >= 0),
                    PRIMARY KEY (network, scheme, host, port)
                ) STRICT;
                ",
            )
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        Ok(Self {
            network,
            connection: Mutex::new(connection),
        })
    }

    fn get(
        &self,
        origin: &NamespaceOriginKey,
    ) -> Result<Option<StoredNamespaceBinding>, ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let stored = connection
            .query_row(
                "
                SELECT namespace, revision
                FROM namespace_bindings
                WHERE network = ?1 AND scheme = ?2 AND host = ?3 AND port = ?4
                ",
                params![
                    self.network.as_str(),
                    origin.scheme,
                    origin.host,
                    i64::from(origin.port)
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        stored
            .map(|(namespace, revision)| {
                let revision = u64::try_from(revision).map_err(|_| {
                    ResolverError::Storage(
                        "namespace binding contains an invalid revision".to_owned(),
                    )
                })?;
                Ok(StoredNamespaceBinding {
                    namespace: StoredNamespace::from_database_value(namespace)?,
                    revision,
                })
            })
            .transpose()
    }

    fn record_success(
        &self,
        origin: &NamespaceOriginKey,
        namespace: StoredNamespace,
        bound_at_unix: u64,
    ) -> Result<StoredNamespaceBinding, ResolverError> {
        let bound_at_unix = i64::try_from(bound_at_unix).map_err(|_| {
            ResolverError::Storage("namespace binding timestamp exceeds SQLite range".to_owned())
        })?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let transaction = connection
            .transaction()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        let stored = transaction
            .query_row(
                "
                SELECT namespace, revision
                FROM namespace_bindings
                WHERE network = ?1 AND scheme = ?2 AND host = ?3 AND port = ?4
                ",
                params![
                    self.network.as_str(),
                    origin.scheme,
                    origin.host,
                    i64::from(origin.port)
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;

        let binding = if let Some((stored_namespace, revision)) = stored {
            let stored_namespace = StoredNamespace::from_database_value(stored_namespace)?;
            if stored_namespace != namespace {
                return Err(ResolverError::Storage(
                    "refusing to replace a successful namespace binding without an explicit origin-scoped switch"
                        .to_owned(),
                ));
            }
            StoredNamespaceBinding {
                namespace,
                revision: u64::try_from(revision).map_err(|_| {
                    ResolverError::Storage(
                        "namespace binding contains an invalid revision".to_owned(),
                    )
                })?,
            }
        } else {
            transaction
                .execute(
                    "
                    INSERT INTO namespace_bindings (
                        network, scheme, host, port, namespace, revision, bound_at_unix
                    ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
                    ",
                    params![
                        self.network.as_str(),
                        origin.scheme,
                        origin.host,
                        i64::from(origin.port),
                        namespace.database_value(),
                        bound_at_unix
                    ],
                )
                .map_err(|error| ResolverError::Storage(error.to_string()))?;
            StoredNamespaceBinding {
                namespace,
                revision: 1,
            }
        };
        transaction
            .commit()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        Ok(binding)
    }
}

struct RuntimeCoordination {
    sync_lock: Mutex<()>,
    maintenance: RwLock<()>,
    maintenance_epoch: AtomicU64,
    header_state_base: PathBuf,
    header_state_lock_path: PathBuf,
    header_sync_lock_path: PathBuf,
    peer_state: Arc<Mutex<()>>,
    relay: SharedDnsRelayState,
    namespace_bindings: Arc<NamespaceBindingStore>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaintenanceEpoch(u64);

struct ProxyMaintenanceGuard<'a> {
    _guard: RwLockReadGuard<'a, ()>,
    _header_state_lock: HeaderStateFileLock,
    epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
}

impl ProxyMaintenanceGuard<'_> {
    fn epoch(&self) -> MaintenanceEpoch {
        self.epoch
    }

    fn storage_identity(&self) -> HeaderSyncStorageIdentity {
        self.storage_identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderSyncStorageIdentity {
    header_generation: u64,
    peer_generation: u64,
    best_hash: Option<hns_core::Hash>,
}

struct HeaderStateFileLock {
    file: File,
}

impl HeaderStateFileLock {
    fn shared(path: &Path) -> Result<Self, String> {
        let file = open_header_state_lock_file(path)?;
        file.lock_shared()
            .map_err(|error| format!("acquire shared header-state lock: {error}"))?;
        Ok(Self { file })
    }

    fn exclusive(path: &Path) -> Result<Self, String> {
        let file = open_header_state_lock_file(path)?;
        file.lock()
            .map_err(|error| format!("acquire exclusive header-state lock: {error}"))?;
        Ok(Self { file })
    }

    fn try_shared(path: &Path) -> Result<Option<Self>, String> {
        let file = open_header_state_lock_file(path)?;
        match file.try_lock_shared() {
            Ok(()) => Ok(Some(Self { file })),
            Err(FileTryLockError::WouldBlock) => Ok(None),
            Err(FileTryLockError::Error(error)) => {
                Err(format!("try shared header-state lock: {error}"))
            }
        }
    }

    fn ready_identity(&mut self) -> Result<HeaderSyncStorageIdentity, String> {
        let record = read_header_state_record(&mut self.file)?;
        match record {
            HeaderStateRecord::Ready(identity) => Ok(identity),
            HeaderStateRecord::Updating => Err("header-state publication is incomplete".to_owned()),
        }
    }

    fn mark_updating(&mut self) -> Result<(), String> {
        write_header_state_record(&mut self.file, HeaderStateRecord::Updating)
    }

    fn mark_ready(&mut self, identity: HeaderSyncStorageIdentity) -> Result<(), String> {
        write_header_state_record(&mut self.file, HeaderStateRecord::Ready(identity))
    }
}

impl Drop for HeaderStateFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn open_header_state_lock_file(path: &Path) -> Result<File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "header-state lock path has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create header-state lock directory: {error}"))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("open header-state lock file: {error}"))
}

fn peer_state_lock_path(peer_store_path: &Path) -> Result<PathBuf, String> {
    peer_store_path
        .parent()
        .map(|parent| parent.join(".peer-state.lock"))
        .ok_or_else(|| "peer-store path has no parent".to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderStateRecord {
    Updating,
    Ready(HeaderSyncStorageIdentity),
}

fn read_header_state_record(file: &mut File) -> Result<HeaderStateRecord, String> {
    let length = file
        .metadata()
        .map_err(|error| format!("inspect header-state record: {error}"))?
        .len();
    if length != HEADER_STATE_RECORD_BYTES as u64 {
        return Err("header-state record has an invalid length".to_owned());
    }
    let mut encoded = [0_u8; HEADER_STATE_RECORD_BYTES];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut encoded))
        .map_err(|error| format!("read header-state record: {error}"))?;
    if &encoded[..8] != HEADER_STATE_RECORD_MAGIC {
        return Err("header-state record has an invalid magic value".to_owned());
    }
    match encoded[8] {
        HEADER_STATE_UPDATING => Ok(HeaderStateRecord::Updating),
        HEADER_STATE_READY => {
            let header_generation = u64::from_le_bytes(
                encoded[9..17]
                    .try_into()
                    .map_err(|_| "header-state header generation is malformed".to_owned())?,
            );
            let peer_generation = u64::from_le_bytes(
                encoded[17..25]
                    .try_into()
                    .map_err(|_| "header-state peer generation is malformed".to_owned())?,
            );
            let best_hash = match encoded[25] {
                0 => None,
                1 => Some(
                    hns_core::Hash::from_slice(&encoded[26..58])
                        .map_err(|error| format!("decode header-state best hash: {error}"))?,
                ),
                _ => return Err("header-state best-hash marker is invalid".to_owned()),
            };
            Ok(HeaderStateRecord::Ready(HeaderSyncStorageIdentity {
                header_generation,
                peer_generation,
                best_hash,
            }))
        }
        _ => Err("header-state record has an invalid state".to_owned()),
    }
}

fn write_header_state_record(file: &mut File, record: HeaderStateRecord) -> Result<(), String> {
    let mut encoded = [0_u8; HEADER_STATE_RECORD_BYTES];
    encoded[..8].copy_from_slice(HEADER_STATE_RECORD_MAGIC);
    match record {
        HeaderStateRecord::Updating => {
            encoded[8] = HEADER_STATE_UPDATING;
        }
        HeaderStateRecord::Ready(identity) => {
            encoded[8] = HEADER_STATE_READY;
            encoded[9..17].copy_from_slice(&identity.header_generation.to_le_bytes());
            encoded[17..25].copy_from_slice(&identity.peer_generation.to_le_bytes());
            if let Some(best_hash) = identity.best_hash {
                encoded[25] = 1;
                encoded[26..58].copy_from_slice(best_hash.as_bytes());
            }
        }
    }
    file.set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(&encoded))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write header-state record: {error}"))
}

fn read_header_sync_storage_identity(base: &Path) -> Result<HeaderSyncStorageIdentity, String> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| format!("open header store for storage identity: {error}"))?;
    let header_generation = header_store
        .sync_generation()
        .map_err(|error| format!("read header sync generation: {error}"))?;
    let best_hash = header_store.best_hash();
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store for storage identity: {error}"))?;
    let peer_generation = peer_store
        .sync_generation()
        .map_err(|error| format!("read peer sync generation: {error}"))?;
    Ok(HeaderSyncStorageIdentity {
        header_generation,
        peer_generation,
        best_hash,
    })
}

fn initialize_header_state_record(base: &Path, lock_path: &Path) -> Result<(), String> {
    let mut lock = HeaderStateFileLock::exclusive(lock_path)?;
    let live_identity = read_header_sync_storage_identity(base)?;
    let record_was_empty = lock
        .file
        .metadata()
        .map_err(|error| format!("inspect header-state record: {error}"))?
        .len()
        == 0;
    let existing = read_header_state_record(&mut lock.file);
    match existing {
        Ok(HeaderStateRecord::Ready(identity)) if identity == live_identity => Ok(()),
        Ok(HeaderStateRecord::Updating) => Ok(()),
        Err(_) if record_was_empty => {
            if live_identity.header_generation == live_identity.peer_generation {
                lock.mark_ready(live_identity)
            } else {
                lock.mark_updating()
            }
        }
        Ok(HeaderStateRecord::Ready(_)) | Err(_) => lock.mark_updating(),
    }
}

impl RuntimeCoordination {
    fn begin_maintenance(&self, _guard: &RwLockWriteGuard<'_, ()>) -> Result<(), RuntimeError> {
        let current = self.maintenance_epoch.load(Ordering::Acquire);
        if current == 0 {
            return Err(RuntimeError::Operation(
                "header maintenance epoch is exhausted".to_owned(),
            ));
        }
        let Some(next) = current.checked_add(1) else {
            // Zero is a permanent fail-closed sentinel. It invalidates every
            // outstanding nonzero publication permit and prevents new work
            // from being admitted against an epoch which could wrap.
            self.maintenance_epoch.store(0, Ordering::Release);
            return Err(RuntimeError::Operation(
                "header maintenance epoch is exhausted".to_owned(),
            ));
        };
        self.maintenance_epoch.store(next, Ordering::Release);
        Ok(())
    }

    fn publication_epoch(&self, _guard: &RwLockReadGuard<'_, ()>) -> Option<MaintenanceEpoch> {
        match self.maintenance_epoch.load(Ordering::Acquire) {
            0 => None,
            epoch => Some(MaintenanceEpoch(epoch)),
        }
    }
}

type SharedDnsRelayFlights = Arc<Mutex<HashMap<Vec<u8>, Arc<DnsRelayFlight>>>>;

#[derive(Clone)]
struct SharedDnsRelayState {
    client: Arc<Mutex<Option<DnsRelayClient>>>,
    queries: SharedDnsRelayFlights,
}

static RUNTIME_COORDINATION: OnceLock<Mutex<HashMap<PathBuf, Weak<RuntimeCoordination>>>> =
    OnceLock::new();

fn runtime_coordination(
    base: &Path,
    network: NetworkKind,
) -> Result<Arc<RuntimeCoordination>, RuntimeError> {
    let identity = fs::canonicalize(base).map_err(|error| {
        RuntimeError::Operation(format!("canonicalize runtime storage directory: {error}"))
    })?;
    let registry = RUNTIME_COORDINATION.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| RuntimeError::Synchronization("runtime coordination registry"))?;
    registry.retain(|_, coordination| coordination.strong_count() != 0);
    if let Some(coordination) = registry.get(&identity).and_then(Weak::upgrade) {
        return Ok(coordination);
    }
    let header_state_lock_path = identity.join(".header-state.lock");
    initialize_header_state_record(&identity, &header_state_lock_path)
        .map_err(RuntimeError::Operation)?;
    let coordination = Arc::new(RuntimeCoordination {
        sync_lock: Mutex::new(()),
        maintenance: RwLock::new(()),
        maintenance_epoch: AtomicU64::new(1),
        header_state_base: identity.clone(),
        header_state_lock_path,
        header_sync_lock_path: identity.join(".header-sync.lock"),
        peer_state: Arc::new(Mutex::new(())),
        relay: SharedDnsRelayState {
            client: Arc::new(Mutex::new(None)),
            queries: Arc::new(Mutex::new(HashMap::new())),
        },
        namespace_bindings: Arc::new(
            NamespaceBindingStore::open(identity.join("namespace-bindings.sqlite"), network)
                .map_err(|error| {
                    RuntimeError::Operation(format!("open namespace binding store: {error}"))
                })?,
        ),
    });
    registry.insert(identity, Arc::downgrade(&coordination));
    Ok(coordination)
}

impl BrowserRuntime {
    pub fn open(mut configuration: RuntimeConfiguration) -> Result<Self, RuntimeError> {
        let configured_data_dir = configuration
            .data_dir
            .to_str()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                RuntimeError::InvalidConfiguration(
                    "data directory must be a non-empty UTF-8 path".to_owned(),
                )
            })?
            .to_owned();
        fs::create_dir_all(&configured_data_dir).map_err(|error| {
            RuntimeError::Operation(format!("create runtime data directory: {error}"))
        })?;
        let canonical_data_dir = fs::canonicalize(&configured_data_dir).map_err(|error| {
            RuntimeError::Operation(format!("canonicalize runtime data directory: {error}"))
        })?;
        let data_dir = canonical_data_dir
            .to_str()
            .ok_or_else(|| {
                RuntimeError::InvalidConfiguration(
                    "canonical data directory must be a UTF-8 path".to_owned(),
                )
            })?
            .to_owned();
        configuration.data_dir = canonical_data_dir;
        let mut policy = configuration.initial_policy.clone();
        normalize_runtime_policy(&mut policy)?;
        let base = network_base_path(&data_dir, configuration.network);
        fs::create_dir_all(&base).map_err(|error| {
            RuntimeError::Operation(format!("create runtime directory: {error}"))
        })?;
        let initialized_header_store = open_initialized_header_chain(&base, configuration.network)
            .map_err(RuntimeError::Operation)?
            .into_store();
        initialized_header_store.flush().map_err(|error| {
            RuntimeError::Operation(format!("close initialized chain: {error}"))
        })?;
        let coordination = runtime_coordination(&base, configuration.network)?;
        let proxy_session = ProxySessionId::generate().map_err(|error| {
            RuntimeError::Operation(format!("generate canonical runtime session: {error}"))
        })?;
        let canonical_session = CanonicalRuntimeSessionId::new(*proxy_session.as_bytes())
            .map_err(canonical_runtime_error)?;
        let canonical_policy = canonical_policy_snapshot(&policy, 1)?;
        let canonical_authority = Arc::new(CanonicalAuthority::new(
            canonical_session,
            canonical_policy,
            base,
            configuration.network,
        )?);

        configuration.initial_policy = policy.clone();
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                configuration,
                policy: RwLock::new(policy),
                data_dir,
                transport: TcpHttpTransport::default(),
                coordination,
                policy_revision: AtomicU64::new(0),
                proxy_session,
                proxy_generation: AtomicU64::new(0),
                canonical_authority,
                canonical_statuses: Arc::new(CanonicalStatusRegistry::default()),
                operation: Mutex::new(()),
            }),
        })
    }

    pub fn configuration(&self) -> Result<RuntimeConfiguration, RuntimeError> {
        let mut configuration = self.inner.configuration.clone();
        let policy = self.policy()?;
        configuration.initial_policy = policy;
        Ok(configuration)
    }

    pub fn network(&self) -> NetworkKind {
        self.inner.configuration.network
    }

    /// Current nonzero epoch that invalidates navigation security decisions
    /// across header maintenance.
    pub fn security_maintenance_epoch(&self) -> Option<u64> {
        match self
            .inner
            .coordination
            .maintenance_epoch
            .load(Ordering::Acquire)
        {
            0 => None,
            epoch => Some(epoch),
        }
    }

    pub fn policy(&self) -> Result<RuntimePolicy, RuntimeError> {
        self.policy_snapshot().map(|(policy, _)| policy)
    }

    pub fn policy_snapshot(&self) -> Result<(RuntimePolicy, u64), RuntimeError> {
        let policy = self
            .inner
            .policy
            .read()
            .map_err(|_| RuntimeError::Synchronization("policy lock"))?;
        let revision = self.inner.policy_revision.load(Ordering::Acquire);
        Ok((policy.clone(), revision))
    }

    pub fn set_policy(&self, policy: RuntimePolicy) -> Result<u64, RuntimeError> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| RuntimeError::Synchronization("runtime operation lock"))?;
        self.set_policy_locked(policy)
    }

    fn set_policy_locked(&self, mut policy: RuntimePolicy) -> Result<u64, RuntimeError> {
        normalize_runtime_policy(&mut policy)?;
        let mut current = self
            .inner
            .policy
            .write()
            .map_err(|_| RuntimeError::Synchronization("policy lock"))?;
        let revision = self.inner.policy_revision.load(Ordering::Acquire);
        if *current == policy {
            return Ok(revision);
        }
        let next_revision = revision.checked_add(1).ok_or_else(|| {
            RuntimeError::Operation("runtime policy generation is exhausted".to_owned())
        })?;
        let canonical_generation = next_revision.checked_add(1).ok_or_else(|| {
            RuntimeError::Operation("canonical policy generation is exhausted".to_owned())
        })?;
        let canonical_policy = canonical_policy_snapshot(&policy, canonical_generation)?;
        self.inner
            .canonical_authority
            .update_policy(canonical_policy)?;
        self.inner.canonical_statuses.clear();
        *current = policy;
        self.inner
            .policy_revision
            .store(next_revision, Ordering::Release);
        Ok(next_revision)
    }

    fn with_policy_operation<T>(
        &self,
        policy: RuntimePolicy,
        operation: impl FnOnce(&BrowserRuntime) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| RuntimeError::Synchronization("runtime operation lock"))?;
        if self.policy()? != policy {
            self.set_policy_locked(policy)?;
        }
        operation(self)
    }

    pub fn policy_revision(&self) -> u64 {
        self.inner.policy_revision.load(Ordering::Acquire)
    }

    /// Returns the exact canonical session/runtime/policy tuple used by
    /// checked browser statuses. Native adapters use this at activation so
    /// their freshness boundary cannot be confused with proxy-listener
    /// generation or the legacy zero-based policy revision.
    pub fn canonical_authority_tuple(
        &self,
    ) -> Result<CanonicalBrowserAuthorityTuple, RuntimeError> {
        self.inner.canonical_authority.authority_tuple()
    }

    /// Returns a proxy backend that shares this runtime's policy, persistent
    /// stores, resolver coordination, and origin transport state.
    pub fn proxy_backend(&self) -> RuntimeProxyBackend {
        RuntimeProxyBackend {
            runtime: self.clone(),
            authority_generation: self
                .inner
                .canonical_authority
                .active_proxy_generation
                .load(Ordering::Acquire),
        }
    }

    fn proxy_backend_for_generation(&self, generation: u64) -> RuntimeProxyBackend {
        RuntimeProxyBackend {
            runtime: self.clone(),
            authority_generation: generation,
        }
    }

    #[cfg(test)]
    fn start_proxy(&self, scope_root: &str) -> Result<BrowserProxy, BrowserProxyError> {
        self.start_proxy_with_observer(scope_root, Arc::new(NoopBrowserProxyStatusObserver))
    }

    #[cfg(test)]
    fn start_proxy_with_observer(
        &self,
        scope_root: &str,
        observer: Arc<dyn BrowserProxyStatusObserver>,
    ) -> Result<BrowserProxy, BrowserProxyError> {
        let scope = hns_loopback_proxy::HostScope::new(scope_root)?;
        let generation = self
            .inner
            .proxy_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| BrowserProxyError::GenerationExhausted)?
            + 1;
        self.inner
            .canonical_authority
            .prepare_proxy(generation)
            .map_err(|error| BrowserProxyError::Authority(error.to_string()))?;
        let session = self.inner.proxy_session.clone();
        let instance = ProxyInstanceId::new(session, generation);
        let metadata_observer = RuntimeProxyStatusMetadataObserver {
            observer,
            authority: Arc::clone(&self.inner.canonical_authority),
            authority_generation: generation,
            statuses: Arc::clone(&self.inner.canonical_statuses),
        };
        let running = match RunningProxy::start_with_metadata_observer(
            ProxyConfig::new(instance, scope),
            Arc::new(self.proxy_backend_for_generation(generation)),
            Arc::new(NoopProxyObserver),
            Arc::new(metadata_observer),
        ) {
            Ok(running) => running,
            Err(error) => {
                self.inner
                    .canonical_authority
                    .cancel_prepared_proxy(generation);
                return Err(error.into());
            }
        };
        if let Err(error) = self.inner.canonical_authority.activate_proxy(generation) {
            running.stop();
            self.inner
                .canonical_authority
                .cancel_prepared_proxy(generation);
            return Err(BrowserProxyError::Authority(error.to_string()));
        }
        Ok(BrowserProxy {
            running,
            authority: Arc::clone(&self.inner.canonical_authority),
            authority_generation: generation,
            statuses: Arc::clone(&self.inner.canonical_statuses),
        })
    }

    /// Starts a Chromium generation which sends every canonical DNS host
    /// through one authenticated Rust boundary. ICANN TLSA discovery and the
    /// WebPKI/fail-closed decision therefore apply uniformly to main frames,
    /// redirects, subresources, workers, downloads, and WebSockets.
    pub fn start_dane_browser_proxy_with_certificate_authority_and_observer(
        &self,
        certificate_authority: LocalCertificateAuthority,
        observer: Arc<dyn BrowserProxyStatusObserver>,
    ) -> Result<BrowserProxy, BrowserProxyError> {
        self.start_browser_proxy_with_options(Some(certificate_authority), observer)
    }

    fn start_browser_proxy_with_options(
        &self,
        certificate_authority: Option<LocalCertificateAuthority>,
        observer: Arc<dyn BrowserProxyStatusObserver>,
    ) -> Result<BrowserProxy, BrowserProxyError> {
        let generation = self
            .inner
            .proxy_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| BrowserProxyError::GenerationExhausted)?
            + 1;
        self.inner
            .canonical_authority
            .prepare_proxy(generation)
            .map_err(|error| BrowserProxyError::Authority(error.to_string()))?;
        let session = self.inner.proxy_session.clone();
        let instance = ProxyInstanceId::new(session, generation);
        let metadata_observer = RuntimeProxyStatusMetadataObserver {
            observer,
            authority: Arc::clone(&self.inner.canonical_authority),
            authority_generation: generation,
            statuses: Arc::clone(&self.inner.canonical_statuses),
        };
        let mut config = ProxyConfig::dane_browser(instance);
        if let Some(certificate_authority) = certificate_authority {
            config = config.with_local_certificate_authority(certificate_authority);
        }
        let running = match RunningProxy::start_with_metadata_observer(
            config,
            Arc::new(self.proxy_backend_for_generation(generation)),
            Arc::new(NoopProxyObserver),
            Arc::new(metadata_observer),
        ) {
            Ok(running) => running,
            Err(error) => {
                self.inner
                    .canonical_authority
                    .cancel_prepared_proxy(generation);
                return Err(error.into());
            }
        };
        if let Err(error) = self.inner.canonical_authority.activate_proxy(generation) {
            running.stop();
            self.inner
                .canonical_authority
                .cancel_prepared_proxy(generation);
            return Err(BrowserProxyError::Authority(error.to_string()));
        }
        Ok(BrowserProxy {
            running,
            authority: Arc::clone(&self.inner.canonical_authority),
            authority_generation: generation,
            statuses: Arc::clone(&self.inner.canonical_statuses),
        })
    }

    pub fn sync_once(&self) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let mut observed_header_state =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let observed_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        let observed_recorded_identity = observed_header_state.ready_identity().ok();
        let observed_status =
            read_sync_status(&self.inner.data_dir, self.inner.configuration.network).ok();
        drop(observed_header_state);

        let _process_sync =
            HeaderStateFileLock::exclusive(&self.inner.coordination.header_sync_lock_path)
                .map_err(RuntimeError::Operation)?;
        let mut header_state_lock =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let current_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        let recorded_identity = header_state_lock.ready_identity().ok();
        let mut current_status =
            read_sync_status(&self.inner.data_dir, self.inner.configuration.network)
                .map_err(RuntimeError::Operation)?;
        let another_process_refreshed = current_identity != observed_identity
            || target_evidence_deadline_advanced(
                observed_status
                    .as_ref()
                    .and_then(|status| status.target_evidence_valid_until_unix),
                current_status.target_evidence_valid_until_unix,
            )
            || (observed_recorded_identity != Some(observed_identity)
                && recorded_identity == Some(current_identity));
        if another_process_refreshed
            && Some(current_identity) == recorded_identity
            && current_status.freshness == "current"
            && !current_status.target_evidence_expired
        {
            current_status.status = "coalesced";
            return Ok(current_status);
        }
        drop(header_state_lock);

        let staged = prepare_header_sync_stage(
            &self.inner.data_dir,
            self.inner.configuration.network,
            &self.inner.coordination,
        )
        .map_err(RuntimeError::Operation)?;
        let staged_status = run_sync_once(
            staged.data_dir()?,
            self.inner.configuration.network,
            self.inner.configuration.sync.seed_peers,
            self.inner.configuration.sync.timeout,
            self.inner.configuration.sync.resource_cache_limit_bytes,
        )
        .map_err(RuntimeError::Operation)?;

        if staged_status.freshness == "current"
            && !staged_status.target_evidence_expired
            && staged_headers_match_baseline(&staged, self.inner.configuration.network)
                .map_err(RuntimeError::Operation)?
        {
            let _maintenance = self
                .inner
                .coordination
                .maintenance
                .read()
                .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
            let mut header_state_lock =
                HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                    .map_err(RuntimeError::Operation)?;
            let live_identity =
                read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                    .map_err(RuntimeError::Operation)?;
            let recorded_identity = header_state_lock.ready_identity().ok();
            if live_identity != staged.baseline_storage_identity {
                return Err(RuntimeError::Operation(format!(
                    "header sync stage was superseded before peer refresh \
                     (baseline {baseline:?}, live {live_identity:?}, record {recorded_identity:?})",
                    baseline = staged.baseline_storage_identity,
                )));
            }
            if recorded_identity == Some(live_identity) {
                let _peer_state = self
                    .inner
                    .coordination
                    .peer_state
                    .lock()
                    .map_err(|_| RuntimeError::Synchronization("peer state lock"))?;
                let peer_store_path = self
                    .inner
                    .coordination
                    .header_state_base
                    .join("peers.sqlite");
                let process_peer_state_path =
                    peer_state_lock_path(&peer_store_path).map_err(RuntimeError::Operation)?;
                let _process_peer_state = HeaderStateFileLock::exclusive(&process_peer_state_path)
                    .map_err(RuntimeError::Operation)?;
                return publish_peer_only_sync_stage(
                    &self.inner.data_dir,
                    &staged,
                    self.inner.configuration.network,
                    staged_status,
                )
                .map_err(RuntimeError::Operation);
            }
        }

        let maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let mut header_state_lock =
            HeaderStateFileLock::exclusive(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let live_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        if live_identity != staged.baseline_storage_identity {
            return Err(RuntimeError::Operation(
                "header sync stage was superseded by another process before publication".to_owned(),
            ));
        }
        let _peer_state = self
            .inner
            .coordination
            .peer_state
            .lock()
            .map_err(|_| RuntimeError::Synchronization("peer state lock"))?;
        let peer_store_path = self
            .inner
            .coordination
            .header_state_base
            .join("peers.sqlite");
        let process_peer_state_path =
            peer_state_lock_path(&peer_store_path).map_err(RuntimeError::Operation)?;
        let _process_peer_state = HeaderStateFileLock::exclusive(&process_peer_state_path)
            .map_err(RuntimeError::Operation)?;
        header_state_lock
            .mark_updating()
            .map_err(RuntimeError::Operation)?;
        self.inner.coordination.begin_maintenance(&maintenance)?;
        let status = publish_header_sync_stage(
            &self.inner.data_dir,
            &staged,
            self.inner.configuration.network,
            self.inner.configuration.sync.resource_cache_limit_bytes,
            staged_status,
        )
        .map_err(RuntimeError::Operation)?;
        let published_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        header_state_lock
            .mark_ready(published_identity)
            .map_err(RuntimeError::Operation)?;
        Ok(status)
    }

    pub fn sync_status(&self) -> Result<SyncStatus, RuntimeError> {
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _header_state_lock =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        read_sync_status(&self.inner.data_dir, self.inner.configuration.network)
            .map_err(RuntimeError::Operation)
    }

    /// Verifies and persists one explicitly configured relay-capable Handshake peer.
    ///
    /// The live version handshake happens before the shared peer-store lock is acquired. The
    /// selected network's endpoint policy is applied to the numeric address, so mainnet/testnet
    /// configuration cannot be used to reach a private address or non-P2P port.
    pub fn add_static_relay_peer(&self, endpoint: &str) -> Result<SyncStatus, RuntimeError> {
        let network_kind = self.inner.configuration.network;
        let network = network_kind.network();
        let addresses = resolve_static_relay_peer_endpoint(endpoint, &network)
            .map_err(RuntimeError::InvalidConfiguration)?;
        let mut verified = None;

        for address in addresses {
            let Ok(version) = hns_p2p::probe_dns_relay_peer(
                address,
                &network,
                self.inner.configuration.sync.timeout,
            ) else {
                continue;
            };
            if version.services & SERVICE_NETWORK == 0
                || version.services & EXPERIMENTAL_DNS_RELAY_SERVICE == 0
            {
                continue;
            }
            verified = Some(address);
            break;
        }

        let Some(address) = verified else {
            return Err(RuntimeError::Operation(
                "no reachable relay-capable Handshake peer was found at that endpoint".to_owned(),
            ));
        };

        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _header_state_lock =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let _peer_state = self
            .inner
            .coordination
            .peer_state
            .lock()
            .map_err(|_| RuntimeError::Synchronization("peer state lock"))?;

        let base = network_base_path(&self.inner.data_dir, network_kind);
        let peer_store_path = base.join("peers.sqlite");
        let process_peer_state_path =
            peer_state_lock_path(&peer_store_path).map_err(RuntimeError::Operation)?;
        let _process_peer_state = HeaderStateFileLock::exclusive(&process_peer_state_path)
            .map_err(RuntimeError::Operation)?;
        let peer_store = SqlitePeerStore::open(peer_store_path)
            .map_err(|error| RuntimeError::Operation(format!("open peer store: {error}")))?;
        let mut peers = peer_store
            .load_manager()
            .map_err(|error| RuntimeError::Operation(format!("load peer store: {error}")))?;
        retain_allowed_peer_endpoints(&mut peers, &network);
        // A relay capability handshake authenticates neither the remote chain
        // height nor a sync target. Persist membership and liveness only.
        peers.record_connection(address, now_unix_seconds());
        peer_store
            .save_manager(&peers)
            .map_err(|error| RuntimeError::Operation(format!("save peer store: {error}")))?;

        let mut status = read_sync_status(&self.inner.data_dir, network_kind)
            .map_err(RuntimeError::Operation)?;
        status.status = "peer_added";
        status.peer_count = peers.len();
        status.peer_groups = peers.address_group_count(now_unix_seconds());
        status.best_peer_height = best_peer_height(&peers);
        Ok(status)
    }

    pub fn clear_resolver_cache(&self) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _header_state_lock =
            HeaderStateFileLock::exclusive(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        self.inner.coordination.begin_maintenance(&maintenance)?;
        clear_resolver_cache_inner(&self.inner.data_dir, self.inner.configuration.network)
            .map_err(RuntimeError::Operation)
    }

    pub fn install_header_snapshot(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<SyncStatus, RuntimeError> {
        let snapshot_path = snapshot_path.as_ref().to_str().ok_or_else(|| {
            RuntimeError::InvalidConfiguration("snapshot must be a UTF-8 path".to_owned())
        })?;
        self.coordinated_header_mutation(|| {
            install_header_snapshot_inner(
                &self.inner.data_dir,
                snapshot_path,
                self.inner.configuration.network,
            )
        })
    }

    pub fn reset_headers_from_peers(&self) -> Result<SyncStatus, RuntimeError> {
        self.coordinated_header_mutation(|| {
            reset_headers_from_peers_inner(&self.inner.data_dir, self.inner.configuration.network)
        })
    }

    fn coordinated_header_mutation(
        &self,
        mutation: impl FnOnce() -> Result<NativeSyncStatus, String>,
    ) -> Result<SyncStatus, RuntimeError> {
        let _sync = self
            .inner
            .coordination
            .sync_lock
            .lock()
            .map_err(|_| RuntimeError::Synchronization("sync lock"))?;
        let _process_sync =
            HeaderStateFileLock::exclusive(&self.inner.coordination.header_sync_lock_path)
                .map_err(RuntimeError::Operation)?;
        let maintenance = self
            .inner
            .coordination
            .maintenance
            .write()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let mut header_state_lock =
            HeaderStateFileLock::exclusive(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let _peer_state = self
            .inner
            .coordination
            .peer_state
            .lock()
            .map_err(|_| RuntimeError::Synchronization("peer state lock"))?;
        let peer_store_path = self
            .inner
            .coordination
            .header_state_base
            .join("peers.sqlite");
        let process_peer_state_path =
            peer_state_lock_path(&peer_store_path).map_err(RuntimeError::Operation)?;
        let _process_peer_state = HeaderStateFileLock::exclusive(&process_peer_state_path)
            .map_err(RuntimeError::Operation)?;
        let baseline =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        header_state_lock
            .mark_updating()
            .map_err(RuntimeError::Operation)?;
        self.inner.coordination.begin_maintenance(&maintenance)?;
        let outcome = mutation().map_err(RuntimeError::Operation)?;
        let next_generation = baseline
            .header_generation
            .max(baseline.peer_generation)
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::Operation(
                    "header mutation publication generation is exhausted".to_owned(),
                )
            })?;
        let mut header_store = SqliteHeaderStore::open(
            self.inner
                .coordination
                .header_state_base
                .join("headers.sqlite"),
        )
        .map_err(|error| RuntimeError::Operation(format!("open mutated header store: {error}")))?;
        header_store
            .set_sync_generation(next_generation)
            .map_err(|error| {
                RuntimeError::Operation(format!("publish mutated header generation: {error}"))
            })?;
        header_store.flush().map_err(|error| {
            RuntimeError::Operation(format!("close mutated header store: {error}"))
        })?;
        let peer_store = SqlitePeerStore::open(peer_store_path).map_err(|error| {
            RuntimeError::Operation(format!("open peer store for header mutation: {error}"))
        })?;
        let peers = peer_store.load_manager().map_err(|error| {
            RuntimeError::Operation(format!("load peer store for header mutation: {error}"))
        })?;
        peer_store
            .replace_manager_with_sync_generation(&peers, next_generation)
            .map_err(|error| {
                RuntimeError::Operation(format!("publish peer mutation generation: {error}"))
            })?;
        let published_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        header_state_lock
            .mark_ready(published_identity)
            .map_err(RuntimeError::Operation)?;

        let mut published =
            read_sync_status(&self.inner.data_dir, self.inner.configuration.network)
                .map_err(RuntimeError::Operation)?;
        published.status = outcome.status;
        published.attempted = outcome.attempted;
        published.successful = outcome.successful;
        published.accepted = outcome.accepted;
        published.failed = outcome.failed;
        published.resource_cache_evicted = outcome.resource_cache_evicted;
        published.failures = outcome.failures;
        Ok(published)
    }

    pub fn proof_details(&self, host_or_url: &str) -> Result<String, RuntimeError> {
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        Ok(hns_proof_details_for_network(
            &self.inner.data_dir,
            host_or_url,
            self.inner.configuration.network,
        ))
    }

    pub fn gateway_request(
        &self,
        request: GatewayHttpRequest,
    ) -> Result<GatewayHttpResponse, RuntimeError> {
        self.validate_gateway_request(&request)?;
        let authority_stamp = self.inner.canonical_authority.admit_direct()?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _header_state_lock =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let storage_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        let header_text = self.gateway_header_text(&request.headers)?;
        let prepared = prepare_gateway_http_response_with_transport(
            GatewayHttpRequestInput {
                data_dir: &self.inner.data_dir,
                method: &request.method,
                scheme: &request.scheme,
                host: &request.host,
                port: request.port,
                path_and_query: &request.path_and_query,
                header_text: &header_text,
                body: &request.body,
            },
            AuthorityOriginTransport::new(
                self.inner.transport.clone(),
                Arc::clone(&self.inner.canonical_authority),
                authority_stamp,
                HeaderStateLease {
                    coordination: Arc::clone(&self.inner.coordination),
                    identity: storage_identity,
                },
            ),
            self.inner.transport.clone(),
            Some(Arc::clone(&self.inner.coordination.peer_state)),
        );
        let PreparedGatewayHttpResponse {
            encoded_http,
            namespace_decision,
        } = prepared;
        let encoded_http = self.inner.canonical_authority.publish_direct_result(
            authority_stamp,
            &self.inner.coordination.namespace_bindings,
            namespace_decision.as_ref(),
            || Ok(encoded_http),
        )?;
        Ok(GatewayHttpResponse { encoded_http })
    }

    pub fn gateway_request_body_to_file(
        &self,
        request: GatewayHttpRequest,
        body_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.validate_gateway_request(&request)?;
        let authority_stamp = self.inner.canonical_authority.admit_direct()?;
        let _maintenance = self
            .inner
            .coordination
            .maintenance
            .read()
            .map_err(|_| RuntimeError::Synchronization("maintenance lock"))?;
        let _header_state_lock =
            HeaderStateFileLock::shared(&self.inner.coordination.header_state_lock_path)
                .map_err(RuntimeError::Operation)?;
        let storage_identity =
            read_header_sync_storage_identity(&self.inner.coordination.header_state_base)
                .map_err(RuntimeError::Operation)?;
        let header_text = self.gateway_header_text(&request.headers)?;
        let target = body_path.as_ref();
        let (staged, staged_file) =
            create_pending_body_file(target).map_err(RuntimeError::Operation)?;
        drop(staged_file);
        fs::remove_file(&staged.path)
            .map_err(|error| RuntimeError::Operation(format!("prepare staged body: {error}")))?;
        let prepared = prepare_gateway_http_response_body_to_file_with_transport(
            GatewayHttpRequestInput {
                data_dir: &self.inner.data_dir,
                method: &request.method,
                scheme: &request.scheme,
                host: &request.host,
                port: request.port,
                path_and_query: &request.path_and_query,
                header_text: &header_text,
                body: &request.body,
            },
            &staged.path,
            AuthorityOriginTransport::new(
                self.inner.transport.clone(),
                Arc::clone(&self.inner.canonical_authority),
                authority_stamp,
                HeaderStateLease {
                    coordination: Arc::clone(&self.inner.coordination),
                    identity: storage_identity,
                },
            ),
            self.inner.transport.clone(),
            Some(Arc::clone(&self.inner.coordination.peer_state)),
        )
        .map_err(RuntimeError::Operation)?;
        let PreparedGatewayFileResponse {
            encoded_head,
            namespace_decision,
        } = prepared;
        self.inner.canonical_authority.publish_direct_result(
            authority_stamp,
            &self.inner.coordination.namespace_bindings,
            namespace_decision.as_ref(),
            || {
                staged.publish(target).map_err(RuntimeError::Operation)?;
                Ok(encoded_head)
            },
        )
    }

    pub fn raw_gateway_request(
        &self,
        request: RawGatewayHttpRequest,
        policy: RuntimePolicy,
    ) -> Result<GatewayHttpResponse, RuntimeError> {
        let address = raw_gateway_request_address(&request);
        let request = match prepare_raw_gateway_request(request) {
            Ok(request) => request,
            Err(rejection) => {
                return Ok(GatewayHttpResponse {
                    encoded_http: plain_response_with_address(
                        rejection.status,
                        rejection.reason,
                        rejection.detail,
                        Some(&address),
                    ),
                });
            }
        };
        // Post-admission/final-publication rejection must propagate without
        // synthesizing a fresh, unstamped response around stale work.
        self.with_policy_operation(policy, move |runtime| runtime.gateway_request(request))
    }

    pub fn raw_gateway_request_body_to_file(
        &self,
        request: RawGatewayHttpRequest,
        policy: RuntimePolicy,
        body_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let address = raw_gateway_request_address(&request);
        let body_path = body_path.as_ref();
        let request = match prepare_raw_gateway_request(request) {
            Ok(request) => request,
            Err(rejection) => {
                return plain_response_to_file_with_address(
                    rejection.status,
                    rejection.reason,
                    rejection.detail,
                    Some(&address),
                    body_path,
                )
                .map_err(RuntimeError::Operation);
            }
        };
        match self.with_policy_operation(policy, move |runtime| {
            runtime.gateway_request_body_to_file(request, body_path)
        }) {
            Ok(head) => Ok(head),
            // Once an origin request has started, runtime failures (including
            // durable namespace-binding failures) must not be converted into
            // a caller-visible download file. The staged writer below keeps
            // the destination untouched and this typed error propagates.
            Err(error) => Err(error),
        }
    }

    fn validate_gateway_request(&self, request: &GatewayHttpRequest) -> Result<(), RuntimeError> {
        if request.body.len() > DEFAULT_MAX_REQUEST_BODY_BYTES {
            return Err(RuntimeError::InvalidConfiguration(format!(
                "gateway request body exceeds {DEFAULT_MAX_REQUEST_BODY_BYTES} bytes"
            )));
        }
        let header_bytes = request
            .headers
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .and_then(|total| total.checked_add(4))
            });
        if header_bytes.is_none_or(|bytes| bytes > MAX_GATEWAY_HEADER_TEXT_BYTES) {
            return Err(RuntimeError::InvalidConfiguration(format!(
                "gateway request headers exceed {MAX_GATEWAY_HEADER_TEXT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn gateway_header_text(&self, headers: &[(String, String)]) -> Result<String, RuntimeError> {
        let policy = self.policy()?;
        let mut header_text = String::new();
        for (name, value) in headers {
            if !is_valid_gateway_header_name(name) || !is_valid_gateway_header_value(value) {
                return Err(RuntimeError::InvalidConfiguration(
                    "gateway request contains an invalid header".to_owned(),
                ));
            }
            if is_reserved_hns_header(name) {
                continue;
            }
            header_text.push_str(name);
            header_text.push_str(": ");
            header_text.push_str(value);
            header_text.push_str("\r\n");
        }
        header_text.push_str(HNS_GATEWAY_P2P_DNS_RELAY_HEADER);
        header_text.push_str(if policy.experimental_p2p_dns_relay {
            ": 1\r\n"
        } else {
            ": 0\r\n"
        });
        if let Some(endpoint) = policy.hns_doh_resolver.as_deref() {
            header_text.push_str(HNS_GATEWAY_DOH_RESOLVER_HEADER);
            header_text.push_str(": ");
            header_text.push_str(endpoint);
            header_text.push_str("\r\n");
        }
        if policy.resolution_mode == ResolutionMode::Strict {
            header_text.push_str(HNS_GATEWAY_STRICT_MODE_HEADER);
            header_text.push_str(": 1\r\n");
        }
        if policy.stateless_dane_certificates {
            header_text.push_str(HNS_GATEWAY_STATELESS_DANE_HEADER);
            header_text.push_str(": 1\r\n");
        }
        header_text.push_str(HNS_GATEWAY_NETWORK_HEADER);
        header_text.push_str(": ");
        header_text.push_str(self.inner.configuration.network.as_str());
        header_text.push_str("\r\n");
        Ok(header_text)
    }
}

fn prepare_raw_gateway_request(
    request: RawGatewayHttpRequest,
) -> Result<GatewayHttpRequest, RawGatewayRequestRejection> {
    if request.body.len() > DEFAULT_MAX_REQUEST_BODY_BYTES {
        return Err(RawGatewayRequestRejection {
            status: 413,
            reason: "Origin Request Too Large",
            detail: "Origin request body exceeds the configured gateway limit.",
        });
    }
    let port = u16::try_from(request.port).map_err(|_| RawGatewayRequestRejection {
        status: 400,
        reason: "Bad Request",
        detail: "origin port is invalid",
    })?;
    let headers = parse_untrusted_gateway_headers(&request.header_text).map_err(|detail| {
        RawGatewayRequestRejection {
            status: 400,
            reason: "Bad Request",
            detail,
        }
    })?;
    Ok(GatewayHttpRequest {
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port,
        path_and_query: request.path_and_query,
        headers,
        body: request.body,
    })
}

fn parse_untrusted_gateway_headers(
    header_text: &str,
) -> Result<Vec<(String, String)>, &'static str> {
    if header_text.len() > MAX_GATEWAY_HEADER_TEXT_BYTES {
        return Err("request headers are too large");
    }
    let mut headers = Vec::new();
    for line in header_text.split("\r\n").filter(|line| !line.is_empty()) {
        let Some(separator) = line.find(':') else {
            return Err("request header is malformed");
        };
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if !is_valid_gateway_header_name(name) || !is_valid_gateway_header_value(value) {
            return Err("request header is invalid");
        }
        if !is_reserved_hns_header(name) {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok(headers)
}

fn raw_gateway_request_address(request: &RawGatewayHttpRequest) -> String {
    let scheme = request.scheme.to_ascii_lowercase();
    let port = match (scheme.as_str(), request.port) {
        ("http" | "ws", 80) | ("https" | "wss", 443) => String::new(),
        (_, port) => format!(":{port}"),
    };
    let path = if request.path_and_query.is_empty() {
        "/"
    } else {
        &request.path_and_query
    };
    format!("{scheme}://{}{port}{path}", request.host)
}

const CANONICAL_AUTHORITY_REVOKED: &str = "canonical browser authority revoked in-flight work";
const CONNECT_READINESS_RECHECK_INTERVAL: Duration = Duration::from_secs(1);
#[derive(Clone)]
struct AuthorityOriginTransport {
    inner: TcpHttpTransport,
    authority: Arc<CanonicalAuthority>,
    stamp: CanonicalWorkStamp,
    header_state: HeaderStateLease,
}

#[derive(Clone)]
struct HeaderStateLease {
    coordination: Arc<RuntimeCoordination>,
    identity: HeaderSyncStorageIdentity,
}

impl HeaderStateLease {
    fn acquire(&self) -> std::io::Result<HeaderStateFileLock> {
        let mut guard = HeaderStateFileLock::try_shared(&self.coordination.header_state_lock_path)
            .map_err(|_| canonical_authority_publication_error())?
            .ok_or_else(canonical_authority_publication_error)?;
        if guard
            .ready_identity()
            .map_err(|_| canonical_authority_publication_error())?
            != self.identity
        {
            return Err(canonical_authority_publication_error());
        }
        Ok(guard)
    }
}

impl AuthorityOriginTransport {
    fn new(
        inner: TcpHttpTransport,
        authority: Arc<CanonicalAuthority>,
        stamp: CanonicalWorkStamp,
        header_state: HeaderStateLease,
    ) -> Self {
        Self {
            inner,
            authority,
            stamp,
            header_state,
        }
    }

    fn require_current(&self) -> Result<(), TransportError> {
        if self.authority.admits(self.stamp) {
            Ok(())
        } else {
            Err(canonical_authority_transport_error())
        }
    }
}

impl OriginTransport for AuthorityOriginTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        self.require_current()?;
        let response = self.inner.fetch(request)?;
        self.require_current()?;
        Ok(response)
    }

    fn open_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        self.require_current()?;
        let tunnel = self.inner.open_tunnel(request)?;
        self.require_current()?;
        Ok(OriginTunnel {
            response_head: tunnel.response_head,
            stream: Box::new(AuthorityBoundTunnel {
                inner: tunnel.stream,
                authority: Arc::clone(&self.authority),
                stamp: self.stamp,
                header_state: self.header_state.clone(),
            }),
            dane_decision: tunnel.dane_decision,
            tls_inspection: tunnel.tls_inspection,
        })
    }

    fn open_webpki_passthrough(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginWebPkiPassthrough, TransportError> {
        self.require_current()?;
        let passthrough = self.inner.open_webpki_passthrough(request)?;
        self.require_current()?;
        let lease = Arc::new(AuthorityPassthroughLease::new(
            Arc::clone(&self.authority),
            self.stamp,
            self.header_state.clone(),
        ));
        Ok(OriginWebPkiPassthrough {
            peer_addr: passthrough.peer_addr,
            reader: Box::new(AuthorityBoundPassthroughReader {
                inner: passthrough.reader,
                lease: Arc::clone(&lease),
            }),
            writer: Box::new(AuthorityBoundPassthroughWriter {
                inner: passthrough.writer,
                lease,
            }),
            shutdown: passthrough.shutdown,
        })
    }

    fn open_webpki_passthrough_candidates(
        &self,
        requests: &[OriginRequest],
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        self.require_current()?;
        let mut before_dial = || self.require_current();
        let selected = self
            .inner
            .open_webpki_passthrough_candidates_with_guard(requests, &mut before_dial)?;
        self.require_current()?;
        let lease = Arc::new(AuthorityPassthroughLease::new(
            Arc::clone(&self.authority),
            self.stamp,
            self.header_state.clone(),
        ));
        Ok(SelectedOriginWebPkiPassthrough {
            transport: OriginWebPkiPassthrough {
                peer_addr: selected.transport.peer_addr,
                reader: Box::new(AuthorityBoundPassthroughReader {
                    inner: selected.transport.reader,
                    lease: Arc::clone(&lease),
                }),
                writer: Box::new(AuthorityBoundPassthroughWriter {
                    inner: selected.transport.writer,
                    lease,
                }),
                shutdown: selected.transport.shutdown,
            },
        })
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        self.require_current()?;
        // Stage privately so a generation/policy/readiness change cannot
        // leave caller-visible partial download bytes behind.
        let mut staged = Vec::new();
        let response = self.inner.fetch_to_writer(request, &mut staged)?;
        self.require_current()?;
        self.authority.with_current(self.stamp, || {
            body.write_all(&staged)
                .map_err(|error| TransportError::Io(error.to_string()))
        })?;
        Ok(response)
    }
}

struct AuthorityBoundTunnel {
    inner: Box<dyn ReadWrite>,
    authority: Arc<CanonicalAuthority>,
    stamp: CanonicalWorkStamp,
    header_state: HeaderStateLease,
}

struct AuthorityBoundPassthroughReader {
    inner: Box<dyn Read + Send>,
    lease: Arc<AuthorityPassthroughLease>,
}

impl Read for AuthorityBoundPassthroughReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let header_state = self.lease.header_state.acquire()?;
        self.lease.require_current()?;
        drop(header_state);
        let read = self.inner.read(buffer)?;
        let _header_state = self.lease.header_state.acquire()?;
        self.lease.require_current()?;
        Ok(read)
    }
}

struct AuthorityBoundPassthroughWriter {
    inner: Box<dyn Write + Send>,
    lease: Arc<AuthorityPassthroughLease>,
}

impl Write for AuthorityBoundPassthroughWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let _header_state = self.lease.header_state.acquire()?;
        self.lease.require_current()?;
        let written = self.inner.write(buffer)?;
        self.lease.require_current()?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _header_state = self.lease.header_state.acquire()?;
        self.lease.require_current()?;
        self.inner.flush()?;
        self.lease.require_current()
    }
}

struct AuthorityPassthroughLease {
    authority: Arc<CanonicalAuthority>,
    stamp: CanonicalWorkStamp,
    header_state: HeaderStateLease,
    next_readiness_check_ms: AtomicU64,
    readiness_check_in_progress: AtomicBool,
    revoked: AtomicBool,
}

impl AuthorityPassthroughLease {
    fn new(
        authority: Arc<CanonicalAuthority>,
        stamp: CanonicalWorkStamp,
        header_state: HeaderStateLease,
    ) -> Self {
        Self {
            authority,
            stamp,
            header_state,
            next_readiness_check_ms: AtomicU64::new(
                connect_authority_millis()
                    .saturating_add(connect_readiness_recheck_interval_millis()),
            ),
            readiness_check_in_progress: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
        }
    }

    fn require_current(&self) -> std::io::Result<()> {
        if self.revoked.load(Ordering::Acquire)
            || !self.authority.admits_without_readiness(self.stamp)
        {
            self.revoked.store(true, Ordering::Release);
            return Err(canonical_authority_publication_error());
        }
        let now = connect_authority_millis();
        if now < self.next_readiness_check_ms.load(Ordering::Acquire)
            || self
                .readiness_check_in_progress
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Ok(());
        }
        let current = self.authority.admits(self.stamp);
        if !current {
            self.revoked.store(true, Ordering::Release);
        }
        self.next_readiness_check_ms.store(
            now.saturating_add(connect_readiness_recheck_interval_millis()),
            Ordering::Release,
        );
        self.readiness_check_in_progress
            .store(false, Ordering::Release);
        if current {
            Ok(())
        } else {
            Err(canonical_authority_publication_error())
        }
    }
}

fn connect_authority_millis() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn connect_readiness_recheck_interval_millis() -> u64 {
    u64::try_from(CONNECT_READINESS_RECHECK_INTERVAL.as_millis()).unwrap_or(u64::MAX)
}

impl AuthorityBoundTunnel {
    fn require_current(&self) -> std::io::Result<()> {
        if self.authority.admits(self.stamp) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                ErrorKind::ConnectionAborted,
                CANONICAL_AUTHORITY_REVOKED,
            ))
        }
    }
}

impl Read for AuthorityBoundTunnel {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let header_state = self.header_state.acquire()?;
        self.require_current()?;
        drop(header_state);
        let read = self.inner.read(buffer)?;
        let _header_state = self.header_state.acquire()?;
        self.require_current()?;
        Ok(read)
    }
}

impl Write for AuthorityBoundTunnel {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let _header_state = self.header_state.acquire()?;
        self.require_current()?;
        let written = self.inner.write(buffer)?;
        self.require_current()?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _header_state = self.header_state.acquire()?;
        self.require_current()?;
        self.inner.flush()?;
        self.require_current()
    }
}

struct MaintenanceBoundConnectReader {
    inner: Box<dyn Read + Send>,
    coordination: Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    publication_signal: Arc<AtomicBool>,
}

impl Read for MaintenanceBoundConnectReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let maintenance = connect_publication_guard(
            &self.coordination,
            self.maintenance_epoch,
            &self.publication_signal,
        )?;
        drop(maintenance);
        let read = self.inner.read(buffer)?;
        let _maintenance = connect_publication_guard(
            &self.coordination,
            self.maintenance_epoch,
            &self.publication_signal,
        )?;
        Ok(read)
    }
}

struct MaintenanceBoundConnectWriter {
    inner: Box<dyn Write + Send>,
    coordination: Arc<RuntimeCoordination>,
    maintenance_epoch: MaintenanceEpoch,
    publication_signal: Arc<AtomicBool>,
}

impl Write for MaintenanceBoundConnectWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let _maintenance = connect_publication_guard(
            &self.coordination,
            self.maintenance_epoch,
            &self.publication_signal,
        )?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _maintenance = connect_publication_guard(
            &self.coordination,
            self.maintenance_epoch,
            &self.publication_signal,
        )?;
        self.inner.flush()
    }
}

fn connect_publication_guard<'a>(
    coordination: &'a RuntimeCoordination,
    maintenance_epoch: MaintenanceEpoch,
    publication_signal: &AtomicBool,
) -> std::io::Result<RwLockReadGuard<'a, ()>> {
    if !publication_signal.load(Ordering::Acquire)
        || coordination.maintenance_epoch.load(Ordering::Acquire) != maintenance_epoch.0
    {
        return Err(canonical_authority_publication_error());
    }
    let maintenance = coordination
        .maintenance
        .try_read()
        .map_err(|_| canonical_authority_publication_error())?;
    if !publication_signal.load(Ordering::Acquire)
        || coordination.publication_epoch(&maintenance) != Some(maintenance_epoch)
    {
        return Err(canonical_authority_publication_error());
    }
    Ok(maintenance)
}

struct RuntimeConnectShutdown(Arc<dyn OriginPassthroughShutdown>);

impl ProxyConnectShutdown for RuntimeConnectShutdown {
    fn shutdown(&self) {
        self.0.shutdown();
    }
}

fn canonical_authority_transport_error() -> TransportError {
    TransportError::Io(CANONICAL_AUTHORITY_REVOKED.to_owned())
}

fn canonical_authority_publication_error() -> std::io::Error {
    std::io::Error::new(ErrorKind::ConnectionAborted, CANONICAL_AUTHORITY_REVOKED)
}

struct PreparedRuntimeGateway {
    gateway: Gateway<AndroidGatewayResolver, AuthorityOriginTransport>,
    request: GatewayRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    fallback_marker: FallbackMarker,
    dns_trace: DnsTraceRecorder,
}

impl BrowserRuntime {
    fn acquire_proxy_maintenance<'a>(
        &'a self,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyMaintenanceGuard<'a>, ProxyBackendError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(ProxyBackendError::Cancelled);
            }
            match self.inner.coordination.maintenance.try_read() {
                Ok(guard) => {
                    let Some(epoch) = self.inner.coordination.publication_epoch(&guard) else {
                        return Err(ProxyBackendError::Internal);
                    };
                    let Some(mut header_state_lock) = HeaderStateFileLock::try_shared(
                        &self.inner.coordination.header_state_lock_path,
                    )
                    .map_err(|_| ProxyBackendError::Internal)?
                    else {
                        drop(guard);
                        if cancellation.wait_cancelled_timeout(PROXY_MAINTENANCE_POLL_INTERVAL) {
                            return Err(ProxyBackendError::Cancelled);
                        }
                        continue;
                    };
                    let recorded_identity = header_state_lock
                        .ready_identity()
                        .map_err(|_| ProxyBackendError::Internal)?;
                    let storage_identity = read_header_sync_storage_identity(
                        &self.inner.coordination.header_state_base,
                    )
                    .map_err(|_| ProxyBackendError::Internal)?;
                    if storage_identity != recorded_identity {
                        return Err(ProxyBackendError::Internal);
                    }
                    return Ok(ProxyMaintenanceGuard {
                        _guard: guard,
                        _header_state_lock: header_state_lock,
                        epoch,
                        storage_identity,
                    });
                }
                Err(TryLockError::Poisoned(_)) => return Err(ProxyBackendError::Internal),
                Err(TryLockError::WouldBlock) => {
                    if cancellation.wait_cancelled_timeout(PROXY_MAINTENANCE_POLL_INTERVAL) {
                        return Err(ProxyBackendError::Cancelled);
                    }
                }
            }
        }
    }

    fn prepare_proxy_gateway(
        &self,
        request: &GatewayHttpRequest,
        authority_stamp: CanonicalWorkStamp,
        storage_identity: HeaderSyncStorageIdentity,
    ) -> Result<PreparedRuntimeGateway, RuntimeError> {
        self.validate_gateway_request(request)?;
        let header_text = self.gateway_header_text(&request.headers)?;
        let parsed_headers = parse_gateway_headers(&header_text)
            .map_err(|error| RuntimeError::InvalidConfiguration(error.to_owned()))?;
        let network = parsed_headers.network;
        let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
        let input = GatewayHttpRequestInput {
            data_dir: &self.inner.data_dir,
            method: &request.method,
            scheme: &request.scheme,
            host: &request.host,
            port: request.port,
            path_and_query: &request.path_and_query,
            header_text: &header_text,
            body: &request.body,
        };
        let gateway_request = gateway_request(&input, parsed_headers.headers);
        let base = network_base_path(&self.inner.data_dir, network);
        fs::create_dir_all(&base).map_err(|error| {
            RuntimeError::Operation(format!("create gateway directory: {error}"))
        })?;
        let values = SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .map_err(|error| RuntimeError::Operation(format!("open resource cache: {error}")))?;
        let fallback_marker = FallbackMarker::default();
        let dns_trace = DnsTraceRecorder::default();
        let resolver = android_gateway_resolver(
            base.clone(),
            values,
            GatewayResolverContext {
                network,
                mode,
                configured_hns_doh: parsed_headers.configured_hns_doh,
                experimental_p2p_dns_relay: parsed_headers.experimental_p2p_dns_relay,
                peer_state: Some(Arc::clone(&self.inner.coordination.peer_state)),
                relay: Some(self.inner.coordination.relay.clone()),
                http: self.inner.transport.clone(),
            },
            fallback_marker.clone(),
            dns_trace.clone(),
        );
        let stateless_dane =
            stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Strict,
                stateless_dane,
                allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
                allow_unsafe_origin_ports: network == NetworkKind::Regtest,
                ..GatewayConfig::default()
            },
            resolver,
            AuthorityOriginTransport::new(
                self.inner.transport.clone(),
                Arc::clone(&self.inner.canonical_authority),
                authority_stamp,
                HeaderStateLease {
                    coordination: Arc::clone(&self.inner.coordination),
                    identity: storage_identity,
                },
            ),
        )
        .map_err(|error| RuntimeError::Operation(format!("create gateway: {error}")))?;
        Ok(PreparedRuntimeGateway {
            gateway,
            request: gateway_request,
            network,
            mode,
            fallback_marker,
            dns_trace,
        })
    }
}

impl ProxyBackend for RuntimeProxyBackend {
    fn open_connect(
        &self,
        request: LoopbackProxyRequest,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyConnectOpen, ProxyBackendError> {
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let maintenance = self.runtime.acquire_proxy_maintenance(cancellation)?;
        let maintenance_epoch = maintenance.epoch();
        let storage_identity = maintenance.storage_identity();
        let authority_stamp = self
            .runtime
            .inner
            .canonical_authority
            .admit(self.authority_generation)
            .map_err(runtime_error_to_proxy_backend)?
            .with_storage_identity(storage_identity);
        drop(maintenance);
        let request = gateway_request_from_proxy(request);
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let prepared =
            match self
                .runtime
                .prepare_proxy_gateway(&request, authority_stamp, storage_identity)
            {
                Ok(prepared) => prepared,
                Err(_error) => {
                    require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                    return Ok(ProxyConnectOpen::Intercept);
                }
            };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let passthrough = match prepared
            .gateway
            .open_browser_connect_with_failure_context(&prepared.request)
        {
            Ok(GatewayConnectDisposition::Intercept) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(ProxyConnectOpen::Intercept);
            }
            Err(failure) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(if gateway_failure_selected_browser_webpki(&failure) {
                    ProxyConnectOpen::WebPkiUnavailable
                } else {
                    ProxyConnectOpen::Intercept
                });
            }
            Ok(GatewayConnectDisposition::WebPkiPassthrough(passthrough)) => *passthrough,
        };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let canonical_status = canonical_status_for_gateway_success(
            &self.runtime,
            authority_stamp,
            prepared.network,
            Some(&passthrough.namespace_decision),
            passthrough.resolution.secure,
            &passthrough.origin_request,
            &DaneDecision::WebPkiFallback,
            OriginTlsObservation::BrowserWebPkiPassthrough,
            &prepared.dns_trace,
        );
        let observation_id =
            match publishable_webpki_connect_observation(canonical_status, |canonical_status| {
                self.runtime.inner.canonical_statuses.insert_with_epoch(
                    &self.runtime.inner.canonical_authority,
                    authority_stamp,
                    canonical_status,
                    maintenance_epoch,
                )
            }) {
                Ok(observation_id) => observation_id,
                Err(disposition) => return Ok(disposition),
            };
        let publication_signal = Arc::new(AtomicBool::new(false));
        let publication_permit = canonical_connect_publication_permit(
            &self.runtime.inner.canonical_authority,
            &self.runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            authority_stamp,
            &self.runtime.inner.coordination.namespace_bindings,
            passthrough.namespace_decision,
            Arc::clone(&publication_signal),
        );
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let hns_transport::OriginWebPkiPassthrough {
            peer_addr: _,
            reader,
            writer,
            shutdown,
        } = passthrough.transport;
        Ok(ProxyConnectOpen::WebPkiPassthrough(ProxyConnectTunnel {
            reader: Box::new(MaintenanceBoundConnectReader {
                inner: reader,
                coordination: Arc::clone(&self.runtime.inner.coordination),
                maintenance_epoch,
                publication_signal: Arc::clone(&publication_signal),
            }),
            writer: Box::new(MaintenanceBoundConnectWriter {
                inner: writer,
                coordination: Arc::clone(&self.runtime.inner.coordination),
                maintenance_epoch,
                publication_signal,
            }),
            shutdown: Arc::new(RuntimeConnectShutdown(shutdown)),
            observation_id: Some(observation_id),
            correlation_epoch: maintenance_epoch.0,
            publication_permit,
        }))
    }

    fn execute(
        &self,
        request: LoopbackProxyRequest,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyResponse, ProxyBackendError> {
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let maintenance = self.runtime.acquire_proxy_maintenance(cancellation)?;
        let maintenance_epoch = maintenance.epoch();
        let storage_identity = maintenance.storage_identity();
        let authority_stamp = self
            .runtime
            .inner
            .canonical_authority
            .admit(self.authority_generation)
            .map_err(runtime_error_to_proxy_backend)?
            .with_storage_identity(storage_identity);
        drop(maintenance);
        let request = gateway_request_from_proxy(request);
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let prepared =
            match self
                .runtime
                .prepare_proxy_gateway(&request, authority_stamp, storage_identity)
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                    return Ok(proxy_error_response_from_backend(
                        &self.runtime,
                        authority_stamp,
                        maintenance_epoch,
                        storage_identity,
                        &request,
                        runtime_error_to_proxy_backend(error),
                    ));
                }
            };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let response = match prepared
            .gateway
            .handle_with_failure_context(&prepared.request)
        {
            Ok(response) => response,
            Err(failure) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(proxy_error_response_from_gateway(
                    &self.runtime,
                    authority_stamp,
                    maintenance_epoch,
                    storage_identity,
                    &request,
                    prepared.network,
                    prepared.mode,
                    &failure,
                    &prepared.fallback_marker,
                    &prepared.dns_trace,
                ));
            }
        };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let response = match proxy_response_from_gateway(
            &self.runtime,
            authority_stamp,
            maintenance_epoch,
            storage_identity,
            &request,
            prepared.network,
            prepared.mode,
            response,
            &prepared.fallback_marker,
            &prepared.dns_trace,
        ) {
            Ok(response) => response,
            Err(error) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(proxy_error_response_from_backend(
                    &self.runtime,
                    authority_stamp,
                    maintenance_epoch,
                    storage_identity,
                    &request,
                    error,
                ));
            }
        };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        Ok(response)
    }

    fn open_tunnel(
        &self,
        request: LoopbackProxyRequest,
        cancellation: &ProxyCancellationToken,
    ) -> Result<ProxyTunnelOpen, ProxyBackendError> {
        if cancellation.is_cancelled() {
            return Err(ProxyBackendError::Cancelled);
        }
        let maintenance = self.runtime.acquire_proxy_maintenance(cancellation)?;
        let maintenance_epoch = maintenance.epoch();
        let storage_identity = maintenance.storage_identity();
        let authority_stamp = self
            .runtime
            .inner
            .canonical_authority
            .admit(self.authority_generation)
            .map_err(runtime_error_to_proxy_backend)?
            .with_storage_identity(storage_identity);
        drop(maintenance);
        let request = gateway_request_from_proxy(request);
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let prepared =
            match self
                .runtime
                .prepare_proxy_gateway(&request, authority_stamp, storage_identity)
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                    return Ok(ProxyTunnelOpen::Response(
                        proxy_error_response_from_backend(
                            &self.runtime,
                            authority_stamp,
                            maintenance_epoch,
                            storage_identity,
                            &request,
                            runtime_error_to_proxy_backend(error),
                        ),
                    ));
                }
            };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let response = match prepared
            .gateway
            .handle_tunnel_with_failure_context(&prepared.request)
        {
            Ok(response) => response,
            Err(failure) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(ProxyTunnelOpen::Response(
                    proxy_error_response_from_gateway(
                        &self.runtime,
                        authority_stamp,
                        maintenance_epoch,
                        storage_identity,
                        &request,
                        prepared.network,
                        prepared.mode,
                        &failure,
                        &prepared.fallback_marker,
                        &prepared.dns_trace,
                    ),
                ));
            }
        };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        let tunnel = match proxy_tunnel_from_gateway(
            &self.runtime,
            authority_stamp,
            maintenance_epoch,
            storage_identity,
            &request,
            prepared.network,
            prepared.mode,
            response,
            &prepared.fallback_marker,
            &prepared.dns_trace,
        ) {
            Ok(tunnel) => tunnel,
            Err(error) => {
                require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
                return Ok(ProxyTunnelOpen::Response(
                    proxy_error_response_from_backend(
                        &self.runtime,
                        authority_stamp,
                        maintenance_epoch,
                        storage_identity,
                        &request,
                        error,
                    ),
                ));
            }
        };
        require_current_proxy_work(&self.runtime, authority_stamp, cancellation)?;
        Ok(ProxyTunnelOpen::Tunnel(tunnel))
    }
}

fn gateway_failure_selected_browser_webpki(failure: &GatewayFailure) -> bool {
    failure
        .namespace_decision()
        .and_then(NamespaceDecision::selected_plan)
        .is_some_and(|plan| {
            plan.namespace() == Namespace::Icann
                && matches!(
                    plan.tls_policy(),
                    TlsTrustPolicy::WebPkiAuthenticatedAbsence
                        | TlsTrustPolicy::WebPkiInsecureDelegation
                )
        })
}

fn publishable_webpki_connect_observation(
    canonical_status: CanonicalStatusAvailability,
    insert: impl FnOnce(CanonicalStatusAvailability) -> Option<u64>,
) -> Result<u64, ProxyConnectOpen> {
    if !matches!(&canonical_status, CanonicalStatusAvailability::Available(_)) {
        return Err(ProxyConnectOpen::WebPkiUnavailable);
    }
    insert(canonical_status).ok_or(ProxyConnectOpen::WebPkiUnavailable)
}

fn require_current_proxy_work(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    cancellation: &ProxyCancellationToken,
) -> Result<(), ProxyBackendError> {
    if cancellation.is_cancelled() {
        return Err(ProxyBackendError::Cancelled);
    }
    if let Some(identity) = stamp.storage_identity {
        HeaderStateLease {
            coordination: Arc::clone(&runtime.inner.coordination),
            identity,
        }
        .acquire()
        .map_err(|_| ProxyBackendError::Cancelled)?;
    }
    if runtime.inner.canonical_authority.admits(stamp) {
        Ok(())
    } else {
        Err(ProxyBackendError::Cancelled)
    }
}

fn gateway_request_from_proxy(request: LoopbackProxyRequest) -> GatewayHttpRequest {
    GatewayHttpRequest {
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path_and_query: request.path_and_query,
        headers: request
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect(),
        body: match request.body {
            ProxyRequestBody::Empty => Vec::new(),
            ProxyRequestBody::Bytes(bytes) => bytes,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn proxy_response_from_gateway(
    runtime: &BrowserRuntime,
    authority_stamp: CanonicalWorkStamp,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    response: hns_gateway::GatewayResponse,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> Result<ProxyResponse, ProxyBackendError> {
    let input = runtime_gateway_input(runtime, request);
    let namespace_decision_for_publication = response.namespace_decision.clone();
    let canonical_status = canonical_status_for_gateway_success(
        runtime,
        authority_stamp,
        network,
        response.namespace_decision.as_ref(),
        response.resolution.secure,
        &response.origin_request,
        &response.origin.dane_decision,
        OriginTlsObservation::RustValidated(response.origin.tls_inspection.is_some()),
        dns_trace,
    );
    let resolver_policy = fallback_marker
        .used()
        .then_some("user-configured-recursive-hns-doh");
    let selected_namespace = response
        .namespace_decision
        .as_ref()
        .and_then(NamespaceDecision::selected_namespace);
    let security_path = security_path_name(
        &input,
        response.origin_request.port,
        response.origin_request.tls.service_transport,
        &response.origin.dane_decision,
        selected_namespace,
        &dns_trace.snapshot(),
    );
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        Some(&response.resolution),
        TlsTraceInput {
            validation: Some(&response.origin_request.tls),
            decision: Some(&response.origin.dane_decision),
            inspection: response.origin.tls_inspection.as_ref(),
            origin_address: response.origin_request.connect_host.as_deref(),
        },
        None,
        fallback_marker,
        dns_trace,
    );
    let mut headers = sanitize_typed_origin_headers(response.origin.headers)?;
    append_runtime_response_metadata(
        &mut headers,
        &response.origin.dane_decision,
        resolver_policy,
        security_path,
        &trace,
    );
    let observation_id = runtime.inner.canonical_statuses.insert_with_epoch(
        &runtime.inner.canonical_authority,
        authority_stamp,
        canonical_status,
        maintenance_epoch,
    );
    Ok(ProxyResponse {
        head: ProxyResponseHead {
            status_code: response.origin.status,
            reason_phrase: "OK".to_owned(),
            headers: proxy_headers(headers),
            observation_id,
        },
        body: ProxyResponseBody::Bytes(response.origin.body),
        publication_permit: canonical_proxy_publication_permit_with_namespace(
            &runtime.inner.canonical_authority,
            &runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            authority_stamp,
            &runtime.inner.coordination.namespace_bindings,
            namespace_decision_for_publication,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn proxy_error_response_from_gateway(
    runtime: &BrowserRuntime,
    authority_stamp: CanonicalWorkStamp,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    failure: &GatewayFailure,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> ProxyResponse {
    let input = runtime_gateway_input(runtime, request);
    let error = failure.error();
    let (status, reason, detail) =
        map_gateway_error_for_namespace(dns_trace.selected_namespace(), error, dns_trace);
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        None,
        TlsTraceInput::default(),
        Some(error),
        fallback_marker,
        dns_trace,
    );
    let document = gateway_error_document(&input, status, reason, detail, dns_trace);
    let mut headers = vec![("Content-Type".to_owned(), document.content_type.to_owned())];
    headers.extend(document.headers);
    append_runtime_response_metadata(&mut headers, &DaneDecision::NoTlsa, None, None, &trace);
    let canonical_status =
        canonical_status_for_gateway_failure(runtime, authority_stamp, network, failure, dns_trace);
    let observation_id = runtime.inner.canonical_statuses.insert_with_epoch(
        &runtime.inner.canonical_authority,
        authority_stamp,
        canonical_status,
        maintenance_epoch,
    );
    ProxyResponse {
        head: ProxyResponseHead {
            status_code: status,
            reason_phrase: reason.to_owned(),
            headers: proxy_headers(headers),
            observation_id,
        },
        body: ProxyResponseBody::Bytes(document.body),
        publication_permit: canonical_proxy_publication_permit(
            &runtime.inner.canonical_authority,
            &runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            authority_stamp,
        ),
    }
}

fn proxy_error_response_from_backend(
    runtime: &BrowserRuntime,
    authority_stamp: CanonicalWorkStamp,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    request: &GatewayHttpRequest,
    error: ProxyBackendError,
) -> ProxyResponse {
    let (status, reason, detail) = match error {
        ProxyBackendError::Cancelled => (
            503,
            "Proxy Request Cancelled",
            "The admitted proxy request was cancelled.",
        ),
        ProxyBackendError::InvalidRequest => (
            400,
            "Invalid Gateway Request",
            "The native gateway rejected the request.",
        ),
        ProxyBackendError::PolicyDenied => (
            403,
            "Gateway Policy Denied",
            "The native gateway policy denied the request.",
        ),
        ProxyBackendError::ResolutionFailed => (
            502,
            "Resolution Failed",
            "Native namespace resolution failed closed.",
        ),
        ProxyBackendError::TlsValidationFailed => (
            502,
            "TLS Validation Failed",
            "Native TLS validation failed closed.",
        ),
        ProxyBackendError::UpstreamUnavailable => (
            502,
            "Upstream Unavailable",
            "The selected upstream was unavailable.",
        ),
        ProxyBackendError::InvalidResponse => (
            502,
            "Invalid Upstream Response",
            "The selected upstream returned an invalid response.",
        ),
        ProxyBackendError::ResponseTooLarge => (
            502,
            "Upstream Response Too Large",
            "The selected upstream response exceeded the configured limit.",
        ),
        ProxyBackendError::UnsupportedUpgrade => (
            501,
            "Protocol Upgrade Unsupported",
            "The native gateway does not support the requested protocol upgrade.",
        ),
        ProxyBackendError::Internal => (
            500,
            "Proxy Internal Error",
            "The native gateway failed closed before response publication.",
        ),
    };
    let input = runtime_gateway_input(runtime, request);
    let address = gateway_request_address(&input);
    let body = plain_response_body(status, reason, detail, Some(&address));
    let headers = vec![(
        "Content-Type".to_owned(),
        "text/plain; charset=utf-8".to_owned(),
    )];
    let observation_id = runtime.inner.canonical_statuses.insert_with_epoch(
        &runtime.inner.canonical_authority,
        authority_stamp,
        CanonicalStatusAvailability::Unavailable(
            CanonicalStatusUnavailableReason::EvidenceUnavailable,
        ),
        maintenance_epoch,
    );
    ProxyResponse {
        head: ProxyResponseHead {
            status_code: status,
            reason_phrase: reason.to_owned(),
            headers: proxy_headers(headers),
            observation_id,
        },
        body: ProxyResponseBody::Bytes(body),
        publication_permit: canonical_proxy_publication_permit(
            &runtime.inner.canonical_authority,
            &runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            authority_stamp,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn proxy_tunnel_from_gateway(
    runtime: &BrowserRuntime,
    authority_stamp: CanonicalWorkStamp,
    maintenance_epoch: MaintenanceEpoch,
    storage_identity: HeaderSyncStorageIdentity,
    request: &GatewayHttpRequest,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    response: hns_gateway::GatewayTunnel,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> Result<ProxyTunnel, ProxyBackendError> {
    let input = runtime_gateway_input(runtime, request);
    let namespace_decision_for_publication = response.namespace_decision.clone();
    let canonical_status = canonical_status_for_gateway_success(
        runtime,
        authority_stamp,
        network,
        response.namespace_decision.as_ref(),
        response.resolution.secure,
        &response.origin_request,
        &response.origin.dane_decision,
        OriginTlsObservation::RustValidated(response.origin.tls_inspection.is_some()),
        dns_trace,
    );
    let resolver_policy = fallback_marker
        .used()
        .then_some("user-configured-recursive-hns-doh");
    let trace = resolution_trace_json(
        &input,
        network,
        mode,
        Some(&response.resolution),
        TlsTraceInput {
            validation: Some(&response.origin_request.tls),
            decision: Some(&response.origin.dane_decision),
            inspection: response.origin.tls_inspection.as_ref(),
            origin_address: response.origin_request.connect_host.as_deref(),
        },
        None,
        fallback_marker,
        dns_trace,
    );
    let parsed = parse_upgrade_response_head(&response.origin.response_head)?;
    let mut headers = sanitize_typed_upgrade_headers(parsed.headers)?;
    append_runtime_response_metadata(
        &mut headers,
        &response.origin.dane_decision,
        resolver_policy,
        None,
        &trace,
    );
    let observation_id = runtime.inner.canonical_statuses.insert_with_epoch(
        &runtime.inner.canonical_authority,
        authority_stamp,
        canonical_status,
        maintenance_epoch,
    );
    Ok(ProxyTunnel {
        head: ProxyResponseHead {
            status_code: parsed.status_code,
            reason_phrase: "Switching Protocols".to_owned(),
            headers: proxy_headers(headers),
            observation_id,
        },
        // A boxed transport trait object is itself a concrete Read + Write +
        // Send value and therefore satisfies the proxy tunnel trait.
        stream: Box::new(response.origin.stream),
        publication_permit: canonical_proxy_publication_permit_with_namespace(
            &runtime.inner.canonical_authority,
            &runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            authority_stamp,
            &runtime.inner.coordination.namespace_bindings,
            namespace_decision_for_publication,
        ),
    })
}

fn canonical_status_for_gateway_failure(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
    failure: &GatewayFailure,
    dns_trace: &DnsTraceRecorder,
) -> CanonicalStatusAvailability {
    let root_states = failure
        .classification_error()
        .and_then(canonical_root_resolution_states);
    match (
        try_canonical_status_for_gateway_failure(runtime, stamp, network, failure, dns_trace),
        root_states,
    ) {
        (Ok(status), Some(root_states)) => CanonicalStatusAvailability::AvailableWithRootStates {
            status: Box::new(status),
            root_states,
        },
        (Ok(status), None) => CanonicalStatusAvailability::Available(Box::new(status)),
        (Err(reason), _) => CanonicalStatusAvailability::Unavailable(reason),
    }
}

fn canonical_root_resolution_states(
    classification: &ClassificationError,
) -> Option<CanonicalRootResolutionStates> {
    let ClassificationError::RootFailed { hns, icann } = classification else {
        return None;
    };
    Some(CanonicalRootResolutionStates::new(
        hns.disposition(),
        icann.disposition(),
    ))
}

fn try_canonical_status_for_gateway_failure(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
    failure: &GatewayFailure,
    dns_trace: &DnsTraceRecorder,
) -> Result<CanonicalBrowserStatus, CanonicalStatusUnavailableReason> {
    if let Some(classification) = failure.classification_error() {
        return canonical_status_for_classification_failure(
            runtime,
            stamp,
            network,
            classification,
        );
    }
    let decision = failure
        .namespace_decision()
        .ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    if !decision.is_fresh_at(now_unix_seconds()) {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }
    if decision.kind() == OutcomeKind::Neither {
        let mut input = canonical_status_base(runtime, stamp, network)?;
        input.namespace_outcome = Some(OutcomeKind::Neither);
        // Shared schema v2 requires the name-free decision fingerprint for a
        // completed Neither decision even though no namespace was selected.
        input.decision_fingerprint = Some(*decision_fingerprint(decision).as_bytes());
        return CanonicalBrowserStatus::new(input)
            .map_err(|_| CanonicalStatusUnavailableReason::SchemaValidationRejected);
    }
    if !gateway_failure_is_post_selection_dane(failure.error()) {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }
    let selected = decision
        .selected_namespace()
        .ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    let selected_plan = decision
        .selected_plan()
        .ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    if selected_plan.tls_policy() != TlsTrustPolicy::Dane {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }

    let mut input = canonical_status_base(runtime, stamp, network)?;
    input.namespace_outcome = Some(decision.kind());
    input.selected_namespace = Some(selected);
    input.selection_reason = decision.selection_reason();
    input.decision_fingerprint = Some(*decision_fingerprint(decision).as_bytes());
    input.evidence.dnssec = CanonicalEvidenceState::Verified;
    input.evidence.tlsa = CanonicalEvidenceState::Verified;
    input.evidence.dane = CanonicalEvidenceState::Failed;
    // A certificate-association mismatch does not prove an SNI mismatch.
    // Leave SNI unavailable until the transport carries separate typed SNI
    // evidence instead of fabricating it from a generic TLS failure.
    input.evidence.origin_sni = CanonicalEvidenceState::Unavailable;

    match (selected, selected_plan.provenance()) {
        (
            Namespace::Hns,
            EvidenceProvenance::Hns {
                network: evidence_network,
                tree_root,
                height,
            },
        ) if canonical_hns_network_matches(network, *evidence_network) => {
            input.chain_anchor = Some(CanonicalChainAnchor {
                height: *height,
                tree_root: *tree_root,
            });
            input.evidence.hns_proof = CanonicalEvidenceState::Verified;
            input.evidence.chain_current = CanonicalEvidenceState::Verified;
            input.actual_transport =
                canonical_hns_actual_transport_for_plan(decision.query(), selected_plan, dns_trace)
                    .unwrap_or(CanonicalResolutionTransport::Unavailable);
        }
        (
            Namespace::Icann,
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
        ) => {
            input.actual_transport = CanonicalResolutionTransport::ValidatingIcannDoh;
            input.icann_tls_action = Some(CanonicalIcannTlsAction::FailClosed);
            input.icann_dnssec_status = Some(CanonicalIcannDnssecStatus::Secure);
        }
        _ => return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable),
    }

    CanonicalBrowserStatus::new(input)
        .map_err(|_| CanonicalStatusUnavailableReason::SchemaValidationRejected)
}

fn canonical_status_for_classification_failure(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
    classification: &ClassificationError,
) -> Result<CanonicalBrowserStatus, CanonicalStatusUnavailableReason> {
    let ClassificationError::RootFailed { hns, icann } = classification else {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    };
    let hns_failure = hns.failure().map(RootFailure::kind);
    let icann_failure = icann.failure().map(RootFailure::kind);
    if hns_failure.is_none() && icann_failure.is_none() {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }

    let mut input = canonical_status_base(runtime, stamp, network)?;
    input.hns_root_failure = hns_failure;
    input.icann_root_failure = icann_failure;
    if let Some(failure) = hns_failure {
        match failure {
            RootFailureKind::StaleHnsAnchor | RootFailureKind::StaleEvidence => {
                input.evidence.chain_current = CanonicalEvidenceState::Failed;
            }
            RootFailureKind::BogusDnssec => {
                input.evidence.dnssec = CanonicalEvidenceState::Failed;
            }
            RootFailureKind::IndeterminateDnssec => {
                input.evidence.dnssec = CanonicalEvidenceState::Unavailable;
            }
            RootFailureKind::Timeout
            | RootFailureKind::Transport
            | RootFailureKind::UnauthenticatedResolver
            | RootFailureKind::MalformedResponse
            | RootFailureKind::Unsupported
            | RootFailureKind::Cancelled
            | RootFailureKind::Internal => {}
        }
    }
    if let Some(failure) = icann_failure {
        input.actual_transport = CanonicalResolutionTransport::ValidatingIcannDoh;
        input.icann_tls_action = Some(CanonicalIcannTlsAction::FailClosed);
        input.evidence.tlsa = CanonicalEvidenceState::Unavailable;
        input.evidence.dane = CanonicalEvidenceState::Unavailable;
        match failure {
            RootFailureKind::BogusDnssec => {
                input.evidence.dnssec = CanonicalEvidenceState::Failed;
                input.icann_dnssec_status = Some(CanonicalIcannDnssecStatus::Bogus);
            }
            RootFailureKind::IndeterminateDnssec => {
                input.evidence.dnssec = CanonicalEvidenceState::Unavailable;
                input.icann_dnssec_status = Some(CanonicalIcannDnssecStatus::Indeterminate);
            }
            RootFailureKind::Timeout
            | RootFailureKind::Transport
            | RootFailureKind::UnauthenticatedResolver
            | RootFailureKind::MalformedResponse
            | RootFailureKind::Unsupported
            | RootFailureKind::Cancelled
            | RootFailureKind::Internal
            | RootFailureKind::StaleEvidence => {
                input.evidence.dnssec = CanonicalEvidenceState::Unavailable;
            }
            RootFailureKind::StaleHnsAnchor => {
                return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
            }
        }
    }

    CanonicalBrowserStatus::new(input)
        .map_err(|_| CanonicalStatusUnavailableReason::SchemaValidationRejected)
}

fn canonical_status_base(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
) -> Result<CanonicalStatusInput, CanonicalStatusUnavailableReason> {
    let (runtime_snapshot, policy) = runtime
        .inner
        .canonical_authority
        .status_context(stamp)
        .map_err(|_| CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    Ok(CanonicalStatusInput {
        runtime: runtime_snapshot,
        network: canonical_network(network),
        policy,
        chain_anchor: None,
        actual_transport: CanonicalResolutionTransport::Unavailable,
        identities: CanonicalTransportIdentities::default(),
        registry_profile: policy.config().wire_profile,
        registry_fingerprint: [0; 32],
        protocol_version: 0,
        provider_readiness: CanonicalProviderReadiness::from_policy(policy),
        rate_limits: CanonicalRateLimitState::default(),
        evidence: CanonicalValidationEvidence::not_attempted(),
        namespace_outcome: None,
        hns_root_failure: None,
        icann_root_failure: None,
        selected_namespace: None,
        selection_reason: None,
        decision_fingerprint: None,
        icann_tls_action: None,
        icann_dnssec_status: None,
        degraded_reason: None,
        revocation_reason: None,
        unsupported_evidence: Vec::new(),
    })
}

fn gateway_failure_is_post_selection_dane(error: &GatewayError) -> bool {
    matches!(error, GatewayError::Transport(TransportError::DaneFailed))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginTlsObservation {
    RustValidated(bool),
    BrowserWebPkiPassthrough,
}

#[allow(clippy::too_many_arguments)]
fn canonical_status_for_gateway_success(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
    decision: Option<&NamespaceDecision>,
    resolution_secure: bool,
    origin_request: &OriginRequest,
    dane_decision: &DaneDecision,
    tls_observation: OriginTlsObservation,
    dns_trace: &DnsTraceRecorder,
) -> CanonicalStatusAvailability {
    match try_canonical_status_for_gateway_success(
        runtime,
        stamp,
        network,
        decision,
        resolution_secure,
        origin_request,
        dane_decision,
        tls_observation,
        dns_trace,
    ) {
        Ok(status) => CanonicalStatusAvailability::Available(Box::new(status)),
        Err(reason) => CanonicalStatusAvailability::Unavailable(reason),
    }
}

#[allow(clippy::too_many_arguments)]
fn try_canonical_status_for_gateway_success(
    runtime: &BrowserRuntime,
    stamp: CanonicalWorkStamp,
    network: NetworkKind,
    decision: Option<&NamespaceDecision>,
    resolution_secure: bool,
    origin_request: &OriginRequest,
    dane_decision: &DaneDecision,
    tls_observation: OriginTlsObservation,
    dns_trace: &DnsTraceRecorder,
) -> Result<CanonicalBrowserStatus, CanonicalStatusUnavailableReason> {
    let decision = decision.ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    if !decision.is_fresh_at(now_unix_seconds()) {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }
    let selected = decision
        .selected_namespace()
        .ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    let selected_plan = decision
        .selected_plan()
        .ok_or(CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    let fingerprint = decision_fingerprint(decision);
    if origin_request.tls.namespace_fingerprint.as_deref() != Some(fingerprint.to_hex().as_str()) {
        return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
    }

    let actual_transport = match selected {
        Namespace::Icann => CanonicalResolutionTransport::ValidatingIcannDoh,
        Namespace::Hns => {
            canonical_hns_actual_transport_for_plan(decision.query(), selected_plan, dns_trace)?
        }
    };
    if actual_transport == CanonicalResolutionTransport::HandshakeP2pDnsRelay {
        // The legacy relay records a peer and retry count but not the exact
        // negotiated registry fingerprint/protocol version required by
        // schema v2. Static local constants are not negotiated identity.
        return Err(CanonicalStatusUnavailableReason::P2pRegistryIdentityUnavailable);
    }

    let not_attempted = CanonicalEvidenceState::NotAttempted;
    let verified = CanonicalEvidenceState::Verified;
    let unavailable = CanonicalEvidenceState::Unavailable;
    let mut evidence = CanonicalValidationEvidence::not_attempted();
    let mut chain_anchor = None;
    let mut icann_tls_action = None;
    let mut icann_dnssec_status = None;
    let uses_tls = matches!(
        origin_request.scheme.to_ascii_lowercase().as_str(),
        "https" | "wss"
    );

    match (selected, selected_plan.provenance()) {
        (
            Namespace::Hns,
            EvidenceProvenance::Hns {
                network: evidence_network,
                tree_root,
                height,
            },
        ) if canonical_hns_network_matches(network, *evidence_network) => {
            chain_anchor = Some(CanonicalChainAnchor {
                height: *height,
                tree_root: *tree_root,
            });
            evidence.hns_proof = verified;
            evidence.chain_current = verified;
            if uses_tls {
                if !resolution_secure
                    || tls_observation != OriginTlsObservation::RustValidated(true)
                    || origin_request.tls.browser_tls_decision.is_some()
                    || !origin_request.tls.dnssec_secure
                    || origin_request.tls.tlsa_records.is_empty()
                    || origin_request.tls.tlsa_source != Some(TlsaRecordSource::NativeTlsa)
                    || !matches!(dane_decision, DaneDecision::Matched(_))
                {
                    return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
                }
                evidence.dnssec = verified;
                evidence.tlsa = verified;
                evidence.dane = verified;
                evidence.origin_sni = verified;
            } else {
                if !matches!(dane_decision, DaneDecision::NoTlsa) {
                    return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
                }
                evidence.dnssec = if resolution_secure {
                    verified
                } else {
                    not_attempted
                };
                evidence.tlsa = not_attempted;
                evidence.dane = not_attempted;
                evidence.origin_sni = not_attempted;
            }
        }
        (Namespace::Icann, EvidenceProvenance::IcannDoh { chain_state }) => {
            // The validating resolver's secure/proven-insecure disposition is
            // itself verified typed evidence. HNS-only fields deliberately
            // remain absent for an ICANN-selected response.
            evidence.dnssec = verified;
            if uses_tls && tls_observation == OriginTlsObservation::RustValidated(false) {
                return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
            }
            match (
                selected_plan.tls_policy(),
                origin_request.tls.browser_tls_decision,
                dane_decision,
                chain_state,
            ) {
                (
                    TlsTrustPolicy::Dane,
                    Some(BrowserTlsDecision::EnforceDane { record_count }),
                    DaneDecision::Matched(_),
                    IcannChainState::Secure,
                ) if uses_tls
                    && tls_observation == OriginTlsObservation::RustValidated(true)
                    && origin_request.tls.dnssec_secure
                    && record_count.get() == origin_request.tls.tlsa_records.len()
                    && origin_request.tls.tlsa_source == Some(TlsaRecordSource::NativeTlsa) =>
                {
                    evidence.tlsa = verified;
                    evidence.dane = verified;
                    evidence.origin_sni = verified;
                    icann_tls_action = Some(CanonicalIcannTlsAction::EnforceDane);
                    icann_dnssec_status = Some(CanonicalIcannDnssecStatus::Secure);
                }
                (
                    TlsTrustPolicy::WebPkiAuthenticatedAbsence,
                    Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
                    DaneDecision::WebPkiFallback,
                    IcannChainState::Secure,
                ) if uses_tls
                    && origin_request.tls.dnssec_secure
                    && origin_request.tls.tlsa_records.is_empty() =>
                {
                    evidence.tlsa = unavailable;
                    evidence.dane = not_attempted;
                    evidence.origin_sni = match tls_observation {
                        OriginTlsObservation::RustValidated(true) => verified,
                        OriginTlsObservation::BrowserWebPkiPassthrough => not_attempted,
                        OriginTlsObservation::RustValidated(false) => {
                            return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
                        }
                    };
                    icann_tls_action = Some(CanonicalIcannTlsAction::WebPkiAuthenticatedAbsence);
                    icann_dnssec_status = Some(CanonicalIcannDnssecStatus::Secure);
                }
                (
                    TlsTrustPolicy::WebPkiInsecureDelegation,
                    Some(BrowserTlsDecision::WebPkiInsecureDelegation),
                    DaneDecision::WebPkiFallback,
                    IcannChainState::ProvenInsecure,
                ) if uses_tls
                    && !origin_request.tls.dnssec_secure
                    && origin_request.tls.tlsa_records.is_empty() =>
                {
                    evidence.tlsa = unavailable;
                    evidence.dane = not_attempted;
                    evidence.origin_sni = match tls_observation {
                        OriginTlsObservation::RustValidated(true) => verified,
                        OriginTlsObservation::BrowserWebPkiPassthrough => not_attempted,
                        OriginTlsObservation::RustValidated(false) => {
                            return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
                        }
                    };
                    icann_tls_action = Some(CanonicalIcannTlsAction::WebPkiInsecureDelegation);
                    icann_dnssec_status = Some(CanonicalIcannDnssecStatus::InsecureDelegation);
                }
                (TlsTrustPolicy::Cleartext, None, DaneDecision::NoTlsa, chain_state)
                    if !uses_tls =>
                {
                    evidence.tlsa = not_attempted;
                    evidence.dane = not_attempted;
                    evidence.origin_sni = not_attempted;
                    icann_dnssec_status = Some(match chain_state {
                        IcannChainState::Secure => CanonicalIcannDnssecStatus::Secure,
                        IcannChainState::ProvenInsecure => {
                            CanonicalIcannDnssecStatus::InsecureDelegation
                        }
                    });
                }
                _ => return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable),
            }
        }
        _ => return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable),
    }

    let (runtime_snapshot, policy) = runtime
        .inner
        .canonical_authority
        .status_context(stamp)
        .map_err(|_| CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
    CanonicalBrowserStatus::new(CanonicalStatusInput {
        runtime: runtime_snapshot,
        network: canonical_network(network),
        policy,
        chain_anchor,
        actual_transport,
        identities: CanonicalTransportIdentities::default(),
        registry_profile: policy.config().wire_profile,
        registry_fingerprint: [0; 32],
        protocol_version: 0,
        provider_readiness: CanonicalProviderReadiness::from_policy(policy),
        rate_limits: CanonicalRateLimitState::default(),
        evidence,
        namespace_outcome: Some(decision.kind()),
        hns_root_failure: None,
        icann_root_failure: None,
        selected_namespace: Some(selected),
        selection_reason: decision.selection_reason(),
        decision_fingerprint: Some(*fingerprint.as_bytes()),
        icann_tls_action,
        icann_dnssec_status,
        degraded_reason: None,
        revocation_reason: None,
        unsupported_evidence: Vec::new(),
    })
    .map_err(|_| CanonicalStatusUnavailableReason::SchemaValidationRejected)
}

fn canonical_hns_actual_transport_for_plan(
    query: &OriginQuery,
    selected_plan: &ValidatedOriginPlan,
    dns_trace: &DnsTraceRecorder,
) -> Result<CanonicalResolutionTransport, CanonicalStatusUnavailableReason> {
    let events = dns_trace.snapshot();
    let protocol = if selected_plan.tls_policy() == TlsTrustPolicy::Dane {
        let owner = TlsaOwner::derive(
            query.host().as_str(),
            selected_plan.service().effective_port().get(),
            canonical_tlsa_transport(selected_plan.service().transport()),
        )
        .map_err(|_| CanonicalStatusUnavailableReason::EvidenceUnavailable)?;
        successful_dns_path(
            &events,
            owner.resolver_name(),
            RecordType::Tlsa,
            Namespace::Hns,
        )
    } else {
        successful_dns_path_for_namespace(
            &events,
            selected_plan.endpoint_target().as_str(),
            &[RecordType::A, RecordType::Aaaa],
            Namespace::Hns,
        )
    };
    let Some(protocol) = protocol else {
        if has_hns_dns_transport_event(&events) {
            return Err(CanonicalStatusUnavailableReason::EvidenceUnavailable);
        }
        return Ok(CanonicalResolutionTransport::LocalHnsProof);
    };

    match protocol {
        "udp53" => Ok(CanonicalResolutionTransport::DirectAuthoritativeUdp),
        "tcp53" => Ok(CanonicalResolutionTransport::DirectAuthoritativeTcp),
        "authoritative_doh" => Ok(CanonicalResolutionTransport::AuthenticatedAuthoritativeDoh),
        "p2p_dns_relay" => Ok(CanonicalResolutionTransport::HandshakeP2pDnsRelay),
        "user_configured_recursive_hns_doh" => {
            Ok(CanonicalResolutionTransport::UserConfiguredRecursiveHnsDoh)
        }
        _ => Err(CanonicalStatusUnavailableReason::EvidenceUnavailable),
    }
}

fn has_hns_dns_transport_event(events: &[DnsTraceEvent]) -> bool {
    events
        .iter()
        .any(|event| dns_protocol_namespace(event.protocol) == Some(Namespace::Hns))
}

const fn canonical_tlsa_transport(transport: ServiceTransport) -> TlsaTransport {
    match transport {
        ServiceTransport::Tcp => TlsaTransport::Tcp,
        ServiceTransport::Udp => TlsaTransport::Udp,
    }
}

fn canonical_hns_network_matches(network: NetworkKind, evidence: HnsNetwork) -> bool {
    matches!(
        (network, evidence),
        (NetworkKind::Mainnet, HnsNetwork::Mainnet)
            | (NetworkKind::Testnet, HnsNetwork::Testnet)
            | (NetworkKind::Regtest, HnsNetwork::Regtest)
    )
}

const fn canonical_network(network: NetworkKind) -> CanonicalNetwork {
    match network {
        NetworkKind::Mainnet => CanonicalNetwork::Mainnet,
        NetworkKind::Testnet => CanonicalNetwork::Testnet,
        NetworkKind::Regtest => CanonicalNetwork::Regtest,
    }
}

fn runtime_gateway_input<'a>(
    runtime: &'a BrowserRuntime,
    request: &'a GatewayHttpRequest,
) -> GatewayHttpRequestInput<'a> {
    GatewayHttpRequestInput {
        data_dir: &runtime.inner.data_dir,
        method: &request.method,
        scheme: &request.scheme,
        host: &request.host,
        port: request.port,
        path_and_query: &request.path_and_query,
        header_text: "",
        body: &request.body,
    }
}

fn sanitize_typed_origin_headers(
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, ProxyBackendError> {
    let nominated = connection_nominated_response_headers(&headers)?;
    Ok(headers
        .into_iter()
        .filter(|(name, _)| {
            !suppressed_origin_response_header(name)
                && !nominated.contains(&name.to_ascii_lowercase())
        })
        .collect())
}

fn sanitize_typed_upgrade_headers(
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, ProxyBackendError> {
    let nominated = connection_nominated_response_headers(&headers)?;
    let mut headers: Vec<_> = headers
        .into_iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("upgrade")
                && !suppressed_origin_response_header(name)
                && !nominated.contains(&name.to_ascii_lowercase())
        })
        .collect();
    headers.push(("Connection".to_owned(), "Upgrade".to_owned()));
    headers.push(("Upgrade".to_owned(), "websocket".to_owned()));
    Ok(headers)
}

fn connection_nominated_response_headers(
    headers: &[(String, String)],
) -> Result<HashSet<String>, ProxyBackendError> {
    let mut nominated = HashSet::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        for token in value.split(',').map(str::trim) {
            if !is_valid_gateway_header_name(token) {
                return Err(ProxyBackendError::InvalidResponse);
            }
            nominated.insert(token.to_ascii_lowercase());
        }
    }
    Ok(nominated)
}

fn append_runtime_response_metadata(
    headers: &mut Vec<(String, String)>,
    decision: &DaneDecision,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) {
    if let Some(policy) = hns_tls_policy_header(decision) {
        headers.push(("X-HNS-TLS-Policy".to_owned(), policy.to_owned()));
    }
    if let Some(policy) = resolver_policy {
        headers.push(("X-HNS-Resolver-Policy".to_owned(), policy.to_owned()));
    }
    if let Some(path) = security_path {
        headers.push((HNS_SECURITY_PATH_HEADER.to_owned(), path.to_owned()));
    }
    headers.push((
        HNS_RESOLVER_MODE_HEADER.to_owned(),
        trace_mode(trace_json).to_owned(),
    ));
    headers.push((
        HNS_DOH_FALLBACK_HEADER.to_owned(),
        trace_doh_fallback(trace_json).to_owned(),
    ));
    headers.push((
        HNS_RESOLUTION_TRACE_HEADER.to_owned(),
        trace_json.to_owned(),
    ));
}

fn proxy_headers(headers: Vec<(String, String)>) -> Vec<ProxyHeader> {
    headers
        .into_iter()
        .map(|(name, value)| ProxyHeader::new(name, value))
        .collect()
}

struct ParsedUpgradeResponseHead {
    status_code: u16,
    headers: Vec<(String, String)>,
}

fn parse_upgrade_response_head(
    bytes: &[u8],
) -> Result<ParsedUpgradeResponseHead, ProxyBackendError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_PROXY_UPGRADE_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(bytes)
        .map_err(|_error| ProxyBackendError::InvalidResponse)?;
    let httparse::Status::Complete(consumed) = parsed else {
        return Err(ProxyBackendError::InvalidResponse);
    };
    if consumed != bytes.len() || !matches!(response.version, Some(0 | 1)) {
        return Err(ProxyBackendError::InvalidResponse);
    }
    let status_code = response.code.ok_or(ProxyBackendError::InvalidResponse)?;
    if status_code != 101 {
        return Err(ProxyBackendError::InvalidResponse);
    }
    let headers = response
        .headers
        .iter()
        .map(|header| {
            let value = std::str::from_utf8(header.value)
                .map_err(|_error| ProxyBackendError::InvalidResponse)?;
            Ok((header.name.to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<Vec<_>, ProxyBackendError>>()?;
    let connection_upgrade = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
    });
    let upgrade_values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        .map(|(_, value)| value.as_str())
        .collect();
    if !connection_upgrade
        || upgrade_values.len() != 1
        || !upgrade_values[0].eq_ignore_ascii_case("websocket")
    {
        return Err(ProxyBackendError::InvalidResponse);
    }
    Ok(ParsedUpgradeResponseHead {
        status_code,
        headers,
    })
}

fn runtime_error_to_proxy_backend(error: RuntimeError) -> ProxyBackendError {
    match error {
        RuntimeError::InvalidConfiguration(_) => ProxyBackendError::InvalidRequest,
        RuntimeError::Operation(_) | RuntimeError::Synchronization(_) => {
            ProxyBackendError::Internal
        }
    }
}

fn is_reserved_hns_header(name: &str) -> bool {
    name.get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("X-HNS-"))
}

fn is_valid_gateway_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_gateway_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

struct ParsedGatewayHeaders {
    headers: Vec<(String, String)>,
    strict_hns_mode: bool,
    configured_hns_doh: Option<HnsDohEndpoint>,
    experimental_p2p_dns_relay: bool,
    stateless_dane_certificates: bool,
    network: NetworkKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayResolutionMode {
    Strict,
    Compatibility,
}

impl GatewayResolutionMode {
    fn from_strict_hns_mode(strict_hns_mode: bool) -> Self {
        if strict_hns_mode {
            Self::Strict
        } else {
            Self::Compatibility
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Compatibility => "compatibility",
        }
    }
}

pub fn parse_network_kind(value: &str) -> Result<NetworkKind, String> {
    value
        .parse()
        .map_err(|_| format!("unsupported Handshake network: {value}"))
}

fn network_base_path(data_dir: &str, network: NetworkKind) -> PathBuf {
    match network {
        NetworkKind::Mainnet => Path::new(data_dir).join("hns"),
        NetworkKind::Testnet => Path::new(data_dir).join("hns-testnet"),
        NetworkKind::Regtest => Path::new(data_dir).join("hns-regtest"),
    }
}

fn chain_for_network(
    store: SqliteHeaderStore,
    network: NetworkKind,
) -> HeaderChain<SqliteHeaderStore> {
    match network {
        NetworkKind::Mainnet => HeaderChain::new(store),
        NetworkKind::Testnet | NetworkKind::Regtest => {
            HeaderChain::with_difficulty_policy(store, DifficultyPolicy::Permissive)
        }
    }
}

fn seed_peers_for_network(
    peers: &mut hns_p2p::PeerManager,
    network: &hns_core::network::Network,
    network_kind: NetworkKind,
) -> Result<usize, hns_p2p::P2pError> {
    if !network.dns_seeds.is_empty() {
        let source = DnsSeedPeerSource::from_network(network);
        let discovered = source.discover()?;
        return Ok(peers.seed(
            discovered
                .into_iter()
                .filter(|address| is_allowed_peer_endpoint(network, *address)),
        ));
    }

    if network_kind == NetworkKind::Regtest {
        let source = StaticPeerSource::new([
            SocketAddr::from((Ipv4Addr::LOCALHOST, network.port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, network.port)),
        ]);
        let discovered = source.discover()?;
        return Ok(peers.seed(
            discovered
                .into_iter()
                .filter(|address| is_allowed_peer_endpoint(network, *address)),
        ));
    }

    Ok(0)
}

fn resolve_static_relay_peer_endpoint(
    endpoint: &str,
    network: &hns_core::network::Network,
) -> Result<Vec<SocketAddr>, String> {
    let normalized = normalize_static_relay_peer_endpoint(endpoint)?;
    let address = normalized
        .parse::<SocketAddr>()
        .map_err(|_| "enter one relay peer as an IP address and port".to_owned())?;
    if !is_allowed_peer_endpoint(network, address) {
        return Err("the relay peer endpoint is not allowed for this Handshake network".to_owned());
    }
    Ok(vec![address])
}

fn normalize_static_relay_peer_endpoint(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty()
        || endpoint.len() > MAX_STATIC_RELAY_PEER_ENDPOINT_BYTES
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("enter one relay peer as an IP address and port".to_owned());
    }

    let (host, port_text, bracketed_ipv6) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, port_text) = rest
            .split_once("]:")
            .filter(|(_, port)| !port.contains(':') && !port.contains(']'))
            .ok_or_else(|| "enter an IPv6 relay peer as [address]:port".to_owned())?;
        (host, port_text, true)
    } else {
        let (host, port_text) = endpoint
            .rsplit_once(':')
            .filter(|(host, _)| !host.contains(':'))
            .ok_or_else(|| "enter one relay peer as an IP address and port".to_owned())?;
        (host, port_text, false)
    };
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "the relay peer port must be between 1 and 65535".to_owned())?;

    if bracketed_ipv6 {
        if host.contains('%') {
            return Err("scoped IPv6 relay peer addresses are not supported".to_owned());
        }
        let address = host
            .parse::<Ipv6Addr>()
            .map_err(|_| "enter a valid bracketed IPv6 relay peer address".to_owned())?;
        return Ok(format!("[{address}]:{port}"));
    }

    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(format!("{address}:{port}"));
    }
    Err("enter a valid IPv4 relay peer address".to_owned())
}

fn retain_allowed_peer_endpoints(
    peers: &mut hns_p2p::PeerManager,
    network: &hns_core::network::Network,
) -> usize {
    peers.retain(|peer| is_allowed_peer_endpoint(network, peer.address))
}

fn allowed_peer_count(peers: &hns_p2p::PeerManager, network: &hns_core::network::Network) -> usize {
    peers
        .iter()
        .filter(|peer| is_allowed_peer_endpoint(network, peer.address))
        .count()
}

fn sync_checkpoints_for_network(network: NetworkKind) -> Vec<hns_chain::HeaderCheckpoint> {
    match network {
        NetworkKind::Mainnet => mainnet_sync_checkpoints(),
        NetworkKind::Testnet | NetworkKind::Regtest => Vec::new(),
    }
}

fn estimated_tip_height_for_network(network: NetworkKind, now: u64) -> Option<u32> {
    match network {
        NetworkKind::Mainnet => estimated_mainnet_tip_height(now),
        NetworkKind::Testnet | NetworkKind::Regtest => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HnsDohEndpoint {
    host: String,
    port: u16,
    path_and_query: String,
}

impl HnsDohEndpoint {
    fn display(&self) -> String {
        if self.port == 443 {
            format!("https://{}{}", self.host, self.path_and_query)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path_and_query)
        }
    }
}

/// Validates and canonicalizes the explicit recursive HNS DoH recovery
/// endpoint accepted by browser policy. A blank value disables the recovery
/// path. The endpoint hostname is intentionally restricted to an ordinary
/// ICANN DNS name: runtime bootstrap is performed through the built-in
/// validating ICANN DoH path and never through the operating-system resolver.
pub fn normalize_configured_hns_doh_resolver(
    value: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    parse_configured_hns_doh_endpoint(value).map(|endpoint| Some(endpoint.display()))
}

fn parse_configured_hns_doh_endpoint(value: &str) -> Result<HnsDohEndpoint, String> {
    if value.len() > MAX_CONFIGURED_HNS_DOH_URL_BYTES {
        return Err(format!(
            "configured HNS DoH URL exceeds {MAX_CONFIGURED_HNS_DOH_URL_BYTES} bytes"
        ));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("configured HNS DoH URL contains whitespace or control bytes".to_owned());
    }
    if value.contains('#') {
        return Err("configured HNS DoH URL must not contain a fragment".to_owned());
    }

    let uri = value
        .parse::<http::Uri>()
        .map_err(|_| "configured HNS DoH URL is invalid".to_owned())?;
    if !uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        return Err("configured HNS DoH URL must use https".to_owned());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "configured HNS DoH URL must contain a hostname".to_owned())?;
    if authority.as_str().contains('@') {
        return Err("configured HNS DoH URL must not contain credentials".to_owned());
    }
    let raw_host = authority.host();
    if raw_host.parse::<IpAddr>().is_ok() {
        return Err(
            "configured HNS DoH URL must use a WebPKI-authenticated ICANN hostname".to_owned(),
        );
    }
    let host = CanonicalHost::parse(raw_host)
        .map_err(|_| "configured HNS DoH URL hostname is invalid".to_owned())?;
    if !host.as_str().contains('.') || is_browser_special_use_host(host.as_str()) {
        return Err("configured HNS DoH URL must use a non-special-use ICANN hostname".to_owned());
    }
    let port = authority.port_u16().unwrap_or(443);
    if is_browser_blocked_port(port) {
        return Err(format!(
            "configured HNS DoH URL port {port} is blocked by browser network policy"
        ));
    }
    let path_and_query = uri
        .path_and_query()
        .map(|path| path.as_str())
        .filter(|path| !path.is_empty())
        .unwrap_or("/");
    if !path_and_query.starts_with('/') {
        return Err("configured HNS DoH URL path is invalid".to_owned());
    }

    Ok(HnsDohEndpoint {
        host: host.as_str().to_owned(),
        port,
        path_and_query: path_and_query.to_owned(),
    })
}

struct GatewayProofProvider {
    base: PathBuf,
    values: SqliteResourceValueProvider,
    network: NetworkKind,
    preferred_peers: usize,
    timeout: Duration,
    seed_on_empty: bool,
    peer_state: Option<Arc<Mutex<()>>>,
    proof_peer: Option<Arc<Mutex<Option<SocketAddr>>>>,
    lineage: HnsProofLineage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HnsProofObservation {
    anchor: ResourceValueAnchor,
    exists: bool,
    observed_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Clone, Debug, Default)]
struct HnsProofLineage {
    state: Arc<Mutex<HnsProofLineageState>>,
}

#[derive(Debug, Default)]
struct HnsProofLineageState {
    observations: HashMap<String, HnsProofObservation>,
    inconsistent_roots: HashSet<String>,
}

impl HnsProofLineage {
    fn record(
        &self,
        root_name: &str,
        observation: HnsProofObservation,
    ) -> Result<(), ResolverError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        if let Some(current) = state.observations.get_mut(root_name) {
            if current.anchor != observation.anchor || current.exists != observation.exists {
                state.inconsistent_roots.insert(root_name.to_owned());
                return Ok(());
            }
            current.observed_at_unix = current.observed_at_unix.max(observation.observed_at_unix);
            current.expires_at_unix = current.expires_at_unix.min(observation.expires_at_unix);
            if current.expires_at_unix <= current.observed_at_unix {
                state.inconsistent_roots.insert(root_name.to_owned());
            }
        } else {
            state.observations.insert(root_name.to_owned(), observation);
        }
        Ok(())
    }

    fn exact(&self, root_name: &str) -> Result<Option<HnsProofObservation>, ResolverError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        if state.inconsistent_roots.contains(root_name) {
            return Err(ResolverError::ProofNameMismatch);
        }
        Ok(state.observations.get(root_name).copied())
    }
}

impl GatewayProofProvider {
    fn new(base: PathBuf, values: SqliteResourceValueProvider, network: NetworkKind) -> Self {
        Self {
            base,
            values,
            network,
            preferred_peers: DEFAULT_GATEWAY_PROOF_PEERS,
            timeout: DEFAULT_GATEWAY_PROOF_TIMEOUT,
            seed_on_empty: true,
            peer_state: None,
            proof_peer: None,
            lineage: HnsProofLineage::default(),
        }
    }

    fn with_peer_state(mut self, peer_state: Option<Arc<Mutex<()>>>) -> Self {
        self.peer_state = peer_state;
        self
    }

    fn with_proof_peer(mut self, proof_peer: Arc<Mutex<Option<SocketAddr>>>) -> Self {
        self.proof_peer = Some(proof_peer);
        self
    }

    fn with_lineage(mut self, lineage: HnsProofLineage) -> Self {
        self.lineage = lineage;
        self
    }

    fn cached_records(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        let verified = self.values.prove_resource_value(root_name, name_hash)?;
        if verified.root_name != root_name || verified.name_hash != name_hash || !verified.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if local_chain_lacks_authoritative_tree_root(&self.base, self.network)? {
            return Err(ResolverError::LocalChainNotCurrent);
        }
        if !self.anchor_matches_authoritative_tree_root(verified.anchor)? {
            return Err(ResolverError::ProofUnavailable);
        }
        let anchor = verified.anchor.ok_or(ResolverError::ProofUnavailable)?;
        let observed_at_unix = now_unix_seconds();
        self.lineage.record(
            root_name,
            HnsProofObservation {
                anchor,
                exists: verified.value.is_some(),
                observed_at_unix,
                expires_at_unix: observed_at_unix
                    .saturating_add(HNS_NAMESPACE_EVIDENCE_TTL_SECONDS),
            },
        )?;
        ProvenNameRecords::from_verified_resource_value(verified)
    }

    fn anchor_matches_authoritative_tree_root(
        &self,
        anchor: Option<ResourceValueAnchor>,
    ) -> Result<bool, ResolverError> {
        let Some(anchor) = anchor else {
            return Ok(false);
        };
        hns_anchor_matches_authoritative_tree_root(&self.base, self.network, anchor)
    }

    fn fetch_and_store_live_proof(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<(), ResolverError> {
        if local_chain_lacks_authoritative_tree_root(&self.base, self.network)? {
            return Err(ResolverError::LocalChainNotCurrent);
        }
        let peer_store_path = self.base.join("peers.sqlite");
        let process_peer_state_path =
            peer_state_lock_path(&peer_store_path).map_err(ResolverError::Storage)?;
        let authority = authoritative_tree_root_header(&self.base, self.network)?;
        let network = self.network.network();
        let (mut peers, baseline_peers, selected) = {
            let _peer_state = match self.peer_state.as_ref() {
                Some(peer_state) => Some(
                    peer_state
                        .lock()
                        .map_err(|_| ResolverError::CachePoisoned)?,
                ),
                None => None,
            };
            let _process_peer_state = HeaderStateFileLock::exclusive(&process_peer_state_path)
                .map_err(ResolverError::Storage)?;
            let peer_store = SqlitePeerStore::open(&peer_store_path)
                .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
            let mut peers = peer_store
                .load_manager()
                .map_err(|error| ResolverError::Storage(format!("load peer store: {error}")))?;
            let peer_generation = peer_store.sync_generation().map_err(|error| {
                ResolverError::Storage(format!("read peer sync generation: {error}"))
            })?;
            retain_allowed_peer_endpoints(&mut peers, &network);
            if self.seed_on_empty && allowed_peer_count(&peers, &network) == 0 {
                let _ = seed_peers_for_network(&mut peers, &network, self.network);
            }
            peer_store
                .replace_manager_with_sync_generation(&peers, peer_generation)
                .map_err(|error| {
                    ResolverError::Storage(format!("save prepared peer store: {error}"))
                })?;
            let baseline_peers = hns_p2p::PeerManager::from_states(peers.iter().cloned());
            let selected = select_live_proof_peers(
                &peers,
                &network,
                self.preferred_peers,
                now_unix_seconds(),
                authority.height,
            );
            (peers, baseline_peers, selected)
        };
        if selected.is_empty() {
            return Err(ResolverError::ProofUnavailable);
        }

        let now = now_unix_seconds();
        let mut attempted = Vec::new();
        for address in selected {
            attempted.push(address);
            match self.fetch_from_peer(
                address,
                root_name,
                name_hash,
                authority.header.tree_root,
                authority.height,
            ) {
                Ok(()) => {
                    // The proof is verified against our already validated local
                    // tree root. Its transport handshake does not authenticate
                    // the peer's advertised version height, so only refresh
                    // connection health here.
                    peers.record_transport_success(address, now);
                    if let Some(proof_peer) = self.proof_peer.as_ref()
                        && let Ok(mut selected) = proof_peer.lock()
                    {
                        *selected = Some(address);
                    }
                    persist_gateway_proof_peer_updates(
                        &peer_store_path,
                        &process_peer_state_path,
                        self.peer_state.as_ref(),
                        &baseline_peers,
                        &peers,
                        &attempted,
                        &network,
                    )?;
                    return Ok(());
                }
                Err(_) => {
                    peers.record_transient_failure(address);
                }
            }
        }

        persist_gateway_proof_peer_updates(
            &peer_store_path,
            &process_peer_state_path,
            self.peer_state.as_ref(),
            &baseline_peers,
            &peers,
            &attempted,
            &network,
        )?;
        Err(ResolverError::ProofUnavailable)
    }

    fn fetch_from_peer(
        &self,
        address: SocketAddr,
        root_name: &str,
        name_hash: NameHash,
        proof_root: hns_core::Hash,
        proof_height: Height,
    ) -> Result<(), SyncError> {
        let network = self.network.network();
        let mut peer = PeerConnection::connect(address, network, self.timeout)?;
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let remote = peer.handshake(&mut session)?;
        if remote.height < proof_height {
            return Err(SyncError::UnexpectedAction);
        }
        let mut scheduler =
            ProofScheduler::new(UrkelProofVerifier, ResolverResourceSink(&self.values));
        scheduler.request_hash_and_store_at_height(
            &mut peer,
            &mut session,
            root_name,
            proof_root,
            name_hash,
            proof_height,
        )?;
        Ok(())
    }
}

fn persist_gateway_proof_peer_updates(
    peer_store_path: &Path,
    process_peer_state_path: &Path,
    peer_state: Option<&Arc<Mutex<()>>>,
    baseline: &hns_p2p::PeerManager,
    updated: &hns_p2p::PeerManager,
    attempted: &[SocketAddr],
    network: &hns_core::network::Network,
) -> Result<(), ResolverError> {
    let baseline_updates = hns_p2p::PeerManager::from_states(
        attempted
            .iter()
            .filter_map(|address| baseline.get(*address).cloned()),
    );
    let staged_updates = hns_p2p::PeerManager::from_states(
        attempted
            .iter()
            .filter_map(|address| updated.get(*address).cloned()),
    );
    let _peer_state = match peer_state {
        Some(peer_state) => Some(
            peer_state
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?,
        ),
        None => None,
    };
    let _process_peer_state =
        HeaderStateFileLock::exclusive(process_peer_state_path).map_err(ResolverError::Storage)?;
    let peer_store = SqlitePeerStore::open(peer_store_path)
        .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
    let live = peer_store
        .load_manager()
        .map_err(|error| ResolverError::Storage(format!("reload peer store: {error}")))?;
    let generation = peer_store
        .sync_generation()
        .map_err(|error| ResolverError::Storage(format!("read peer sync generation: {error}")))?;
    let merged = merge_staged_peer_manager(&baseline_updates, &staged_updates, &live, network);
    peer_store
        .replace_manager_with_sync_generation(&merged, generation)
        .map_err(|error| ResolverError::Storage(format!("save peer store: {error}")))?;
    Ok(())
}

impl HnsProofProvider for GatewayProofProvider {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        match self.cached_records(root_name, name_hash) {
            Ok(records) => Ok(records),
            Err(ResolverError::ProofUnavailable) => {
                self.fetch_and_store_live_proof(root_name, name_hash)?;
                self.cached_records(root_name, name_hash)
            }
            Err(error) => Err(error),
        }
    }
}

struct AndroidGatewayResolver {
    inner: Box<dyn Resolver>,
}

impl AndroidGatewayResolver {
    fn new(inner: impl Resolver + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }
}

struct BoxedDelegatedResolver {
    inner: Box<dyn DelegatedResolver>,
}

impl BoxedDelegatedResolver {
    fn new(inner: impl DelegatedResolver + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }
}

struct TracedHnsDelegatedResolver<R> {
    inner: R,
    trace: DnsTraceRecorder,
}

impl<R> TracedHnsDelegatedResolver<R> {
    fn new(inner: R, trace: DnsTraceRecorder) -> Self {
        Self { inner, trace }
    }
}

impl<R> DelegatedResolver for TracedHnsDelegatedResolver<R>
where
    R: DelegatedResolver,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        self.trace.record_hns_delegation(delegation);
        self.inner.resolve_delegated(request, delegation)
    }
}

impl DelegatedResolver for BoxedDelegatedResolver {
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        self.inner.resolve_delegated(request, delegation)
    }
}

#[derive(Clone, Debug, Default)]
struct DnsTraceRecorder {
    events: Arc<Mutex<Vec<DnsTraceEvent>>>,
    relay: Arc<Mutex<Option<DnsRelayTraceMetadata>>>,
    hns_delegation: Arc<Mutex<HnsDelegationTraceState>>,
    namespace_resolution: Arc<Mutex<Option<String>>>,
    selected_namespace: Arc<Mutex<Option<Namespace>>>,
}

impl DnsTraceRecorder {
    fn push(&self, event: DnsTraceEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    fn snapshot(&self) -> Vec<DnsTraceEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    fn record_relay(&self, metadata: DnsRelayTraceMetadata) {
        if let Ok(mut relay) = self.relay.lock() {
            *relay = Some(metadata);
        }
    }

    fn relay_snapshot(&self) -> Option<DnsRelayTraceMetadata> {
        self.relay.lock().ok().and_then(|relay| relay.clone())
    }

    fn record_hns_delegation(&self, delegation: &HnsDelegation) {
        let root_name = delegation.root_name.to_ascii_lowercase();
        let valid_owner = DnsName::from_ascii(&root_name)
            .ok()
            .is_some_and(|owner| owner == delegation.owner);
        let mut nameservers = delegation
            .records
            .iter()
            .filter(|record| {
                record.name == delegation.owner
                    && record.class == DNS_CLASS_IN
                    && record.record_type == RecordType::Ns
            })
            .filter_map(canonical_nameserver_target)
            .collect::<Vec<_>>();
        nameservers.sort();
        nameservers.dedup();
        if let Ok(mut recorded) = self.hns_delegation.lock() {
            if recorded.conflicted {
                return;
            }
            let observation = HnsDelegationTraceMetadata {
                root_name,
                nameservers,
            };
            match &recorded.observation {
                None if valid_owner => recorded.observation = Some(observation),
                Some(current) if valid_owner && current == &observation => {}
                None | Some(_) => {
                    recorded.observation = None;
                    recorded.conflicted = true;
                }
            }
        }
    }

    fn hns_delegation_snapshot(&self) -> Option<HnsDelegationTraceMetadata> {
        self.hns_delegation.lock().ok().and_then(|state| {
            (!state.conflicted)
                .then(|| state.observation.clone())
                .flatten()
        })
    }

    fn record_namespace_resolution(&self, value: String, selected: Option<Namespace>) {
        if let Ok(mut namespace_resolution) = self.namespace_resolution.lock() {
            *namespace_resolution = Some(value);
        }
        if let Ok(mut selected_namespace) = self.selected_namespace.lock() {
            *selected_namespace = selected;
        }
    }

    fn namespace_resolution_json(&self) -> String {
        self.namespace_resolution
            .lock()
            .ok()
            .and_then(|value| value.clone())
            .unwrap_or_else(|| {
                r#"{"schemaVersion":2,"outcome":"indeterminate","selected":null,"reason":"unavailable","fingerprint":null,"divergenceMask":null,"hnsState":"unknown","icannState":"unknown","hns":{"state":"unknown","rcode":null,"denial":null,"failure":null},"icann":{"state":"unknown","rcode":null,"denial":null,"failure":null}}"#
                    .to_owned()
            })
    }

    fn selected_namespace(&self) -> Option<Namespace> {
        self.selected_namespace
            .lock()
            .ok()
            .and_then(|namespace| *namespace)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HnsDelegationTraceState {
    observation: Option<HnsDelegationTraceMetadata>,
    conflicted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HnsDelegationTraceMetadata {
    root_name: String,
    nameservers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsRelayTraceMetadata {
    peer: Option<SocketAddr>,
    retries: usize,
    service_advertised: Option<bool>,
    error: Option<String>,
}

#[derive(Default)]
struct DnsRelayAttemptTracker {
    attempts: Mutex<HashMap<thread::ThreadId, Vec<DnsRelayAttempt>>>,
}

#[derive(Default)]
struct DnsRelayAttempt {
    peers: HashSet<SocketAddr>,
    retry_offset: usize,
}

impl DnsRelayAttemptTracker {
    fn begin(&self, retry_offset: usize) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts
                .entry(thread::current().id())
                .or_default()
                .push(DnsRelayAttempt {
                    peers: HashSet::new(),
                    retry_offset,
                });
        }
    }

    fn observe(&self, metadata: &DnsRelayTraceMetadata) -> DnsRelayTraceMetadata {
        let mut observed = metadata.clone();
        if let Ok(mut attempts) = self.attempts.lock()
            && let Some(attempt) = attempts
                .get_mut(&thread::current().id())
                .and_then(|attempts| attempts.last_mut())
        {
            if let Some(peer) = metadata.peer {
                attempt.peers.insert(peer);
            }
            observed.retries = observed.retries.saturating_add(attempt.retry_offset);
        }
        observed
    }

    fn finish(&self) -> Vec<SocketAddr> {
        let thread_id = thread::current().id();
        let Ok(mut attempts) = self.attempts.lock() else {
            return Vec::new();
        };
        let (mut peers, remove_thread) = match attempts.get_mut(&thread_id) {
            Some(thread_attempts) => {
                let peers = thread_attempts
                    .pop()
                    .map(|attempt| attempt.peers.into_iter().collect::<Vec<_>>())
                    .unwrap_or_default();
                (peers, thread_attempts.is_empty())
            }
            None => (Vec::new(), false),
        };
        if remove_thread {
            attempts.remove(&thread_id);
        }
        peers.sort_unstable();
        peers
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsTraceEvent {
    protocol: &'static str,
    server: String,
    question_name: Option<String>,
    question_type: Option<u16>,
    status: String,
    elapsed_ms: u64,
    error: Option<String>,
}

#[derive(Clone)]
struct AndroidAuthoritativeDnsTransport {
    direct: UdpTcpDnsTransport,
    doh_http: Arc<TcpHttpTransport>,
    trace: DnsTraceRecorder,
    interception_probe: Arc<Mutex<Option<DnsInterceptionStatus>>>,
}

impl AndroidAuthoritativeDnsTransport {
    fn new(direct: UdpTcpDnsTransport, trace: DnsTraceRecorder, http: TcpHttpTransport) -> Self {
        Self {
            direct,
            doh_http: Arc::new(http),
            trace,
            interception_probe: Arc::new(Mutex::new(None)),
        }
    }
}

impl DnsTransport for AndroidAuthoritativeDnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.direct.endpoint_policy
    }

    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.direct.exchange_udp(server, query);
        self.trace.push(dns_trace_event(
            "udp53",
            server.to_string(),
            query,
            elapsed_millis(started),
            &result,
        ));
        result
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.direct.exchange_tcp(server, query);
        self.trace.push(dns_trace_event(
            "tcp53",
            server.to_string(),
            query,
            elapsed_millis(started),
            &result,
        ));
        result
    }

    fn exchange_doh(
        &self,
        endpoint: &AuthoritativeDohEndpoint,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let response = fetch_authoritative_doh_message(&self.doh_http, endpoint, query.to_vec());
        self.trace.push(doh_trace_event(
            "authoritative_doh",
            authoritative_doh_endpoint_display(endpoint),
            query,
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("authoritative DoH transport failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "authoritative DoH returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }
        Ok(response.body)
    }

    fn dns_interception_status(&self) -> DnsInterceptionStatus {
        self.interception_probe
            .lock()
            .ok()
            .and_then(|probe| *probe)
            .unwrap_or(DnsInterceptionStatus::NotTested)
    }

    fn probe_dns_interception(&self) -> DnsInterceptionStatus {
        let cached = self.dns_interception_status();
        if cached != DnsInterceptionStatus::NotTested {
            return cached;
        }

        let started = Instant::now();
        let (status, error) = run_dns_interception_probe(DNS_INTERCEPTION_PROBE_TIMEOUT);
        self.trace.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: dns_interception_status_name(status).to_owned(),
            elapsed_ms: elapsed_millis(started),
            error,
        });
        if let Ok(mut probe) = self.interception_probe.lock() {
            *probe = Some(status);
        }
        status
    }
}

/// Recursive DNS transport carried over a capability-advertising HNS peer.
/// It deliberately ignores the authoritative socket supplied by the delegated
/// resolver; the raw answer is still consumed by that resolver's local DNSSEC
/// verifier before it can influence an origin connection.
struct HnsP2pDnsTransport {
    client: Arc<Mutex<Option<DnsRelayClient>>>,
    initialization_error: Option<String>,
    peer_store_path: PathBuf,
    network_kind: NetworkKind,
    peer_state: Option<Arc<Mutex<()>>>,
    proof_peer: Arc<Mutex<Option<SocketAddr>>>,
    trace: DnsTraceRecorder,
    endpoint_policy: DnsEndpointPolicy,
    live_queries: SharedDnsRelayFlights,
    attempts: Arc<DnsRelayAttemptTracker>,
}

#[derive(Clone)]
struct HnsP2pDnssecFeedback {
    client: Arc<Mutex<Option<DnsRelayClient>>>,
    peer_store_path: PathBuf,
    peer_state: Option<Arc<Mutex<()>>>,
    attempts: Arc<DnsRelayAttemptTracker>,
}

struct DnsRelayFlight {
    result: Mutex<Option<Result<DnsRelayFlightSuccess, DnsRelayFlightError>>>,
    completed: Condvar,
}

#[derive(Clone)]
struct DnsRelayFlightSuccess {
    response: Vec<u8>,
    metadata: DnsRelayTraceMetadata,
}

#[derive(Clone)]
enum DnsRelayFlightError {
    InvalidResponse,
    Transport(String),
    CachePoisoned,
}

impl DnsRelayFlightError {
    fn from_resolver(error: &ResolverError) -> Self {
        match error {
            ResolverError::InvalidDnsResponse => Self::InvalidResponse,
            ResolverError::CachePoisoned => Self::CachePoisoned,
            error => Self::Transport(error.to_string()),
        }
    }

    fn into_resolver(self) -> ResolverError {
        match self {
            Self::InvalidResponse => ResolverError::InvalidDnsResponse,
            Self::Transport(error) => ResolverError::DnsTransport(error),
            Self::CachePoisoned => ResolverError::CachePoisoned,
        }
    }
}

impl HnsP2pDnsTransport {
    fn new(
        base: &Path,
        network_kind: NetworkKind,
        peer_state: Option<Arc<Mutex<()>>>,
        shared: Option<SharedDnsRelayState>,
        proof_peer: Arc<Mutex<Option<SocketAddr>>>,
        trace: DnsTraceRecorder,
        endpoint_policy: DnsEndpointPolicy,
    ) -> Self {
        let peer_store_path = base.join("peers.sqlite");
        let SharedDnsRelayState {
            client,
            queries: live_queries,
        } = shared.unwrap_or_else(|| SharedDnsRelayState {
            client: Arc::new(Mutex::new(None)),
            queries: Arc::new(Mutex::new(HashMap::new())),
        });
        let initialization_error = match client.lock() {
            Ok(mut slot) if slot.is_none() => match initialize_dns_relay_client(
                &peer_store_path,
                network_kind,
                peer_state.as_ref(),
            ) {
                Ok(initialized) => {
                    *slot = Some(initialized);
                    None
                }
                Err(error) => Some(error),
            },
            Ok(_) => None,
            Err(_) => Some("relay-client lock is poisoned".to_owned()),
        };
        Self {
            client,
            initialization_error,
            peer_store_path,
            network_kind,
            peer_state,
            proof_peer,
            trace,
            endpoint_policy,
            live_queries,
            attempts: Arc::new(DnsRelayAttemptTracker::default()),
        }
    }

    fn dnssec_feedback(&self) -> HnsP2pDnssecFeedback {
        HnsP2pDnssecFeedback {
            client: Arc::clone(&self.client),
            peer_store_path: self.peer_store_path.clone(),
            peer_state: self.peer_state.clone(),
            attempts: Arc::clone(&self.attempts),
        }
    }

    fn exchange(&self, query: &[u8]) -> Result<DnsRelayFlightSuccess, ResolverError> {
        if let Some(error) = self.initialization_error.as_ref() {
            return Err(ResolverError::DnsTransport(format!(
                "experimental HNS P2P DNS relay initialization failed: {error}"
            )));
        }

        let mut guard = self
            .client
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let client = guard.as_mut().ok_or_else(|| {
            ResolverError::DnsTransport(
                "experimental HNS P2P DNS relay client is unavailable".to_owned(),
            )
        })?;
        refresh_dns_relay_peers(
            &self.peer_store_path,
            self.network_kind,
            client,
            self.peer_state.as_ref(),
            now_unix_seconds(),
        )
        .map_err(|error| {
            ResolverError::DnsTransport(format!(
                "experimental HNS P2P DNS relay peer refresh failed: {error}"
            ))
        })?;
        let proof_peer = self.proof_peer.lock().ok().and_then(|peer| *peer);
        client.set_proof_peer(proof_peer);
        let result = client.resolve(query);

        // Relay scoring is useful but never part of DNS correctness. A write
        // failure therefore must not turn a locally valid response into a DNS
        // failure; the next runtime construction can recover from the store.
        let _ = persist_dns_relay_peers(&self.peer_store_path, client, self.peer_state.as_ref());

        result
            .map(|exchange| DnsRelayFlightSuccess {
                response: exchange.response,
                metadata: DnsRelayTraceMetadata {
                    peer: Some(exchange.peer),
                    retries: exchange.retries,
                    service_advertised: Some(true),
                    error: None,
                },
            })
            .map_err(map_dns_relay_client_error)
    }

    fn coalesced_exchange(&self, query: &[u8]) -> Result<DnsRelayFlightSuccess, ResolverError> {
        let (key, request_id) = dns_relay_coalescing_key(query)?;
        let (flight, leader) = {
            let mut live = self
                .live_queries
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?;
            match live.get(&key) {
                Some(flight) => (Arc::clone(flight), false),
                None => {
                    let flight = Arc::new(DnsRelayFlight {
                        result: Mutex::new(None),
                        completed: Condvar::new(),
                    });
                    live.insert(key.clone(), Arc::clone(&flight));
                    (flight, true)
                }
            }
        };

        if !leader {
            let mut result = flight
                .result
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?;
            while result.is_none() {
                result = flight
                    .completed
                    .wait(result)
                    .map_err(|_| ResolverError::CachePoisoned)?;
            }
            return match result.as_ref() {
                Some(Ok(exchange)) => Ok(DnsRelayFlightSuccess {
                    response: restore_dns_relay_response_id(exchange.response.clone(), request_id)?,
                    metadata: exchange.metadata.clone(),
                }),
                Some(Err(error)) => Err(error.clone().into_resolver()),
                None => Err(ResolverError::CachePoisoned),
            };
        }

        let result = self.exchange(query);
        let mut completed = flight
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *completed = Some(match &result {
            Ok(response) => Ok(response.clone()),
            Err(error) => Err(DnsRelayFlightError::from_resolver(error)),
        });
        flight.completed.notify_all();
        drop(completed);
        if let Ok(mut live) = self.live_queries.lock() {
            live.remove(&key);
        }
        result.and_then(|exchange| {
            Ok(DnsRelayFlightSuccess {
                response: restore_dns_relay_response_id(exchange.response, request_id)?,
                metadata: exchange.metadata,
            })
        })
    }

    fn traced_exchange(&self, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let exchange = self.coalesced_exchange(query);
        let (server, result) = match exchange {
            Ok(exchange) => {
                let metadata = self.attempts.observe(&exchange.metadata);
                let server = metadata
                    .peer
                    .map(|peer| peer.to_string())
                    .unwrap_or_else(|| "dynamic-capable-hns-peer".to_owned());
                self.trace.record_relay(metadata);
                (server, Ok(exchange.response))
            }
            Err(error) => {
                let metadata = self.attempts.observe(&DnsRelayTraceMetadata {
                    peer: None,
                    retries: 0,
                    service_advertised: None,
                    error: Some(error.to_string()),
                });
                self.trace.record_relay(metadata);
                ("dynamic-capable-hns-peer".to_owned(), Err(error))
            }
        };
        self.trace.push(dns_trace_event(
            "p2p_dns_relay",
            server,
            query,
            elapsed_millis(started),
            &result,
        ));
        result
    }
}

fn dns_relay_coalescing_key(query: &[u8]) -> Result<(Vec<u8>, u16), ResolverError> {
    if query.len() < 2 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let request_id = u16::from_be_bytes([query[0], query[1]]);
    let mut key = query.to_vec();
    key[..2].fill(0);
    Ok((key, request_id))
}

fn restore_dns_relay_response_id(
    mut response: Vec<u8>,
    request_id: u16,
) -> Result<Vec<u8>, ResolverError> {
    if response.len() < 2 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    response[..2].copy_from_slice(&request_id.to_be_bytes());
    Ok(response)
}

impl DnsTransport for HnsP2pDnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.endpoint_policy
    }

    fn exchange_udp(&self, _server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.traced_exchange(query)
    }

    fn exchange_tcp(&self, _server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.traced_exchange(query)
    }

    fn is_recursive_relay(&self) -> bool {
        true
    }
}

fn initialize_dns_relay_client(
    peer_store_path: &Path,
    network_kind: NetworkKind,
    peer_state: Option<&Arc<Mutex<()>>>,
) -> Result<DnsRelayClient, String> {
    let _peer_guard = match peer_state {
        Some(peer_state) => Some(
            peer_state
                .lock()
                .map_err(|_| "peer-state lock is poisoned".to_owned())?,
        ),
        None => None,
    };
    let _process_peer_guard =
        HeaderStateFileLock::exclusive(&peer_state_lock_path(peer_store_path)?)?;
    let network = network_kind.network();
    let store = SqlitePeerStore::open(peer_store_path)
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut peers = store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    retain_allowed_peer_endpoints(&mut peers, &network);
    if allowed_peer_count(&peers, &network) == 0 {
        let _ = seed_peers_for_network(&mut peers, &network, network_kind);
    }
    store
        .save_manager(&peers)
        .map_err(|error| format!("save peer store: {error}"))?;
    Ok(DnsRelayClient::new(network, peers))
}

fn refresh_dns_relay_peers(
    peer_store_path: &Path,
    network_kind: NetworkKind,
    client: &mut DnsRelayClient,
    peer_state: Option<&Arc<Mutex<()>>>,
    now: u64,
) -> Result<bool, String> {
    let _peer_guard = match peer_state {
        Some(peer_state) => Some(
            peer_state
                .lock()
                .map_err(|_| "peer-state lock is poisoned".to_owned())?,
        ),
        None => None,
    };
    let _process_peer_guard =
        HeaderStateFileLock::exclusive(&peer_state_lock_path(peer_store_path)?)?;
    let store = SqlitePeerStore::open(peer_store_path)
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut stored = store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    retain_allowed_peer_endpoints(&mut stored, &network_kind.network());

    let refreshed = hns_p2p::PeerManager::from_states(stored.iter().map(|stored_peer| {
        client
            .peer_manager()
            .get(stored_peer.address)
            .map(|local_peer| merge_dns_relay_peer_state(stored_peer, local_peer))
            .unwrap_or_else(|| stored_peer.clone())
    }));
    let invalidate_connections = client.peer_manager().iter().any(|local_peer| {
        refreshed.get(local_peer.address).is_none()
            || refreshed
                .get(local_peer.address)
                .is_some_and(|refreshed_peer| {
                    refreshed_peer.is_banned(now) && !local_peer.is_banned(now)
                })
    });

    // The store is authoritative for membership, while max-merging below keeps
    // an in-memory relay penalty from being erased by a concurrent, older store
    // snapshot. That conservative rule can delay a score reward, but it cannot
    // make a newly discovered or newly banned peer invisible to relay selection.
    *client.peer_manager_mut() = refreshed;
    if invalidate_connections {
        // DnsRelayClient intentionally keeps live connection internals private.
        // Closing the small pool is the narrow way to guarantee that removed or
        // newly banned peers cannot occupy or be selected from a stale session.
        client.shutdown();
    }
    Ok(invalidate_connections)
}

fn persist_dns_relay_peers(
    peer_store_path: &Path,
    client: &DnsRelayClient,
    peer_state: Option<&Arc<Mutex<()>>>,
) -> Result<(), String> {
    let _peer_guard = match peer_state {
        Some(peer_state) => Some(
            peer_state
                .lock()
                .map_err(|_| "peer-state lock is poisoned".to_owned())?,
        ),
        None => None,
    };
    let _process_peer_guard =
        HeaderStateFileLock::exclusive(&peer_state_lock_path(peer_store_path)?)?;
    let store = SqlitePeerStore::open(peer_store_path)
        .map_err(|error| format!("open peer store: {error}"))?;
    let current = store
        .load_manager()
        .map_err(|error| format!("reload peer store: {error}"))?;
    for relay_peer in client.peer_manager().iter() {
        let merged = current
            .get(relay_peer.address)
            .map(|stored| merge_dns_relay_peer_state(stored, relay_peer))
            .unwrap_or_else(|| relay_peer.clone());
        store
            .save_peer(&merged)
            .map_err(|error| format!("save peer store: {error}"))?;
    }
    Ok(())
}

fn merge_dns_relay_peer_state(
    stored: &hns_p2p::PeerState,
    relay: &hns_p2p::PeerState,
) -> hns_p2p::PeerState {
    // Height and observation time are one piece of header-sync-owned
    // evidence. Never independently max them: a newer relay connection must
    // not refresh an older height, and a stale relay snapshot must not replace
    // a newer certified observation.
    let (last_height, last_height_observed_at) = match (
        stored.last_height_observed_at,
        relay.last_height_observed_at,
    ) {
        (Some(stored_at), Some(relay_at)) if stored_at > relay_at => {
            (stored.last_height, Some(stored_at))
        }
        (Some(stored_at), Some(relay_at)) if relay_at > stored_at => {
            (relay.last_height, Some(relay_at))
        }
        (Some(observed_at), Some(_)) => {
            (stored.last_height.max(relay.last_height), Some(observed_at))
        }
        (Some(stored_at), None) => (stored.last_height, Some(stored_at)),
        (None, Some(relay_at)) => (relay.last_height, Some(relay_at)),
        (None, None) => (stored.last_height.max(relay.last_height), None),
    };
    hns_p2p::PeerState {
        address: stored.address,
        // Conservatively preserve either path's penalty. Successful relay
        // counts still persist, but a stale relay snapshot cannot erase a
        // concurrent proof/sync failure or ban.
        score: stored.score.max(relay.score),
        last_height,
        last_height_observed_at,
        last_connected_at: stored.last_connected_at.max(relay.last_connected_at),
        banned_until: stored.banned_until.max(relay.banned_until),
        successes: stored.successes.max(relay.successes),
        failures: stored.failures.max(relay.failures),
    }
}

fn map_dns_relay_client_error(error: DnsRelayClientError) -> ResolverError {
    match error {
        DnsRelayClientError::InvalidQuery(_)
        | DnsRelayClientError::InvalidResponse(_)
        | DnsRelayClientError::UnsolicitedResponse(_)
        | DnsRelayClientError::UnexpectedPacket
        | DnsRelayClientError::AdvisoryPacketLimit => ResolverError::InvalidDnsResponse,
        error => {
            ResolverError::DnsTransport(format!("experimental HNS P2P DNS relay failed: {error}"))
        }
    }
}

fn run_dns_interception_probe(timeout: Duration) -> (DnsInterceptionStatus, Option<String>) {
    let qname = match DnsName::from_ascii(DNS_INTERCEPTION_PROBE_NAME) {
        Ok(name) => name,
        Err(_) => {
            return (
                DnsInterceptionStatus::Inconclusive,
                Some("probe name is invalid".to_owned()),
            );
        }
    };
    let query = match build_doh_query(DNS_INTERCEPTION_PROBE_ID, &qname, RecordType::A) {
        Ok(query) => query,
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    let server = SocketAddr::from(([192, 0, 2, 1], 53));
    let socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))) {
        Ok(socket) => socket,
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    if let Err(error) = socket.set_read_timeout(Some(timeout)) {
        return (DnsInterceptionStatus::Inconclusive, Some(error.to_string()));
    }
    if let Err(error) = socket.send_to(&query, server) {
        return (DnsInterceptionStatus::Inconclusive, Some(error.to_string()));
    }

    let mut response = vec![0u8; DEFAULT_DNS_UDP_PAYLOAD];
    let (length, source) = match socket.recv_from(&mut response) {
        Ok(received) => received,
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            return (DnsInterceptionStatus::NotDetected, None);
        }
        Err(error) => return (DnsInterceptionStatus::Inconclusive, Some(error.to_string())),
    };
    response.truncate(length);
    let parsed = DnsMessage::parse(&response);
    if source == server
        && parsed.as_ref().is_ok_and(|message| {
            message.header.id == DNS_INTERCEPTION_PROBE_ID
                && message.header.flags.is_response()
                && message.questions.len() == 1
                && message.questions[0].name == qname
                && message.questions[0].record_type == RecordType::A
                && message.questions[0].class == DNS_CLASS_IN
        })
    {
        return (
            DnsInterceptionStatus::Detected,
            Some(
                "received a matching DNS reply from a non-routable TEST-NET destination".to_owned(),
            ),
        );
    }

    (
        DnsInterceptionStatus::Inconclusive,
        Some("probe received an unrelated or malformed reply".to_owned()),
    )
}

fn dns_interception_status_name(status: DnsInterceptionStatus) -> &'static str {
    match status {
        DnsInterceptionStatus::NotTested => "not_tested",
        DnsInterceptionStatus::NotDetected => "not_detected",
        DnsInterceptionStatus::Detected => "detected",
        DnsInterceptionStatus::Inconclusive => "inconclusive",
    }
}

fn dns_trace_event(
    protocol: &'static str,
    server: String,
    query: &[u8],
    elapsed_ms: u64,
    result: &Result<Vec<u8>, ResolverError>,
) -> DnsTraceEvent {
    let (question_name, question_type) = dns_trace_question(query);
    match result {
        Ok(_) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Err(error) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: dns_trace_error_status(error).to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn doh_trace_event(
    protocol: &'static str,
    server: String,
    query: &[u8],
    elapsed_ms: u64,
    result: &Result<OriginResponse, TransportError>,
) -> DnsTraceEvent {
    let (question_name, question_type) = dns_trace_question(query);
    match result {
        Ok(response) if doh_response_matches_query(response, query) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Ok(response) if !doh_http_status_success(response.status) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "http_error".to_owned(),
            elapsed_ms,
            error: Some(format!("HTTP {}", response.status)),
        },
        Ok(_) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "invalid_response".to_owned(),
            elapsed_ms,
            error: Some("DoH response did not match the DNS question".to_owned()),
        },
        Err(error) => DnsTraceEvent {
            protocol,
            server,
            question_name,
            question_type,
            status: "transport_error".to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn doh_response_matches_query(response: &OriginResponse, query: &[u8]) -> bool {
    if !doh_http_status_success(response.status)
        || !doh_response_has_dns_message_content_type(response)
    {
        return false;
    }
    let (Ok(query), Ok(answer)) = (DnsMessage::parse(query), DnsMessage::parse(&response.body))
    else {
        return false;
    };
    let ([question], [answered_question]) =
        (query.questions.as_slice(), answer.questions.as_slice())
    else {
        return false;
    };
    answer.header.flags.is_response()
        && !answer.header.flags.truncated()
        && answer.header.flags.opcode() == 0
        && matches!(
            answer.header.flags.rcode(),
            DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN
        )
        && answer.header.id == query.header.id
        && answered_question.name == question.name
        && answered_question.record_type == question.record_type
        && answered_question.class == question.class
}

fn dns_trace_question(query: &[u8]) -> (Option<String>, Option<u16>) {
    let Ok(message) = DnsMessage::parse(query) else {
        return (None, None);
    };
    let Some(question) = message.questions.first() else {
        return (None, None);
    };
    (
        Some(question.name.to_string()),
        Some(question.record_type.code()),
    )
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn dns_trace_error_status(error: &ResolverError) -> &'static str {
    match error {
        ResolverError::DnsTransport(message)
            if message.contains("timed out")
                || message.contains("timeout")
                || message.contains("deadline") =>
        {
            "timeout"
        }
        ResolverError::DnsTransport(_) => "transport_error",
        ResolverError::DnsResponseCode(_) => "response_code",
        ResolverError::InvalidDnsResponse => "invalid_response",
        ResolverError::DnssecFailed | ResolverError::RelayDnssecFailed => "dnssec_failed",
        _ => "error",
    }
}

impl Resolver for AndroidGatewayResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        self.inner.resolve(request)
    }

    fn prepare_namespace_resolution(
        &self,
        query: &OriginQuery,
    ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
        self.inner.prepare_namespace_resolution(query)
    }
}

#[derive(Clone, Debug, Default)]
struct FallbackMarker {
    used: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<&'static str>>>,
}

impl FallbackMarker {
    fn mark(&self, reason: &'static str) {
        self.used.store(true, Ordering::Relaxed);
        if let Ok(mut fallback_reason) = self.reason.lock()
            && fallback_reason.is_none()
        {
            *fallback_reason = Some(reason);
        }
    }

    fn used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    fn reason(&self) -> Option<&'static str> {
        self.reason.lock().ok().and_then(|reason| *reason)
    }
}

#[cfg(test)]
struct FallbackResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_marker: FallbackMarker,
    fallback_roots: Arc<Mutex<HashMap<String, &'static str>>>,
}

#[cfg(test)]
impl<P, F> FallbackResolver<P, F> {
    fn with_marker(primary: P, fallback: F, fallback_marker: FallbackMarker) -> Self {
        Self {
            primary,
            fallback,
            fallback_marker,
            fallback_roots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached_fallback_reason(&self, request: &ResolutionRequest) -> Option<&'static str> {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root).copied())
    }

    fn remember_fallback_reason(&self, request: &ResolutionRequest, reason: &'static str) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.entry(root).or_insert(reason);
        }
    }
}

#[cfg(test)]
impl<P, F> Resolver for FallbackResolver<P, F>
where
    P: Resolver,
    F: Resolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(reason) = self.cached_fallback_reason(request) {
            self.fallback_marker.mark(reason);
            return self.fallback.resolve(request);
        }

        match self.primary.resolve(request) {
            Ok(answer) => Ok(answer),
            Err(error) => {
                let Some(reason) = doh_fallback_reason(&error) else {
                    return Err(error);
                };
                self.remember_fallback_reason(request, reason);
                self.fallback_marker.mark(reason);
                self.fallback.resolve(request)
            }
        }
    }
}

fn fallback_cache_root(request: &ResolutionRequest) -> String {
    hns_trace_root(&request.qname).to_ascii_lowercase()
}

/// Adds the separately consented recursive HNS DoH endpoint only after every
/// earlier delegated transport has exhausted a typed availability failure.
/// Per-root memory avoids replaying known-unavailable direct/owner/P2P paths
/// for every A, AAAA, HTTPS, and TLSA query in one origin decision.
#[derive(Clone, Debug)]
struct ConfiguredDohFallbackDelegatedResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_marker: FallbackMarker,
    fallback_roots: Arc<Mutex<HashMap<String, &'static str>>>,
}

impl<P, F> ConfiguredDohFallbackDelegatedResolver<P, F> {
    fn new(primary: P, fallback: F, fallback_marker: FallbackMarker) -> Self {
        Self {
            primary,
            fallback,
            fallback_marker,
            fallback_roots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached_fallback_reason(&self, request: &ResolutionRequest) -> Option<&'static str> {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root).copied())
    }

    fn remember_fallback_reason(&self, request: &ResolutionRequest, reason: &'static str) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.entry(root).or_insert(reason);
        }
    }
}

impl<P, F> DelegatedResolver for ConfiguredDohFallbackDelegatedResolver<P, F>
where
    P: DelegatedResolver,
    F: DelegatedResolver,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(reason) = self.cached_fallback_reason(request) {
            self.fallback_marker.mark(reason);
            return self.fallback.resolve_delegated(request, delegation);
        }

        match self.primary.resolve_delegated(request, delegation) {
            Ok(answer) => Ok(answer),
            Err(error) => {
                let Some(reason) = configured_doh_transport_fallback_reason(&error) else {
                    return Err(error);
                };
                self.remember_fallback_reason(request, reason);
                self.fallback_marker.mark(reason);
                self.fallback.resolve_delegated(request, delegation)
            }
        }
    }
}

#[cfg(test)]
type FallbackDelegatedResolver<P, F> = ConfiguredDohFallbackDelegatedResolver<P, F>;

trait RelayDnssecAttemptFeedback {
    fn begin_attempt(&self, retry_offset: usize);
    fn finish_attempt(&self) -> Vec<SocketAddr>;
    fn report_dnssec_failure(&self, peers: &[SocketAddr]);
}

impl RelayDnssecAttemptFeedback for HnsP2pDnssecFeedback {
    fn begin_attempt(&self, retry_offset: usize) {
        self.attempts.begin(retry_offset);
    }

    fn finish_attempt(&self) -> Vec<SocketAddr> {
        self.attempts.finish()
    }

    fn report_dnssec_failure(&self, peers: &[SocketAddr]) {
        let Ok(mut guard) = self.client.lock() else {
            return;
        };
        let Some(client) = guard.as_mut() else {
            return;
        };
        let now = now_unix_seconds();
        for peer in peers.iter().copied() {
            let _ = client.report_dnssec_failure(peer, now);
        }
        // As with ordinary relay scoring persistence, failure to write feedback
        // must not change the fail-closed DNSSEC result or permit a DoH fallback.
        let _ = persist_dns_relay_peers(&self.peer_store_path, client, self.peer_state.as_ref());
    }
}

/// Repeats the complete delegated validation once after a relay response fails
/// local DNSSEC verification. Feedback is scoped to the current synchronous
/// resolver call, so another thread's coalesced or concurrent relay exchange
/// cannot supply peers for this request's penalty.
struct RelayDnssecRetryDelegatedResolver<R, F> {
    inner: R,
    feedback: F,
}

impl<R, F> RelayDnssecRetryDelegatedResolver<R, F> {
    fn new(inner: R, feedback: F) -> Self {
        Self { inner, feedback }
    }
}

impl<R, F> RelayDnssecRetryDelegatedResolver<R, F>
where
    R: DelegatedResolver,
    F: RelayDnssecAttemptFeedback,
{
    fn resolve_attempt(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
        retry_offset: usize,
    ) -> (Result<ResolutionAnswer, ResolverError>, Vec<SocketAddr>) {
        self.feedback.begin_attempt(retry_offset);
        let result = self.inner.resolve_delegated(request, delegation);
        let peers = self.feedback.finish_attempt();
        (result, peers)
    }
}

impl<R, F> DelegatedResolver for RelayDnssecRetryDelegatedResolver<R, F>
where
    R: DelegatedResolver,
    F: RelayDnssecAttemptFeedback,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        let (first_result, first_peers) = self.resolve_attempt(request, delegation, 0);
        match first_result {
            Err(ResolverError::DnssecFailed) => {
                if first_peers.is_empty() {
                    return Err(ResolverError::RelayDnssecFailed);
                }
                self.feedback.report_dnssec_failure(&first_peers);

                let (retry_result, retry_peers) = self.resolve_attempt(request, delegation, 1);
                match retry_result {
                    Ok(answer) => Ok(answer),
                    Err(_) => {
                        if !retry_peers.is_empty() {
                            self.feedback.report_dnssec_failure(&retry_peers);
                        }
                        // Once relay-provided DNS has failed local validation,
                        // every exhausted retry path remains a relay DNSSEC
                        // failure. In particular, a transport error from the
                        // alternate must not reopen the configured recursive
                        // HNS DoH fallback.
                        Err(ResolverError::RelayDnssecFailed)
                    }
                }
            }
            result => result,
        }
    }
}

/// Falls back from proof-declared/direct authoritative DNS to the experimental
/// peer relay while keeping the relay inside the delegated DNSSEC validator.
/// The per-root memory avoids repeating a known-unusable port-53 path for every
/// A, AAAA, HTTPS, and TLSA lookup in one gateway request.
struct P2pFallbackDelegatedResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_roots: Arc<Mutex<HashSet<String>>>,
}

impl<P, F> P2pFallbackDelegatedResolver<P, F> {
    fn new(primary: P, fallback: F) -> Self {
        Self {
            primary,
            fallback,
            fallback_roots: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn uses_fallback(&self, request: &ResolutionRequest) -> bool {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .is_ok_and(|roots| roots.contains(&root))
    }

    fn remember_fallback(&self, request: &ResolutionRequest) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.insert(root);
        }
    }
}

impl<P, F> DelegatedResolver for P2pFallbackDelegatedResolver<P, F>
where
    P: DelegatedResolver,
    F: DelegatedResolver,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        if self.uses_fallback(request) {
            return relay_dnssec_result(self.fallback.resolve_delegated(request, delegation));
        }

        match self.primary.resolve_delegated(request, delegation) {
            Ok(answer) => Ok(answer),
            Err(error) if delegated_p2p_fallback_allowed(&error) => {
                self.remember_fallback(request);
                relay_dnssec_result(self.fallback.resolve_delegated(request, delegation))
            }
            Err(error) => Err(error),
        }
    }
}

fn relay_dnssec_result(
    result: Result<ResolutionAnswer, ResolverError>,
) -> Result<ResolutionAnswer, ResolverError> {
    result.map_err(|error| match error {
        ResolverError::DnssecFailed => ResolverError::RelayDnssecFailed,
        error => error,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IcannDohAnswerKind {
    Present,
    NoData,
    NxDomain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IcannDohObservation {
    kind: IcannDohAnswerKind,
    secure: bool,
    rcode: u8,
    observed_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Default)]
struct IcannDohEvidenceState {
    observations: HashMap<ResolutionRequest, IcannDohObservation>,
    inconsistent_queries: HashSet<ResolutionRequest>,
}

#[derive(Clone, Debug, Default)]
struct IcannDohEvidence {
    state: Arc<Mutex<IcannDohEvidenceState>>,
}

impl IcannDohEvidence {
    fn record(
        &self,
        request: &ResolutionRequest,
        observation: IcannDohObservation,
    ) -> Result<(), ResolverError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        if let Some(current) = state.observations.get_mut(request) {
            if current.kind != observation.kind
                || current.secure != observation.secure
                || current.rcode != observation.rcode
            {
                state.inconsistent_queries.insert(request.clone());
                return Ok(());
            }
            current.observed_at_unix = current.observed_at_unix.max(observation.observed_at_unix);
            current.expires_at_unix = current.expires_at_unix.min(observation.expires_at_unix);
            if current.expires_at_unix <= current.observed_at_unix {
                state.inconsistent_queries.insert(request.clone());
            }
        } else {
            state.observations.insert(request.clone(), observation);
        }
        Ok(())
    }

    fn exact(
        &self,
        request: &ResolutionRequest,
    ) -> Result<Option<IcannDohObservation>, ResolverError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        if state.inconsistent_queries.contains(request) {
            return Err(ResolverError::InvalidDnsResponse);
        }
        Ok(state.observations.get(request).copied())
    }
}

#[derive(Clone, Debug)]
struct IcannDohResolver {
    endpoint: HnsDohEndpoint,
    trace: DnsTraceRecorder,
    http: TcpHttpTransport,
    evidence: IcannDohEvidence,
    #[cfg(test)]
    fixture_single_label_absence: bool,
}

impl IcannDohResolver {
    fn new(trace: DnsTraceRecorder, http: TcpHttpTransport) -> Self {
        Self {
            endpoint: default_icann_doh_endpoint(),
            trace,
            http,
            evidence: IcannDohEvidence::default(),
            #[cfg(test)]
            fixture_single_label_absence: false,
        }
    }

    fn with_evidence(mut self, evidence: IcannDohEvidence) -> Self {
        self.evidence = evidence;
        self
    }

    #[cfg(test)]
    fn with_test_single_label_absence(mut self) -> Self {
        self.fixture_single_label_absence = true;
        self
    }
}

impl Resolver for IcannDohResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        #[cfg(test)]
        if self.fixture_single_label_absence && !request.qname.contains('.') {
            let name = DnsName::from_ascii(&request.qname)
                .map_err(|_| ResolverError::UnsupportedBackend)?;
            let observed_at_unix = now_unix_seconds();
            self.evidence.record(
                request,
                IcannDohObservation {
                    kind: IcannDohAnswerKind::NxDomain,
                    secure: true,
                    rcode: DNS_RCODE_NXDOMAIN,
                    observed_at_unix,
                    expires_at_unix: observed_at_unix
                        .saturating_add(HNS_NAMESPACE_EVIDENCE_TTL_SECONDS),
                },
            )?;
            return Ok(ResolutionAnswer {
                name,
                records: Vec::new(),
                secure: true,
            });
        }
        let qname =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let id = DOH_DNS_ID;
        let query = build_doh_query(id, &qname, qtype)?;
        let response = fetch_icann_doh_message(
            &self.http,
            &self.endpoint,
            ICANN_DOH_BOOTSTRAP_ADDRESSES,
            &query,
            &self.trace,
        );
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("ICANN DoH resolver failed: {error}"))
        })?;
        if !doh_http_status_success(response.status) {
            return Err(ResolverError::DnsTransport(format!(
                "ICANN DoH resolver returned HTTP {}",
                response.status
            )));
        }
        if !doh_response_has_dns_message_content_type(&response) {
            return Err(ResolverError::InvalidDnsResponse);
        }

        let (answer, observation) =
            doh_answer_and_observation_from_body(id, &qname, qtype, &response.body)?;
        self.evidence.record(request, observation)?;
        Ok(answer)
    }
}

/// Raw RFC 8484 transport for the explicitly user-configured recursive HNS
/// recovery endpoint. Its hostname is bootstrapped only through the built-in
/// fixed-address ICANN DoH resolver, every connection uses an explicit public
/// IP plus WebPKI hostname authentication, and returned DNS bytes remain
/// untrusted until `AuthoritativeDnssecResolver` validates them locally.
#[derive(Clone)]
struct ConfiguredRecursiveHnsDohTransport {
    endpoint: HnsDohEndpoint,
    trace: DnsTraceRecorder,
    http: TcpHttpTransport,
    endpoint_policy: DnsEndpointPolicy,
    bootstrap_cache: Arc<Mutex<Option<Vec<IpAddr>>>>,
}

impl ConfiguredRecursiveHnsDohTransport {
    fn new(
        endpoint: HnsDohEndpoint,
        trace: DnsTraceRecorder,
        http: TcpHttpTransport,
        endpoint_policy: DnsEndpointPolicy,
    ) -> Self {
        Self {
            endpoint,
            trace,
            http,
            endpoint_policy,
            bootstrap_cache: Arc::new(Mutex::new(None)),
        }
    }

    fn bootstrap_addresses(&self) -> Result<Vec<IpAddr>, ResolverError> {
        if let Some(addresses) = self
            .bootstrap_cache
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .clone()
        {
            return Ok(addresses);
        }

        let addresses = resolve_configured_doh_bootstrap_addresses(
            &self.endpoint.host,
            &self.trace,
            &self.http,
        )?;
        let mut cache = self
            .bootstrap_cache
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        *cache = Some(addresses.clone());
        Ok(addresses)
    }

    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let (wire_query, original_id) = recursive_doh_query(query)?;
        let addresses = match self.bootstrap_addresses() {
            Ok(addresses) => addresses,
            Err(error) => {
                let (question_name, question_type) = dns_trace_question(&wire_query);
                self.trace.push(DnsTraceEvent {
                    protocol: "user_configured_recursive_hns_doh",
                    server: self.endpoint.display(),
                    question_name,
                    question_type,
                    status: dns_trace_error_status(&error).to_owned(),
                    elapsed_ms: 0,
                    error: Some(format!("ICANN DoH bootstrap failed: {error}")),
                });
                return Err(error);
            }
        };
        let mut last_error = None;
        for address in addresses {
            let started = Instant::now();
            let response = self.http.fetch_rfc8484_post(&configured_doh_origin_request(
                &self.endpoint,
                address,
                wire_query.clone(),
            ));
            self.trace.push(doh_trace_event(
                "user_configured_recursive_hns_doh",
                format!("{} via {address}", self.endpoint.display()),
                &wire_query,
                elapsed_millis(started),
                &response,
            ));
            match response {
                Ok(response) => {
                    if !doh_http_status_success(response.status) {
                        last_error = Some(ResolverError::DnsTransport(format!(
                            "user-configured recursive HNS DoH returned HTTP {}",
                            response.status
                        )));
                        continue;
                    }
                    if !doh_response_has_dns_message_content_type(&response)
                        || response.body.len() > u16::MAX as usize
                    {
                        return Err(ResolverError::InvalidDnsResponse);
                    }
                    return restore_doh_response_id(&response.body, original_id);
                }
                Err(error) => {
                    last_error = Some(ResolverError::DnsTransport(format!(
                        "user-configured recursive HNS DoH transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            ResolverError::DnsTransport(
                "user-configured recursive HNS DoH has no public ICANN bootstrap address"
                    .to_owned(),
            )
        }))
    }
}

impl DnsTransport for ConfiguredRecursiveHnsDohTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.endpoint_policy
    }

    fn exchange_udp(&self, _server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.exchange(query)
    }

    fn exchange_tcp(&self, _server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        self.exchange(query)
    }

    fn is_recursive_relay(&self) -> bool {
        true
    }
}

fn resolve_configured_doh_bootstrap_addresses(
    host: &str,
    trace: &DnsTraceRecorder,
    http: &TcpHttpTransport,
) -> Result<Vec<IpAddr>, ResolverError> {
    let resolver = IcannDohResolver::new(trace.clone(), http.clone());
    let start = CanonicalHost::parse(host).map_err(|_| ResolverError::InvalidDnsResponse)?;
    let (ipv4_target, mut addresses) =
        resolve_icann_bootstrap_family(&resolver, &start, RecordType::A)?;
    let (ipv6_target, ipv6) = resolve_icann_bootstrap_family(&resolver, &start, RecordType::Aaaa)?;
    if ipv4_target != ipv6_target {
        return Err(ResolverError::InvalidDnsResponse);
    }
    addresses.extend(ipv6);
    addresses.retain(|address| is_publicly_routable(*address));
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(16);
    if addresses.is_empty() {
        return Err(ResolverError::DnsTransport(
            "validating ICANN DoH bootstrap returned no public resolver address".to_owned(),
        ));
    }
    Ok(addresses)
}

fn resolve_icann_bootstrap_family(
    resolver: &IcannDohResolver,
    start: &CanonicalHost,
    qtype: RecordType,
) -> Result<(CanonicalHost, Vec<IpAddr>), ResolverError> {
    let mut owner = start.clone();
    let mut seen = Vec::new();
    for _ in 0..=hns_namespace_resolution::MAX_ALIAS_STEPS {
        if seen.contains(&owner) {
            return Err(ResolverError::InvalidDnsResponse);
        }
        seen.push(owner.clone());
        let answer = resolver.resolve(&ResolutionRequest {
            qname: owner.as_str().to_owned(),
            qtype: qtype.code(),
        })?;
        let owner_name =
            DnsName::from_ascii(owner.as_str()).map_err(|_| ResolverError::InvalidDnsResponse)?;
        let cnames = records_for_owner(&answer.records, &owner_name, RecordType::Cname)
            .map_err(|_| ResolverError::InvalidDnsResponse)?;
        let records = records_for_owner(&answer.records, &owner_name, qtype)
            .map_err(|_| ResolverError::InvalidDnsResponse)?;
        if !cnames.is_empty() && !records.is_empty() {
            return Err(ResolverError::InvalidDnsResponse);
        }
        if let Some(target) =
            one_cname_target(&cnames).map_err(|_| ResolverError::InvalidDnsResponse)?
        {
            owner = canonical_dns_host(&target).map_err(|_| ResolverError::InvalidDnsResponse)?;
            continue;
        }
        let addresses = records
            .iter()
            .map(|record| match (qtype, record.rdata.as_slice()) {
                (RecordType::A, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
                (RecordType::Aaaa, bytes) if bytes.len() == 16 => {
                    let mut address = [0u8; 16];
                    address.copy_from_slice(bytes);
                    Ok(IpAddr::V6(Ipv6Addr::from(address)))
                }
                _ => Err(ResolverError::InvalidDnsResponse),
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok((owner, addresses));
    }
    Err(ResolverError::InvalidDnsResponse)
}

struct DualRootBrowserResolver {
    hns: Box<dyn Resolver>,
    icann: Box<dyn Resolver>,
    network: NetworkKind,
    hns_lineage: HnsProofLineage,
    icann_evidence: IcannDohEvidence,
    binding_store_path: PathBuf,
    trace: DnsTraceRecorder,
}

impl Resolver for DualRootBrowserResolver {
    fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        // Browser traffic must use the atomic origin-plan boundary below. A
        // record-at-a-time call here could accidentally reintroduce root
        // mixing or a classification/connection TOCTOU.
        Err(ResolverError::UnsupportedBackend)
    }

    fn prepare_namespace_resolution(
        &self,
        query: &OriginQuery,
    ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
        let hns = build_root_resolution(
            Namespace::Hns,
            query,
            self.hns.as_ref(),
            Some(&self.hns_lineage),
            None,
            self.network,
            Some(&self.trace),
        );
        // Both lookups are attempted independently. In particular, an HNS
        // failure never becomes permission to skip ICANN and silently route.
        let icann = build_root_resolution(
            Namespace::Icann,
            query,
            self.icann.as_ref(),
            None,
            Some(&self.icann_evidence),
            self.network,
            None,
        );

        let origin = namespace_origin_key(query)?;
        let binding_store = NamespaceBindingStore::open(&self.binding_store_path, self.network)?;
        let sticky = binding_store.get(&origin)?;
        let policy = SelectionPolicy::new(
            DefaultPrecedence::PreferIcann,
            sticky.map_or(0, |binding| binding.revision),
        )
        .with_sticky_binding(sticky.map(|binding| namespace_from_stored(binding.namespace)));
        let decision =
            match decide_namespace(query, hns.lookup, icann.lookup, policy, now_unix_seconds()) {
                Ok(decision) => decision,
                Err(error) => {
                    self.trace.record_namespace_resolution(
                        indeterminate_namespace_trace_json(query, &error),
                        None,
                    );
                    return Err(error.into());
                }
            };
        self.trace.record_namespace_resolution(
            namespace_decision_trace_json(&decision),
            decision.selected_namespace(),
        );
        let selected_answer = match decision.selected_namespace() {
            Some(Namespace::Hns) => Some(hns.answer),
            Some(Namespace::Icann) => Some(icann.answer),
            None => None,
        };
        Ok(Some(PreparedNamespaceResolution {
            decision,
            selected_answer,
        }))
    }
}

struct BuiltRootResolution {
    lookup: RootLookup,
    answer: ResolutionAnswer,
}

struct RootResolutionSession<'a> {
    namespace: Namespace,
    query: &'a OriginQuery,
    resolver: &'a dyn Resolver,
    hns_lineage: Option<&'a HnsProofLineage>,
    icann_evidence: Option<&'a IcannDohEvidence>,
    dns_trace: Option<&'a DnsTraceRecorder>,
    network: NetworkKind,
    requests: Vec<ResolutionRequest>,
    answers: Vec<ResolutionAnswer>,
    hns_roots: Vec<String>,
    icann_observations: Vec<IcannDohObservation>,
}

impl<'a> RootResolutionSession<'a> {
    fn new(
        namespace: Namespace,
        query: &'a OriginQuery,
        resolver: &'a dyn Resolver,
        hns_lineage: Option<&'a HnsProofLineage>,
        icann_evidence: Option<&'a IcannDohEvidence>,
        network: NetworkKind,
        dns_trace: Option<&'a DnsTraceRecorder>,
    ) -> Self {
        Self {
            namespace,
            query,
            resolver,
            hns_lineage,
            icann_evidence,
            dns_trace,
            network,
            requests: Vec::new(),
            answers: Vec::new(),
            hns_roots: Vec::new(),
            icann_observations: Vec::new(),
        }
    }

    fn resolve(
        &mut self,
        qname: &CanonicalHost,
        qtype: RecordType,
    ) -> Result<ResolutionAnswer, PlanBuildError> {
        self.resolve_name(qname.as_str(), qtype)
    }

    fn resolve_name(
        &mut self,
        qname: &str,
        qtype: RecordType,
    ) -> Result<ResolutionAnswer, PlanBuildError> {
        let request = ResolutionRequest {
            qname: qname.to_owned(),
            qtype: qtype.code(),
        };
        if let Some(index) = self
            .requests
            .iter()
            .position(|candidate| candidate == &request)
        {
            return self
                .answers
                .get(index)
                .cloned()
                .ok_or(PlanBuildError::Malformed);
        }
        if self.namespace == Namespace::Hns {
            let root = hns_root_label(&request.qname).map_err(PlanBuildError::Resolver)?;
            if !self.hns_roots.contains(&root) {
                self.hns_roots.push(root);
            }
        }
        let mut answer = self
            .resolver
            .resolve(&request)
            .map_err(PlanBuildError::Resolver)?;
        normalize_answer_cnames(&mut answer, &self.answers)?;
        if self.namespace == Namespace::Icann {
            let observation = self
                .icann_evidence
                .ok_or(PlanBuildError::Malformed)?
                .exact(&request)
                .map_err(PlanBuildError::Resolver)?
                .ok_or(PlanBuildError::Malformed)?;
            self.icann_observations.push(observation);
        }
        self.requests.push(request);
        self.answers.push(answer.clone());
        Ok(answer)
    }

    fn selected_answer(&self) -> ResolutionAnswer {
        let mut records = Vec::<ResourceRecord>::new();
        for answer in &self.answers {
            for record in &answer.records {
                if record.record_type == RecordType::Cname
                    && let Some(existing) = records.iter_mut().find(|existing| {
                        existing.record_type == RecordType::Cname
                            && existing.name == record.name
                            && existing.class == record.class
                    })
                {
                    // Cross-answer target consistency was enforced when each
                    // answer entered the session. Retain one CNAME and the
                    // most conservative TTL in the aggregate.
                    existing.ttl = existing.ttl.min(record.ttl);
                    continue;
                }
                if !records.contains(record) {
                    records.push(record.clone());
                }
            }
        }
        ResolutionAnswer {
            name: DnsName::from_ascii(self.query.host().as_str())
                .unwrap_or_else(|_| DnsName::root()),
            records,
            secure: !self.answers.is_empty() && self.answers.iter().all(|answer| answer.secure),
        }
    }

    fn last_icann_answer_kind(&self) -> Option<IcannDohAnswerKind> {
        (self.namespace == Namespace::Icann)
            .then(|| {
                self.icann_observations
                    .last()
                    .map(|observation| observation.kind)
            })
            .flatten()
    }

    fn icann_origin_insecure_delegation_observed(&self) -> bool {
        if self.namespace != Namespace::Icann {
            return false;
        }
        let Ok(origin) = DnsName::from_ascii(self.query.host().as_str()) else {
            return false;
        };
        self.requests
            .iter()
            .zip(&self.answers)
            .filter(|(request, answer)| {
                request.qname == self.query.host().as_str() && !answer.secure
            })
            .any(|(request, answer)| {
                let requested_type = RecordType::from_code(request.qtype);
                answer
                    .records
                    .iter()
                    .filter(|record| {
                        record.class == DNS_CLASS_IN
                            && record.name == origin
                            && (record.record_type == RecordType::Cname
                                || record.record_type == requested_type)
                    })
                    .any(|record| {
                        !answer.records.iter().any(|signature| {
                            signature.class == DNS_CLASS_IN
                                && signature.name == origin
                                && rrsig_type_covered(signature) == Some(record.record_type)
                        })
                    })
            })
    }

    fn evidence(
        &self,
        icann_chain_override: Option<IcannChainState>,
    ) -> Result<(EvidenceProvenance, Freshness), PlanBuildError> {
        match self.namespace {
            Namespace::Hns => {
                let lineage = self.hns_lineage.ok_or(PlanBuildError::Malformed)?;
                if self.hns_roots.is_empty() {
                    return Err(PlanBuildError::Malformed);
                }
                let mut anchor = None;
                let mut observed_at_unix = 0u64;
                let mut expires_at_unix = u64::MAX;
                for root in &self.hns_roots {
                    let observation = lineage
                        .exact(root)
                        .map_err(PlanBuildError::Resolver)?
                        .ok_or(PlanBuildError::Malformed)?;
                    if let Some(expected) = anchor
                        && expected != observation.anchor
                    {
                        return Err(PlanBuildError::Malformed);
                    }
                    anchor = Some(observation.anchor);
                    observed_at_unix = observed_at_unix.max(observation.observed_at_unix);
                    expires_at_unix = expires_at_unix.min(observation.expires_at_unix);
                }
                let anchor = anchor.ok_or(PlanBuildError::Malformed)?;
                let mut freshness = Freshness::new(observed_at_unix, expires_at_unix)
                    .map_err(|_| PlanBuildError::Malformed)?;
                if self.dns_trace.is_some_and(|trace| {
                    trace
                        .snapshot()
                        .iter()
                        .any(|event| dns_protocol_namespace(event.protocol) == Some(Namespace::Hns))
                }) {
                    // The legacy delegated HNS resolver validates DNSSEC but
                    // does not expose the exact RR TTL/RRSIG expiration to
                    // this plan boundary. Keep the atomic plan reusable for
                    // at most one second instead of inheriting the longer
                    // Urkel-anchor lifetime.
                    let observed_at_unix = freshness.observed_at_unix().max(now_unix_seconds());
                    let expires_at_unix = freshness.expires_at_unix().min(
                        observed_at_unix.saturating_add(HNS_DELEGATED_DNS_EVIDENCE_TTL_SECONDS),
                    );
                    freshness = Freshness::new(observed_at_unix, expires_at_unix)
                        .map_err(|_| PlanBuildError::Malformed)?;
                }
                Ok((
                    EvidenceProvenance::Hns {
                        network: hns_network(self.network),
                        tree_root: anchor.tree_root.into_bytes(),
                        height: anchor.height.0,
                    },
                    freshness,
                ))
            }
            Namespace::Icann => {
                if self.icann_observations.is_empty() {
                    return Err(PlanBuildError::Malformed);
                }
                let observed_at_unix = self
                    .icann_observations
                    .iter()
                    .map(|observation| observation.observed_at_unix)
                    .max()
                    .ok_or(PlanBuildError::Malformed)?;
                let expires_at_unix = self
                    .icann_observations
                    .iter()
                    .map(|observation| observation.expires_at_unix)
                    .min()
                    .ok_or(PlanBuildError::Malformed)?;
                let freshness = Freshness::new(observed_at_unix, expires_at_unix)
                    .map_err(|_| PlanBuildError::Malformed)?;
                let chain_state = icann_chain_override.unwrap_or_else(|| {
                    if self
                        .icann_observations
                        .iter()
                        .all(|observation| observation.secure)
                    {
                        IcannChainState::Secure
                    } else {
                        IcannChainState::ProvenInsecure
                    }
                });
                Ok((EvidenceProvenance::IcannDoh { chain_state }, freshness))
            }
        }
    }
}

fn normalize_answer_cnames(
    answer: &mut ResolutionAnswer,
    retained_answers: &[ResolutionAnswer],
) -> Result<(), PlanBuildError> {
    let mut normalized = Vec::<ResourceRecord>::with_capacity(answer.records.len());
    for record in answer.records.drain(..) {
        if record.record_type != RecordType::Cname {
            normalized.push(record);
            continue;
        }
        let target = cname_record_target(&record)?;
        for previous in retained_answers
            .iter()
            .flat_map(|answer| answer.records.iter())
            .filter(|previous| {
                previous.record_type == RecordType::Cname
                    && previous.name == record.name
                    && previous.class == record.class
            })
        {
            if cname_record_target(previous)? != target {
                return Err(PlanBuildError::Malformed);
            }
        }
        if let Some(previous) = normalized.iter_mut().find(|previous| {
            previous.record_type == RecordType::Cname
                && previous.name == record.name
                && previous.class == record.class
        }) {
            if cname_record_target(previous)? != target {
                return Err(PlanBuildError::Malformed);
            }
            previous.ttl = previous.ttl.min(record.ttl);
            continue;
        }
        normalized.push(record);
    }
    answer.records = normalized;
    Ok(())
}

#[derive(Debug)]
enum PlanBuildError {
    Resolver(ResolverError),
    NoUsableEndpoint,
    RequiredHnsTlsaMissing,
    Malformed,
    Unsupported,
}

fn build_root_resolution(
    namespace: Namespace,
    query: &OriginQuery,
    resolver: &dyn Resolver,
    hns_lineage: Option<&HnsProofLineage>,
    icann_evidence: Option<&IcannDohEvidence>,
    network: NetworkKind,
    dns_trace: Option<&DnsTraceRecorder>,
) -> BuiltRootResolution {
    let mut session = RootResolutionSession::new(
        namespace,
        query,
        resolver,
        hns_lineage,
        icann_evidence,
        network,
        dns_trace,
    );
    let result = build_validated_origin_plan(&mut session);
    let answer = session.selected_answer();
    let lookup = match result {
        Ok(plan) => RootLookup::Present(plan),
        Err(PlanBuildError::NoUsableEndpoint)
        | Err(PlanBuildError::Resolver(ResolverError::NameNotFound)) => {
            match validated_root_absence(&session) {
                Ok(absence) => RootLookup::Absent(absence),
                Err(error) => RootLookup::Failed(RootFailure::new(
                    namespace,
                    query.clone(),
                    plan_build_failure_kind(&error),
                    None,
                )),
            }
        }
        Err(error) => RootLookup::Failed(RootFailure::new(
            namespace,
            query.clone(),
            plan_build_failure_kind(&error),
            None,
        )),
    };
    BuiltRootResolution { lookup, answer }
}

fn build_validated_origin_plan(
    session: &mut RootResolutionSession<'_>,
) -> Result<ValidatedOriginPlan, PlanBuildError> {
    let query = session.query.clone();
    let origin_host = query.host().clone();
    let (alias_path, terminal_target, services) = if query.scheme().uses_tls() {
        resolve_https_service(session, &origin_host)?
    } else {
        (
            Vec::new(),
            origin_host.clone(),
            vec![default_service_binding(&query, &origin_host)?],
        )
    };

    let mut last_retryable_error = None;
    for service in services {
        match build_validated_origin_plan_for_service(
            session,
            query.clone(),
            alias_path.clone(),
            terminal_target.clone(),
            service,
        ) {
            Ok(plan) => return Ok(plan),
            Err(error @ PlanBuildError::RequiredHnsTlsaMissing) => {
                last_retryable_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable_error.unwrap_or(PlanBuildError::Unsupported))
}

fn build_validated_origin_plan_for_service(
    session: &mut RootResolutionSession<'_>,
    query: OriginQuery,
    alias_path: Vec<AliasStep>,
    terminal_target: CanonicalHost,
    service: ServiceBinding,
) -> Result<ValidatedOriginPlan, PlanBuildError> {
    let (endpoint_alias_path, endpoint_target, endpoints) =
        resolve_service_endpoints(session, service.service_target(), service.effective_port())?;
    if endpoints.is_empty() {
        return Err(PlanBuildError::NoUsableEndpoint);
    }

    let (tls_policy, tlsa_records, icann_chain_override) = if query.scheme().uses_tls() {
        let transport = service.transport();
        let tlsa_owner = format!(
            "_{}._{}.{}",
            service.effective_port(),
            match transport {
                ServiceTransport::Tcp => "tcp",
                ServiceTransport::Udp => "udp",
            },
            query.host()
        );
        // An exact origin RRset returned without a covering RRSIG by the
        // validating ICANN DoH boundary already establishes the
        // proven-insecure branch. TLSA below that unsigned delegation cannot
        // authenticate DANE policy, so do not let a broken authoritative
        // server's optional TLSA lookup prevent the defined WebPKI fallback.
        //
        // Do not generalize from the aggregate AD bit alone: a signed origin
        // CNAME can point into an unsigned target and make the complete answer
        // insecure while a secure TLSA RRset at the origin remains usable.
        let (records, answer_secure) = if session.icann_origin_insecure_delegation_observed() {
            (Vec::new(), false)
        } else {
            resolve_tlsa(session, &tlsa_owner)?
        };
        match session.namespace {
            Namespace::Hns => {
                if !answer_secure {
                    return Err(PlanBuildError::Resolver(ResolverError::DnssecFailed));
                }
                if records.is_empty() {
                    // A DNSSEC-secure HNS address is still namespace
                    // presence. The current atomic plan cannot represent
                    // that presence without the TLSA policy required for an
                    // HTTPS connection, so fail the whole classification
                    // closed instead of converting it into HNS absence and
                    // silently selecting ICANN.
                    return Err(PlanBuildError::RequiredHnsTlsaMissing);
                }
                (TlsTrustPolicy::Dane, records, None)
            }
            Namespace::Icann if answer_secure && !records.is_empty() => {
                (TlsTrustPolicy::Dane, records, Some(IcannChainState::Secure))
            }
            Namespace::Icann if answer_secure => (
                TlsTrustPolicy::WebPkiAuthenticatedAbsence,
                Vec::new(),
                Some(IcannChainState::Secure),
            ),
            Namespace::Icann => (
                TlsTrustPolicy::WebPkiInsecureDelegation,
                Vec::new(),
                Some(IcannChainState::ProvenInsecure),
            ),
        }
    } else {
        (TlsTrustPolicy::Cleartext, Vec::new(), None)
    };

    if session.namespace == Namespace::Hns && session.answers.iter().any(|answer| !answer.secure) {
        return Err(PlanBuildError::Resolver(ResolverError::DnssecFailed));
    }
    let (provenance, freshness) = session.evidence(icann_chain_override)?;
    ValidatedOriginPlan::new(OriginPlanInput {
        namespace: session.namespace,
        query,
        alias_path,
        terminal_target,
        endpoint_alias_path,
        endpoint_target,
        endpoints,
        service,
        tls_policy,
        tlsa_records,
        provenance,
        freshness,
    })
    .map_err(|_| PlanBuildError::Malformed)
}

fn validated_root_absence(
    session: &RootResolutionSession<'_>,
) -> Result<ValidatedAbsence, PlanBuildError> {
    let (provenance, mut freshness) = session.evidence(None)?;
    let kind = match session.namespace {
        Namespace::Hns => {
            let original_root =
                hns_root_label(session.query.host().as_str()).map_err(PlanBuildError::Resolver)?;
            let original = session
                .hns_lineage
                .ok_or(PlanBuildError::Malformed)?
                .exact(&original_root)
                .map_err(PlanBuildError::Resolver)?
                .ok_or(PlanBuildError::Malformed)?;
            if !original.exists {
                AbsenceKind::HnsCurrentUrkelNonInclusion
            } else if session.answers.iter().all(|answer| answer.secure) {
                AbsenceKind::DnssecAuthenticatedNoUsableEndpoint
            } else {
                return Err(PlanBuildError::Resolver(ResolverError::DnssecFailed));
            }
        }
        Namespace::Icann => {
            let secure = session
                .icann_observations
                .iter()
                .all(|observation| observation.secure);
            let nxdomain = session
                .icann_observations
                .iter()
                .any(|observation| observation.kind == IcannDohAnswerKind::NxDomain);
            match (secure, nxdomain) {
                (true, true) => AbsenceKind::DnssecAuthenticatedNxDomain,
                (true, false) => AbsenceKind::DnssecAuthenticatedNoUsableEndpoint,
                (false, true) => AbsenceKind::IcannInsecureNxDomain,
                (false, false) => AbsenceKind::IcannInsecureNoUsableEndpoint,
            }
        }
    };
    if session.namespace == Namespace::Hns && kind != AbsenceKind::HnsCurrentUrkelNonInclusion {
        // The legacy delegated resolver returns a typed authenticated negative
        // result but does not expose the denial RRset TTL/RRSIG lifetime.
        // Never let that discarded lifetime inherit the longer Urkel-anchor
        // window: retain it for one second at most, also bounded by the anchor.
        let observed_at_unix = freshness.observed_at_unix().max(now_unix_seconds());
        let expires_at_unix = freshness
            .expires_at_unix()
            .min(observed_at_unix.saturating_add(HNS_DELEGATED_DNS_EVIDENCE_TTL_SECONDS));
        freshness = Freshness::new(observed_at_unix, expires_at_unix)
            .map_err(|_| PlanBuildError::Malformed)?;
    }
    ValidatedAbsence::new(
        session.namespace,
        session.query.clone(),
        kind,
        provenance,
        freshness,
    )
    .map_err(|_| PlanBuildError::Malformed)
}

fn plan_build_failure_kind(error: &PlanBuildError) -> RootFailureKind {
    match error {
        PlanBuildError::Resolver(ResolverError::DnsTransport(message))
            if message.contains("timed out") || message.contains("timeout") =>
        {
            RootFailureKind::Timeout
        }
        PlanBuildError::Resolver(
            ResolverError::DnsTransport(_) | ResolverError::Port53InterceptionDetected,
        ) => RootFailureKind::Transport,
        PlanBuildError::Resolver(
            ResolverError::ProofUnavailable | ResolverError::LocalChainNotCurrent,
        ) => RootFailureKind::StaleHnsAnchor,
        PlanBuildError::Resolver(
            ResolverError::DnssecFailed | ResolverError::RelayDnssecFailed,
        ) => RootFailureKind::BogusDnssec,
        PlanBuildError::Resolver(ResolverError::UnsupportedBackend)
        | PlanBuildError::Unsupported => RootFailureKind::Unsupported,
        PlanBuildError::Malformed
        | PlanBuildError::Resolver(
            ResolverError::InvalidDnsResponse
            | ResolverError::ProofNameMismatch
            | ResolverError::InvalidAuthoritativeDoh,
        ) => RootFailureKind::MalformedResponse,
        PlanBuildError::NoUsableEndpoint => RootFailureKind::IndeterminateDnssec,
        PlanBuildError::RequiredHnsTlsaMissing => RootFailureKind::Unsupported,
        PlanBuildError::Resolver(_) => RootFailureKind::Internal,
    }
}

fn hns_network(network: NetworkKind) -> HnsNetwork {
    match network {
        NetworkKind::Mainnet => HnsNetwork::Mainnet,
        NetworkKind::Testnet => HnsNetwork::Testnet,
        NetworkKind::Regtest => HnsNetwork::Regtest,
    }
}

fn namespace_from_stored(namespace: StoredNamespace) -> Namespace {
    match namespace {
        StoredNamespace::Hns => Namespace::Hns,
        StoredNamespace::Icann => Namespace::Icann,
    }
}

fn stored_namespace(namespace: Namespace) -> StoredNamespace {
    match namespace {
        Namespace::Hns => StoredNamespace::Hns,
        Namespace::Icann => StoredNamespace::Icann,
    }
}

fn persist_successful_namespace_decision(
    store: &NamespaceBindingStore,
    decision: Option<&NamespaceDecision>,
) -> Result<(), ResolverError> {
    let Some(decision) = decision else {
        return Ok(());
    };
    let selected = decision
        .selected_namespace()
        .ok_or(ResolverError::NamespaceUnavailable)?;
    let origin = namespace_origin_key(decision.query())?;
    store.record_success(&origin, stored_namespace(selected), now_unix_seconds())?;
    Ok(())
}

#[cfg(test)]
fn persist_successful_namespace_decision_at(
    base: &Path,
    network: NetworkKind,
    decision: Option<&NamespaceDecision>,
) -> Result<(), ResolverError> {
    let store = NamespaceBindingStore::open(base.join("namespace-bindings.sqlite"), network)?;
    persist_successful_namespace_decision(&store, decision)
}

fn namespace_origin_key(query: &OriginQuery) -> Result<NamespaceOriginKey, ResolverError> {
    NamespaceOriginKey::new(
        match query.scheme() {
            hns_namespace_resolution::OriginScheme::Http => "http",
            hns_namespace_resolution::OriginScheme::Https => "https",
            hns_namespace_resolution::OriginScheme::Ws => "ws",
            hns_namespace_resolution::OriginScheme::Wss => "wss",
        },
        query.host().as_str(),
        query.origin_port().get(),
    )
}

fn default_service_binding(
    query: &OriginQuery,
    target: &CanonicalHost,
) -> Result<ServiceBinding, PlanBuildError> {
    ServiceBinding::new(ServiceBindingInput {
        priority: None,
        service_target: target.clone(),
        mandatory_keys: Vec::new(),
        advertised_alpn: Vec::new(),
        selected_protocol: ApplicationProtocol::Http11,
        effective_port: query.origin_port(),
        transport: ServiceTransport::Tcp,
        connection_hints: Vec::new(),
        ech_config: None,
        parameters: Vec::new(),
    })
    .map_err(|_| PlanBuildError::Malformed)
}

fn resolve_https_service(
    session: &mut RootResolutionSession<'_>,
    origin_host: &CanonicalHost,
) -> Result<(Vec<AliasStep>, CanonicalHost, Vec<ServiceBinding>), PlanBuildError> {
    let mut owner = origin_host.clone();
    let mut aliases = Vec::new();
    for _ in 0..=hns_namespace_resolution::MAX_ALIAS_STEPS {
        let answer = session.resolve(&owner, RecordType::Https)?;
        let owner_name =
            DnsName::from_ascii(owner.as_str()).map_err(|_| PlanBuildError::Malformed)?;
        let owner_cnames = records_for_owner(&answer.records, &owner_name, RecordType::Cname)?;
        let owner_https = records_for_owner(&answer.records, &owner_name, RecordType::Https)?;
        if !owner_cnames.is_empty() && !owner_https.is_empty() {
            return Err(PlanBuildError::Malformed);
        }
        if let Some(target) = one_cname_target(&owner_cnames)? {
            let target = canonical_dns_host(&target)?;
            aliases.push(
                AliasStep::new(AliasKind::Cname, owner, target.clone())
                    .map_err(|_| PlanBuildError::Malformed)?,
            );
            owner = target;
            continue;
        }

        let mut alias_mode = Vec::new();
        let mut service_mode = Vec::new();
        for record in owner_https {
            let parsed = SvcbRecord::from_record(record).map_err(|_| PlanBuildError::Malformed)?;
            if parsed.is_alias_mode() {
                alias_mode.push(parsed);
            } else {
                service_mode.push((record, parsed));
            }
        }
        if !alias_mode.is_empty() {
            if alias_mode.len() != 1 || !service_mode.is_empty() {
                return Err(PlanBuildError::Malformed);
            }
            let alias = alias_mode.pop().ok_or(PlanBuildError::Malformed)?;
            if alias.target_name == DnsName::root() || !alias.params.is_empty() {
                return Err(PlanBuildError::Malformed);
            }
            let target = canonical_dns_host(&alias.target_name)?;
            aliases.push(
                AliasStep::new(AliasKind::Https, owner, target.clone())
                    .map_err(|_| PlanBuildError::Malformed)?,
            );
            owner = target;
            continue;
        }
        if service_mode.is_empty() {
            let service = default_service_binding(session.query, &owner)?;
            return Ok((aliases, owner, vec![service]));
        }
        let services = select_service_bindings(session.query, &owner, service_mode)?;
        return Ok((aliases, owner, services));
    }
    Err(PlanBuildError::Malformed)
}

fn select_service_bindings(
    query: &OriginQuery,
    owner: &CanonicalHost,
    mut candidates: Vec<(&ResourceRecord, SvcbRecord)>,
) -> Result<Vec<ServiceBinding>, PlanBuildError> {
    candidates.sort_by(|(left_record, left), (right_record, right)| {
        left.svc_priority
            .cmp(&right.svc_priority)
            .then_with(|| left_record.rdata.cmp(&right_record.rdata))
    });
    let mut saw_unsupported = false;
    for (_record, candidate) in candidates {
        match service_bindings_from_svcb(query, owner, &candidate) {
            Ok(services) => return Ok(services),
            Err(PlanBuildError::Unsupported) => saw_unsupported = true,
            Err(error) => return Err(error),
        }
    }
    if saw_unsupported {
        Err(PlanBuildError::Unsupported)
    } else {
        Err(PlanBuildError::Malformed)
    }
}

fn service_bindings_from_svcb(
    query: &OriginQuery,
    owner: &CanonicalHost,
    svcb: &SvcbRecord,
) -> Result<Vec<ServiceBinding>, PlanBuildError> {
    let mandatory_keys = svcb
        .param(SVCB_PARAM_MANDATORY)
        .map(|value| {
            value
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if mandatory_keys.iter().any(|key| {
        !matches!(
            *key,
            SVCB_PARAM_ALPN | SVCB_PARAM_NO_DEFAULT_ALPN | SVCB_PARAM_PORT
        )
    }) {
        return Err(PlanBuildError::Unsupported);
    }
    let advertised_alpn = svcb.alpn_ids().map_err(|_| PlanBuildError::Malformed)?;
    let selected_protocols = application_protocol_candidates(
        query.supported_protocols(),
        &advertised_alpn,
        svcb.param(SVCB_PARAM_NO_DEFAULT_ALPN).is_some(),
    );
    if selected_protocols.is_empty() {
        return Err(PlanBuildError::Unsupported);
    }
    let effective_port = match svcb.port().map_err(|_| PlanBuildError::Malformed)? {
        Some(port) => NonZeroU16::new(port).ok_or(PlanBuildError::Malformed)?,
        None => query.origin_port(),
    };
    let service_target = if svcb.target_name == DnsName::root() {
        owner.clone()
    } else {
        canonical_dns_host(&svcb.target_name)?
    };
    // The current native transport deliberately does not consume address
    // hints or ECH. Non-mandatory values are therefore not connection-used
    // plan fields; mandatory variants were rejected above.
    let mut parameters = Vec::new();
    for parameter in &svcb.params {
        if matches!(
            parameter.key,
            SVCB_PARAM_ALPN | SVCB_PARAM_NO_DEFAULT_ALPN | SVCB_PARAM_PORT
        ) {
            parameters.push(
                ServiceParameter::new(parameter.key, parameter.value.clone())
                    .map_err(|_| PlanBuildError::Malformed)?,
            );
        }
    }
    selected_protocols
        .into_iter()
        .map(|selected_protocol| {
            let transport = if selected_protocol == ApplicationProtocol::Http3 {
                ServiceTransport::Udp
            } else {
                ServiceTransport::Tcp
            };
            ServiceBinding::new(ServiceBindingInput {
                priority: Some(svcb.svc_priority),
                service_target: service_target.clone(),
                mandatory_keys: mandatory_keys.clone(),
                advertised_alpn: advertised_alpn.clone(),
                selected_protocol,
                effective_port,
                transport,
                connection_hints: Vec::new(),
                ech_config: None,
                parameters: parameters.clone(),
            })
            .map_err(|_| PlanBuildError::Malformed)
        })
        .collect()
}

fn application_protocol_candidates(
    capabilities: hns_namespace_resolution::ProtocolCapabilities,
    alpn: &[Vec<u8>],
    no_default_alpn: bool,
) -> Vec<ApplicationProtocol> {
    let mut protocols = Vec::new();
    if capabilities.supports(ApplicationProtocol::Http3)
        && alpn
            .iter()
            .any(|identifier| identifier == b"h3" || identifier.starts_with(b"h3-"))
    {
        protocols.push(ApplicationProtocol::Http3);
    }
    if capabilities.supports(ApplicationProtocol::Http2)
        && alpn.iter().any(|identifier| identifier == b"h2")
    {
        protocols.push(ApplicationProtocol::Http2);
    }
    if capabilities.supports(ApplicationProtocol::Http11)
        && (alpn.iter().any(|identifier| identifier == b"http/1.1") || !no_default_alpn)
    {
        protocols.push(ApplicationProtocol::Http11);
    }
    protocols
}

type AddressResolution = (Vec<AliasStep>, CanonicalHost, Vec<IpAddr>);

fn resolve_service_endpoints(
    session: &mut RootResolutionSession<'_>,
    service_target: &CanonicalHost,
    port: NonZeroU16,
) -> Result<(Vec<AliasStep>, CanonicalHost, Vec<SocketAddr>), PlanBuildError> {
    let ipv4 = resolve_address_family(session, service_target, RecordType::A)?;
    if session.last_icann_answer_kind() == Some(IcannDohAnswerKind::NxDomain) {
        return Err(PlanBuildError::NoUsableEndpoint);
    }
    let ipv6 = resolve_address_family(session, service_target, RecordType::Aaaa)?;
    if session.last_icann_answer_kind() == Some(IcannDohAnswerKind::NxDomain) {
        return if ipv4.2.is_empty() {
            Err(PlanBuildError::NoUsableEndpoint)
        } else {
            Err(PlanBuildError::Malformed)
        };
    }
    if ipv4.0 != ipv6.0 || ipv4.1 != ipv6.1 {
        return Err(PlanBuildError::Malformed);
    }
    let (alias_path, endpoint_target, mut addresses) = ipv4;
    addresses.extend(ipv6.2);
    if addresses.is_empty() {
        return Err(PlanBuildError::NoUsableEndpoint);
    }
    addresses.sort_unstable();
    addresses.dedup();
    Ok((
        alias_path,
        endpoint_target,
        addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port.get()))
            .collect(),
    ))
}

fn resolve_address_family(
    session: &mut RootResolutionSession<'_>,
    start: &CanonicalHost,
    qtype: RecordType,
) -> Result<AddressResolution, PlanBuildError> {
    let mut owner = start.clone();
    let mut aliases = Vec::new();
    for _ in 0..=hns_namespace_resolution::MAX_ALIAS_STEPS {
        let answer = session.resolve(&owner, qtype)?;
        let owner_name =
            DnsName::from_ascii(owner.as_str()).map_err(|_| PlanBuildError::Malformed)?;
        let cnames = records_for_owner(&answer.records, &owner_name, RecordType::Cname)?;
        let addresses = records_for_owner(&answer.records, &owner_name, qtype)?;
        if !cnames.is_empty() && !addresses.is_empty() {
            return Err(PlanBuildError::Malformed);
        }
        if let Some(target) = one_cname_target(&cnames)? {
            let target = canonical_dns_host(&target)?;
            aliases.push(
                AliasStep::new(AliasKind::Cname, owner, target.clone())
                    .map_err(|_| PlanBuildError::Malformed)?,
            );
            owner = target;
            continue;
        }
        let addresses = addresses
            .iter()
            .map(|record| match (qtype, record.rdata.as_slice()) {
                (RecordType::A, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
                (RecordType::Aaaa, bytes) if bytes.len() == 16 => {
                    let mut address = [0u8; 16];
                    address.copy_from_slice(bytes);
                    Ok(IpAddr::V6(Ipv6Addr::from(address)))
                }
                _ => Err(PlanBuildError::Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok((aliases, owner, addresses));
    }
    Err(PlanBuildError::Malformed)
}

fn resolve_tlsa(
    session: &mut RootResolutionSession<'_>,
    start: &str,
) -> Result<(Vec<CanonicalTlsa>, bool), PlanBuildError> {
    let mut owner = DnsName::from_ascii(start).map_err(|_| PlanBuildError::Malformed)?;
    let mut secure = true;
    let mut seen = Vec::new();
    for _ in 0..=hns_namespace_resolution::MAX_ALIAS_STEPS {
        if seen.contains(&owner) {
            return Err(PlanBuildError::Malformed);
        }
        seen.push(owner.clone());
        let owner_text = owner.to_string();
        let answer = session.resolve_name(&owner_text, RecordType::Tlsa)?;
        secure &= answer.secure;
        let cnames = records_for_owner(&answer.records, &owner, RecordType::Cname)?;
        let tlsa = records_for_owner(&answer.records, &owner, RecordType::Tlsa)?;
        if !cnames.is_empty() && !tlsa.is_empty() {
            return Err(PlanBuildError::Malformed);
        }
        if !secure && session.namespace == Namespace::Icann {
            return Ok((Vec::new(), false));
        }
        if let Some(target) = one_cname_target(&cnames)? {
            owner = target;
            continue;
        }
        let records = tlsa
            .iter()
            .map(|record| {
                CanonicalTlsa::new(record.rdata.clone()).map_err(|_| PlanBuildError::Unsupported)
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok((records, secure));
    }
    Err(PlanBuildError::Malformed)
}

fn records_for_owner<'a>(
    records: &'a [ResourceRecord],
    owner: &DnsName,
    record_type: RecordType,
) -> Result<Vec<&'a ResourceRecord>, PlanBuildError> {
    let matches = records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == record_type)
        .collect::<Vec<_>>();
    if matches.iter().any(|record| record.class != DNS_CLASS_IN) {
        Err(PlanBuildError::Malformed)
    } else {
        Ok(matches)
    }
}

fn one_cname_target(records: &[&ResourceRecord]) -> Result<Option<DnsName>, PlanBuildError> {
    let Some(record) = records.first() else {
        return Ok(None);
    };
    let target = cname_record_target(record)?;
    for record in &records[1..] {
        if cname_record_target(record)? != target {
            return Err(PlanBuildError::Malformed);
        }
    }
    Ok(Some(target))
}

fn cname_record_target(record: &ResourceRecord) -> Result<DnsName, PlanBuildError> {
    if record.record_type != RecordType::Cname || record.class != DNS_CLASS_IN {
        return Err(PlanBuildError::Malformed);
    }
    let (target, end) =
        DnsName::parse_wire(&record.rdata, 0).map_err(|_| PlanBuildError::Malformed)?;
    if end != record.rdata.len() || target == DnsName::root() {
        return Err(PlanBuildError::Malformed);
    }
    Ok(target)
}

fn canonical_dns_host(name: &DnsName) -> Result<CanonicalHost, PlanBuildError> {
    CanonicalHost::parse(&name.to_string()).map_err(|_| PlanBuildError::Malformed)
}

fn namespace_decision_trace_json(decision: &NamespaceDecision) -> String {
    let outcome = match decision.kind() {
        OutcomeKind::HnsOnly => "hnsOnly",
        OutcomeKind::IcannOnly => "icannOnly",
        OutcomeKind::BothConvergent => "bothConvergent",
        OutcomeKind::BothDivergent => "bothDivergent",
        OutcomeKind::Neither => "neither",
    };
    let selected = decision
        .selected_namespace()
        .map(|namespace| match namespace {
            Namespace::Hns => r#""hns""#,
            Namespace::Icann => r#""icann""#,
        })
        .unwrap_or("null");
    let reason =
        namespace_selection_reason_trace_name(decision.kind(), decision.selection_reason());
    let (hns_state, icann_state) = match decision.outcome() {
        NamespaceOutcome::HnsOnly { icann_absence, .. } => {
            ("securePresent", icann_absence_state(icann_absence.kind()))
        }
        NamespaceOutcome::IcannOnly { plan, .. } => ("authenticatedAbsent", icann_plan_state(plan)),
        NamespaceOutcome::BothConvergent { icann, .. }
        | NamespaceOutcome::BothDivergent { icann, .. } => {
            ("securePresent", icann_plan_state(icann))
        }
        NamespaceOutcome::Neither { hns: _, icann } => {
            ("authenticatedAbsent", icann_absence_state(icann.kind()))
        }
    };
    let divergence = decision
        .divergence()
        .map(|mask| mask.bits().to_string())
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"schemaVersion":2,"outcome":"{outcome}","selected":{selected},"reason":"{reason}","fingerprint":"{}","divergenceMask":{divergence},"hnsState":"{hns_state}","icannState":"{icann_state}","hns":{{"state":"{hns_state}","rcode":null,"denial":null,"failure":null}},"icann":{{"state":"{icann_state}","rcode":null,"denial":null,"failure":null}}}}"#,
        decision_fingerprint(decision).to_hex(),
    )
}

fn icann_absence_state(kind: AbsenceKind) -> &'static str {
    match kind {
        AbsenceKind::IcannInsecureNxDomain | AbsenceKind::IcannInsecureNoUsableEndpoint => {
            "insecureAbsent"
        }
        AbsenceKind::DnssecAuthenticatedNxDomain
        | AbsenceKind::DnssecAuthenticatedNoUsableEndpoint => "authenticatedAbsent",
        AbsenceKind::HnsCurrentUrkelNonInclusion => "unknown",
    }
}

fn namespace_selection_reason_trace_name(
    kind: OutcomeKind,
    reason: Option<SelectionReason>,
) -> &'static str {
    match (kind, reason) {
        (_, Some(SelectionReason::ExplicitPin)) => "explicitPin",
        (_, Some(SelectionReason::StickyBinding)) => "stickyBinding",
        (OutcomeKind::BothConvergent, Some(SelectionReason::IcannDefault)) => "convergentDefault",
        (OutcomeKind::BothDivergent, Some(SelectionReason::IcannDefault)) => "icannDefault",
        (OutcomeKind::HnsOnly | OutcomeKind::IcannOnly, Some(SelectionReason::SingleRoot)) => {
            "onlyAvailableRoot"
        }
        _ => "unavailable",
    }
}

fn icann_plan_state(plan: &ValidatedOriginPlan) -> &'static str {
    match plan.provenance() {
        EvidenceProvenance::IcannDoh {
            chain_state: IcannChainState::Secure,
        } => "securePresent",
        EvidenceProvenance::IcannDoh {
            chain_state: IcannChainState::ProvenInsecure,
        } => "insecurePresent",
        EvidenceProvenance::Hns { .. } => "unknown",
    }
}

fn indeterminate_namespace_trace_json(
    _query: &OriginQuery,
    error: &hns_namespace_resolution::ClassificationError,
) -> String {
    let (hns_state, icann_state, hns_failure, icann_failure) = match error {
        hns_namespace_resolution::ClassificationError::RootFailed { hns, icann } => (
            root_resolution_trace_state(hns),
            root_resolution_trace_state(icann),
            hns.failure().map(|failure| format!("{:?}", failure.kind())),
            icann
                .failure()
                .map(|failure| format!("{:?}", failure.kind())),
        ),
        _ => ("unknown", "unknown", None, None),
    };
    let hns_failure = hns_failure
        .map(|failure| format!(r#""{}""#, json_escape(&failure)))
        .unwrap_or_else(|| "null".to_owned());
    let icann_failure = icann_failure
        .map(|failure| format!(r#""{}""#, json_escape(&failure)))
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"schemaVersion":2,"outcome":"indeterminate","selected":null,"reason":"unavailable","fingerprint":null,"divergenceMask":null,"hnsState":"{hns_state}","icannState":"{icann_state}","hns":{{"state":"{hns_state}","rcode":null,"denial":null,"failure":{hns_failure}}},"icann":{{"state":"{icann_state}","rcode":null,"denial":null,"failure":{icann_failure}}}}}"#
    )
}

fn root_resolution_trace_state(state: &RootResolutionState) -> &'static str {
    match state.disposition() {
        RootResolutionDisposition::Present => "present",
        RootResolutionDisposition::Absent => "absent",
        RootResolutionDisposition::Failed => "failed",
    }
}

fn default_icann_doh_endpoint() -> HnsDohEndpoint {
    HnsDohEndpoint {
        host: ICANN_DOH_HOST.to_owned(),
        port: 443,
        path_and_query: ICANN_DOH_PATH.to_owned(),
    }
}

#[cfg(test)]
fn doh_fallback_reason(error: &ResolverError) -> Option<&'static str> {
    match error {
        ResolverError::ProofUnavailable => Some("local_hns_proof_unavailable"),
        ResolverError::LocalChainNotCurrent => Some("local_chain_not_current"),
        ResolverError::NoNameserverAddress => Some("no_verified_nameserver_address"),
        _ => None,
    }
}

fn configured_doh_transport_fallback_reason(error: &ResolverError) -> Option<&'static str> {
    match error {
        ResolverError::DnsTransport(_) => Some("earlier_hns_transports_unavailable"),
        ResolverError::Port53InterceptionDetected => Some("port53_interception_detected"),
        _ => None,
    }
}

fn delegated_p2p_fallback_allowed(error: &ResolverError) -> bool {
    matches!(
        error,
        ResolverError::DnsTransport(_) | ResolverError::Port53InterceptionDetected
    )
}

fn fetch_icann_doh_message(
    http: &TcpHttpTransport,
    endpoint: &HnsDohEndpoint,
    bootstrap_addresses: &[IpAddr],
    body: &[u8],
    trace: &DnsTraceRecorder,
) -> Result<OriginResponse, TransportError> {
    let mut last_error = None;
    for bootstrap in bootstrap_addresses {
        let started = Instant::now();
        let response = http.fetch_rfc8484_post(&doh_origin_request(
            endpoint,
            Some(bootstrap.to_string()),
            body.to_vec(),
        ));
        trace.push(doh_trace_event(
            "icann_doh",
            format!("{} via {bootstrap}", endpoint.display()),
            body,
            elapsed_millis(started),
            &response,
        ));
        match response {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        TransportError::Io("no explicit ICANN DoH bootstrap address is configured".to_owned())
    }))
}

fn doh_origin_request(
    endpoint: &HnsDohEndpoint,
    connect_host: Option<String>,
    body: Vec<u8>,
) -> OriginRequest {
    OriginRequest {
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: endpoint.host.clone(),
        connect_host,
        port: endpoint.port,
        path_and_query: endpoint.path_and_query.clone(),
        protocol: OriginProtocol::Http11,
        tls: TlsValidation::default(),
        headers: vec![
            ("Accept".to_owned(), "application/dns-message".to_owned()),
            (
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            ),
        ],
        body,
    }
}

/// Constructs a configured-recursive request only with a pre-resolved address.
/// Keeping the address mandatory prevents this path from ever falling through
/// to the operating system's DNS resolver.
fn configured_doh_origin_request(
    endpoint: &HnsDohEndpoint,
    connect_address: IpAddr,
    body: Vec<u8>,
) -> OriginRequest {
    doh_origin_request(endpoint, Some(connect_address.to_string()), body)
}

fn fetch_authoritative_doh_message(
    http: &TcpHttpTransport,
    endpoint: &AuthoritativeDohEndpoint,
    body: Vec<u8>,
) -> Result<OriginResponse, TransportError> {
    http.fetch(&OriginRequest {
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: endpoint.host.clone(),
        connect_host: Some(endpoint.connect_addr.to_string()),
        port: endpoint.port,
        path_and_query: endpoint.path_and_query.clone(),
        protocol: OriginProtocol::Http2,
        tls: authoritative_doh_tls_validation(endpoint),
        headers: vec![
            ("Accept".to_owned(), "application/dns-message".to_owned()),
            (
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            ),
        ],
        body,
    })
}

fn authoritative_doh_tls_validation(endpoint: &AuthoritativeDohEndpoint) -> TlsValidation {
    match &endpoint.tls_authentication {
        AuthoritativeDohTlsAuthentication::WebPki => TlsValidation::default(),
        AuthoritativeDohTlsAuthentication::HnsProofTlsa(records) => {
            let mut validation = TlsValidation::hns_strict(true, records.clone());
            validation.tlsa_source = Some(TlsaRecordSource::HnsProofTxt);
            validation.service_port = endpoint.port;
            validation
        }
    }
}

fn authoritative_doh_endpoint_display(endpoint: &AuthoritativeDohEndpoint) -> String {
    let base = if endpoint.port == 443 {
        format!("https://{}{}", endpoint.host, endpoint.path_and_query)
    } else {
        format!(
            "https://{}:{}{}",
            endpoint.host, endpoint.port, endpoint.path_and_query
        )
    };
    let authentication = match &endpoint.tls_authentication {
        AuthoritativeDohTlsAuthentication::WebPki => "WebPKI",
        AuthoritativeDohTlsAuthentication::HnsProofTlsa(_) => "HNS-proof TLSA",
    };
    format!("{base} via {} [{authentication}]", endpoint.connect_addr)
}

fn doh_http_status_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn doh_response_has_dns_message_content_type(response: &OriginResponse) -> bool {
    response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .any(|(_, value)| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .is_some_and(|media_type| {
                    media_type.eq_ignore_ascii_case("application/dns-message")
                })
        })
}

fn recursive_doh_query(query: &[u8]) -> Result<(Vec<u8>, u16), ResolverError> {
    if query.len() < 4 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let original_id = u16::from_be_bytes([query[0], query[1]]);
    let mut query = query.to_vec();
    query[0] = 0;
    query[1] = 0;
    query[2] |= 0x01;
    Ok((query, original_id))
}

fn restore_doh_response_id(body: &[u8], original_id: u16) -> Result<Vec<u8>, ResolverError> {
    if body.len() < 2 || body[0] != 0 || body[1] != 0 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let mut body = body.to_vec();
    body[..2].copy_from_slice(&original_id.to_be_bytes());
    Ok(body)
}

fn build_doh_query(id: u16, qname: &DnsName, qtype: RecordType) -> Result<Vec<u8>, ResolverError> {
    let message = DnsMessage {
        header: DnsHeader {
            id,
            flags: DnsFlags::new(DNS_RECURSION_DESIRED_FLAG | DNS_AUTHENTIC_DATA_FLAG),
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 1,
        },
        questions: vec![DnsQuestion {
            name: qname.clone(),
            record_type: qtype,
            class: DNS_CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![ResourceRecord {
            name: DnsName::root(),
            record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
            class: DEFAULT_DNS_UDP_PAYLOAD as u16,
            ttl: DNSSEC_DO_FLAG,
            rdata: Vec::new(),
        }],
    };

    message
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_UDP_PAYLOAD,
        })
        .map_err(|_| ResolverError::InvalidDnsResponse)
}

#[cfg(test)]
fn doh_answer_from_body(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    body: &[u8],
) -> Result<ResolutionAnswer, ResolverError> {
    doh_answer_and_observation_from_body(id, qname, qtype, body).map(|(answer, _)| answer)
}

fn doh_answer_and_observation_from_body(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    body: &[u8],
) -> Result<(ResolutionAnswer, IcannDohObservation), ResolverError> {
    let message = DnsMessage::parse(body).map_err(|_| ResolverError::InvalidDnsResponse)?;
    let rcode = message.header.flags.rcode();
    if message.header.id != id
        || !message.header.flags.is_response()
        || message.header.flags.truncated()
        || message.header.flags.opcode() != 0
        || message.questions.len() != 1
        || message.questions[0].name != *qname
        || message.questions[0].record_type != qtype
        || message.questions[0].class != DNS_CLASS_IN
    {
        return Err(ResolverError::InvalidDnsResponse);
    }
    if !matches!(rcode, DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN) {
        return Err(ResolverError::DnsResponseCode(rcode));
    }

    let secure = message.header.flags.bits() & DNS_AUTHENTIC_DATA_FLAG != 0;
    let has_relevant_answer = message.answers.iter().any(|record| {
        record.class == DNS_CLASS_IN
            && record.name == *qname
            && (record.record_type == qtype || record.record_type == RecordType::Cname)
    });
    if rcode == DNS_RCODE_NXDOMAIN && !message.answers.is_empty() {
        // CNAME followed by NXDOMAIN is valid DNS, but this adapter does not
        // yet retain and validate the complete alias-plus-denial chain.
        // Discarding the answer would let the negative evidence outlive a
        // short CNAME TTL, so reject this shape fail closed.
        return Err(ResolverError::InvalidDnsResponse);
    }
    let kind = if rcode == DNS_RCODE_NXDOMAIN {
        IcannDohAnswerKind::NxDomain
    } else if has_relevant_answer {
        IcannDohAnswerKind::Present
    } else {
        IcannDohAnswerKind::NoData
    };
    let observed_at_unix = now_unix_seconds();
    let expires_at_unix = icann_doh_evidence_expiry(&message, kind, secure, observed_at_unix)
        .ok_or(ResolverError::InvalidDnsResponse)?;
    if expires_at_unix <= observed_at_unix {
        return Err(ResolverError::InvalidDnsResponse);
    }
    let observation = IcannDohObservation {
        kind,
        secure,
        rcode,
        observed_at_unix,
        expires_at_unix,
    };
    Ok((
        ResolutionAnswer {
            name: qname.clone(),
            records: if kind == IcannDohAnswerKind::NxDomain {
                Vec::new()
            } else {
                message.answers
            },
            secure,
        },
        observation,
    ))
}

fn icann_doh_evidence_expiry(
    message: &DnsMessage,
    kind: IcannDohAnswerKind,
    secure: bool,
    observed_at_unix: u64,
) -> Option<u64> {
    let ttl = match kind {
        IcannDohAnswerKind::Present => message
            .answers
            .iter()
            .filter(|record| {
                record.class == DNS_CLASS_IN && record.record_type != RecordType::Rrsig
            })
            .map(|record| record.ttl)
            .min(),
        IcannDohAnswerKind::NoData | IcannDohAnswerKind::NxDomain => message
            .authorities
            .iter()
            .filter(|record| record.class == DNS_CLASS_IN && record.record_type == RecordType::Soa)
            .filter_map(soa_negative_ttl)
            .min(),
    }?;
    let ttl = u64::from(ttl).min(NAMESPACE_EVIDENCE_MAX_TTL_SECONDS);
    if ttl == 0 {
        return None;
    }
    let ttl_expiry = observed_at_unix.checked_add(ttl)?;
    let signature_expiry = if secure
        && matches!(
            kind,
            IcannDohAnswerKind::NoData | IcannDohAnswerKind::NxDomain
        ) {
        Some(secure_negative_signature_expiry(message)?)
    } else {
        message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .filter(|record| {
                record.class == DNS_CLASS_IN && record.record_type == RecordType::Rrsig
            })
            .filter_map(rrsig_expiration)
            .map(u64::from)
            .min()
    };
    Some(signature_expiry.map_or(ttl_expiry, |expiry| ttl_expiry.min(expiry)))
}

fn secure_negative_signature_expiry(message: &DnsMessage) -> Option<u64> {
    let mut rrsets = Vec::<(DnsName, RecordType)>::new();
    let mut has_soa = false;
    let mut has_denial = false;
    for record in message.authorities.iter().filter(|record| {
        record.class == DNS_CLASS_IN
            && matches!(
                record.record_type,
                RecordType::Soa | RecordType::Nsec | RecordType::Nsec3
            )
    }) {
        has_soa |= record.record_type == RecordType::Soa;
        has_denial |= matches!(record.record_type, RecordType::Nsec | RecordType::Nsec3);
        let rrset = (record.name.clone(), record.record_type);
        if !rrsets.contains(&rrset) {
            rrsets.push(rrset);
        }
    }
    if !has_soa || !has_denial {
        return None;
    }

    let mut earliest_expiry = u64::MAX;
    for (owner, covered_type) in rrsets {
        let rrset_expiry = message
            .authorities
            .iter()
            .filter(|record| {
                record.class == DNS_CLASS_IN
                    && record.name == owner
                    && rrsig_type_covered(record) == Some(covered_type)
            })
            .filter_map(rrsig_expiration)
            .map(u64::from)
            .min()?;
        earliest_expiry = earliest_expiry.min(rrset_expiry);
    }
    (earliest_expiry != u64::MAX).then_some(earliest_expiry)
}

fn soa_negative_ttl(record: &ResourceRecord) -> Option<u32> {
    let minimum = record
        .rdata
        .get(record.rdata.len().checked_sub(4)?..)?
        .try_into()
        .ok()
        .map(u32::from_be_bytes)?;
    Some(record.ttl.min(minimum))
}

fn rrsig_type_covered(record: &ResourceRecord) -> Option<RecordType> {
    if record.record_type != RecordType::Rrsig {
        return None;
    }
    let code = record
        .rdata
        .get(..2)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)?;
    Some(RecordType::from_code(code))
}

fn rrsig_expiration(record: &ResourceRecord) -> Option<u32> {
    record
        .rdata
        .get(8..12)?
        .try_into()
        .ok()
        .map(u32::from_be_bytes)
}

pub fn core_version() -> &'static str {
    concat!("hns-dane-browser-rust-core/", env!("CARGO_PKG_VERSION"))
}

pub fn diagnostics_json() -> String {
    r#"{"core":"hns-dane-browser-rust-core","version":"__VERSION__","features":["header-hash","header-pow-validation","header-mainnet-difficulty-retarget","header-mainnet-checkpoints","header-canonical-height-index","hns-name-hash","hns-dotted-root-label","urkel-proof-verification","urkel-proof-value-handoff","hns-name-state-resource-extraction","hns-resource-decoder","hns-authoritative-doh-rfc8484","hns-resource-provider-adapter","hns-memory-resource-provider","hns-sqlite-resource-provider","hns-negative-cache","hns-ttl-cache-lru","hns-resource-cache-stats","hns-resource-cache-eviction","hns-resource-cache-cap-enforcement","hns-resource-cache-chain-anchors","hns-resource-cache-reorg-invalidation","hns-resource-cache-current-tip","hns-proof-backed-resolver-boundary","hns-delegating-resolver-boundary","hns-proof-backed-ns-address-hydration","hns-authoritative-dnssec-delegated-resolver","hns-doh-compat-resolver","dns-wire","dns-svcb-https","dnssec-ds-dnskey-link","dnssec-ds-sha1","dnssec-ds-sha384","dnssec-rrsig-signed-data","dnssec-canonical-name-rdata","dnssec-ecdsa-p256-verify","dnssec-ecdsa-p384-verify","dnssec-rsa-sha1-verify","dnssec-rsa-sha256-sha512-verify","dnssec-ed25519-verify","dnssec-signed-rrset-validation","dnssec-delegated-chain-validation","dnssec-delegated-no-data-validation","dnssec-delegated-name-error-validation","dnssec-delegated-cname-chain","dnssec-child-referral-validation","dnssec-child-cname-chain","dnssec-child-no-data-validation","dnssec-child-name-error-validation","dnssec-nsec-denial-validation","dnssec-nsec3-denial-validation","dnssec-nxdomain-name-error-validation","dane-policy","dane-certificate-chain-policy","x509-spki-extraction","x509-stateless-dane-evidence","hip17-experimental-urkel-extension","rfc9102-authentication-chain-parser","p2p-codec","p2p-tcp-peer-connection","p2p-static-peer-source","p2p-dns-seed-source","p2p-getaddr-peer-discovery","p2p-discovery-rotation","p2p-peer-diversity","p2p-sqlite-peer-store","sync-coordinator","sync-header-runner","sync-multi-batch-header-runner","sync-parallel-peer-probing","sync-ranged-peer-rotation","sync-checkpoint-prefetch","sync-proof-scheduler","native-sync-once","sync-status","sync-outcome-status","sync-progress-heights","sync-high-batch-catchup","clear-resolver-cache","persistent-gateway-resolver","gateway-live-proof-fetch","gateway-header-forwarding","gateway-range-forwarding","gateway-body-forwarding","gateway-file-body-stream","chromium-browser-request-gateway","chromium-service-worker-gateway","chromium-redirect-gateway","actionable-hns-errors","hns-name-not-found-error","gateway-policy","gateway-hns-address-required","gateway-tlsa-service-scope","gateway-delegated-origin-address-lookup","gateway-origin-address-query","gateway-https-service-query","gateway-svcb-alpn-policy","gateway-actionable-nameserver-errors","gateway-cname-address-routing","chromium-proxy-gateway-hook","random-loopback-proxy-port","rust-loopback-local-hns-connect-certs","hns-websocket-native-tunnel","http-origin-transport","http-origin-connection-pooling","http2-origin-transport","http3-origin-transport","http-origin-response-framing","https-rustls-transport","https-tls-session-resumption","https-alt-svc-promotion","dane-tls-policy"],"securityDefault":"fail-closed"}"#
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace(
            "hns-doh-compat-resolver",
            "user-configured-recursive-hns-doh",
        )
}

pub fn sync_once(data_dir: &str) -> String {
    sync_once_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn sync_once_for_network(data_dir: &str, network: NetworkKind) -> String {
    sync_once_with_options(
        data_dir,
        network,
        true,
        Duration::from_secs(3),
        DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
    )
    .to_json()
}

pub fn sync_status(data_dir: &str) -> String {
    sync_status_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn sync_status_for_network(data_dir: &str, network: NetworkKind) -> String {
    runtime_status_result(
        network,
        BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .and_then(|runtime| runtime.sync_status()),
    )
    .to_json()
}

pub fn clear_resolver_cache(data_dir: &str) -> String {
    clear_resolver_cache_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn clear_resolver_cache_for_network(data_dir: &str, network: NetworkKind) -> String {
    runtime_status_result(
        network,
        BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .and_then(|runtime| runtime.clear_resolver_cache()),
    )
    .to_json()
}

pub fn install_header_snapshot(data_dir: &str, snapshot_path: &str) -> String {
    install_header_snapshot_for_network(data_dir, snapshot_path, NetworkKind::Mainnet)
}

pub fn install_header_snapshot_for_network(
    data_dir: &str,
    snapshot_path: &str,
    network: NetworkKind,
) -> String {
    runtime_status_result(
        network,
        BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .and_then(|runtime| runtime.install_header_snapshot(snapshot_path)),
    )
    .to_json()
}

pub fn reset_headers_from_peers(data_dir: &str) -> String {
    reset_headers_from_peers_for_network(data_dir, NetworkKind::Mainnet)
}

pub fn reset_headers_from_peers_for_network(data_dir: &str, network: NetworkKind) -> String {
    runtime_status_result(
        network,
        BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .and_then(|runtime| runtime.reset_headers_from_peers()),
    )
    .to_json()
}

fn sync_once_with_options(
    data_dir: &str,
    network: NetworkKind,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> NativeSyncStatus {
    runtime_status_result(
        network,
        BrowserRuntime::open(
            RuntimeConfiguration::new(data_dir, network).with_sync_options(SyncOptions {
                seed_peers: seed_on_empty,
                timeout,
                resource_cache_limit_bytes,
            }),
        )
        .and_then(|runtime| runtime.sync_once()),
    )
}

fn runtime_status_result(
    network: NetworkKind,
    result: Result<NativeSyncStatus, RuntimeError>,
) -> NativeSyncStatus {
    result.unwrap_or_else(|error| NativeSyncStatus::error_for(network, error.to_string()))
}

#[cfg(test)]
fn gateway_http_response(input: GatewayHttpRequestInput<'_>) -> Vec<u8> {
    gateway_http_response_with_transport(input, shared_http_transport(), None)
}

#[cfg(test)]
fn gateway_http_response_with_transport(
    input: GatewayHttpRequestInput<'_>,
    transport: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> Vec<u8> {
    let prepared = prepare_gateway_http_response_with_transport(
        input,
        transport.clone(),
        transport,
        peer_state,
    );
    if let Some(decision) = prepared.namespace_decision.as_ref() {
        let network = parse_gateway_headers(input.header_text)
            .map(|headers| headers.network)
            .unwrap_or(NetworkKind::Mainnet);
        let base = network_base_path(input.data_dir, network);
        if let Err(error) = persist_successful_namespace_decision_at(&base, network, Some(decision))
        {
            return plain_response_for_request(
                &input,
                500,
                "Namespace Binding Storage Error",
                &error.to_string(),
            );
        }
    }
    prepared.encoded_http
}

fn prepare_gateway_http_response_with_transport(
    input: GatewayHttpRequestInput<'_>,
    transport: impl OriginTransport,
    resolver_http: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> PreparedGatewayHttpResponse {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return PreparedGatewayHttpResponse::without_namespace_decision(
                plain_response_for_request(&input, 400, "Bad Request", &error),
            );
        }
    };
    let network = parsed_headers.network;
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = network_base_path(input.data_dir, network);
    if let Err(error) = fs::create_dir_all(&base) {
        return PreparedGatewayHttpResponse::without_namespace_decision(
            plain_response_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("create gateway directory: {error}"),
            ),
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return PreparedGatewayHttpResponse::without_namespace_decision(
                plain_response_for_request(
                    &input,
                    500,
                    "Gateway Storage Error",
                    &format!("open resource cache: {error}"),
                ),
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        GatewayResolverContext {
            network,
            mode,
            configured_hns_doh: parsed_headers.configured_hns_doh,
            experimental_p2p_dns_relay: parsed_headers.experimental_p2p_dns_relay,
            peer_state,
            relay: None,
            http: resolver_http,
        },
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let stateless_dane = stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Strict,
            stateless_dane,
            allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
            allow_unsafe_origin_ports: network == NetworkKind::Regtest,
            ..GatewayConfig::default()
        },
        resolver,
        transport,
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return PreparedGatewayHttpResponse::without_namespace_decision(
                plain_response_for_request(
                    &input,
                    500,
                    "Gateway Configuration Error",
                    &error.to_string(),
                ),
            );
        }
    };

    match gateway.handle(&request) {
        Ok(response) => {
            let namespace_decision = response.namespace_decision.clone();
            let resolver_policy = fallback_marker
                .used()
                .then_some("user-configured-recursive-hns-doh");
            let selected_namespace = response
                .namespace_decision
                .as_ref()
                .and_then(NamespaceDecision::selected_namespace);
            let security_path = security_path_name(
                &input,
                response.origin_request.port,
                response.origin_request.tls.service_transport,
                &response.origin.dane_decision,
                selected_namespace,
                &dns_trace.snapshot(),
            );
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                    origin_address: response.origin_request.connect_host.as_deref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            PreparedGatewayHttpResponse {
                encoded_http: origin_response_with_resolver_policy_and_trace(
                    response.origin,
                    resolver_policy,
                    security_path,
                    &trace,
                ),
                namespace_decision,
            }
        }
        Err(error) => {
            let (status, reason, detail) =
                map_gateway_error_for_namespace(dns_trace.selected_namespace(), &error, &dns_trace);
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            PreparedGatewayHttpResponse::without_namespace_decision(
                gateway_error_response_for_request_with_trace(
                    &input, status, reason, detail, &trace, &dns_trace,
                ),
            )
        }
    }
}

struct PreparedGatewayHttpResponse {
    encoded_http: Vec<u8>,
    namespace_decision: Option<NamespaceDecision>,
}

impl PreparedGatewayHttpResponse {
    fn without_namespace_decision(encoded_http: Vec<u8>) -> Self {
        Self {
            encoded_http,
            namespace_decision: None,
        }
    }
}

struct PreparedGatewayFileResponse {
    encoded_head: Vec<u8>,
    namespace_decision: Option<NamespaceDecision>,
}

impl PreparedGatewayFileResponse {
    fn without_namespace_decision(encoded_head: Vec<u8>) -> Self {
        Self {
            encoded_head,
            namespace_decision: None,
        }
    }
}

struct PendingBodyPath {
    path: PathBuf,
    active: bool,
}

impl PendingBodyPath {
    fn publish(mut self, destination: &Path) -> Result<(), String> {
        fs::rename(&self.path, destination)
            .map_err(|error| format!("publish response body: {error}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for PendingBodyPath {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_pending_body_file(body_path: &Path) -> Result<(PendingBodyPath, fs::File), String> {
    let parent = body_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = body_path
        .file_name()
        .ok_or_else(|| "response body path has no file name".to_owned())?;
    for _ in 0..64 {
        let sequence = GATEWAY_BODY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut pending_name = std::ffi::OsString::from(".");
        pending_name.push(file_name);
        pending_name.push(format!(".hns-pending-{}-{sequence}", std::process::id()));
        let path = parent.join(pending_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((PendingBodyPath { path, active: true }, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create pending response body: {error}")),
        }
    }
    Err("unable to allocate a unique pending response body path".to_owned())
}

#[cfg(test)]
fn gateway_http_response_body_to_file(
    input: GatewayHttpRequestInput<'_>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    let prepared = prepare_gateway_http_response_body_to_file_with_transport(
        input,
        body_path,
        shared_http_transport(),
        shared_http_transport(),
        None,
    )?;
    if let Some(decision) = prepared.namespace_decision.as_ref() {
        let network = parse_gateway_headers(input.header_text)
            .map(|headers| headers.network)
            .unwrap_or(NetworkKind::Mainnet);
        let base = network_base_path(input.data_dir, network);
        persist_successful_namespace_decision_at(&base, network, Some(decision))
            .map_err(|error| format!("persist namespace binding: {error}"))?;
    }
    Ok(prepared.encoded_head)
}

fn prepare_gateway_http_response_body_to_file_with_transport(
    input: GatewayHttpRequestInput<'_>,
    body_path: &Path,
    transport: impl OriginTransport,
    resolver_http: TcpHttpTransport,
    peer_state: Option<Arc<Mutex<()>>>,
) -> Result<PreparedGatewayFileResponse, String> {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                400,
                "Bad Request",
                &error,
                body_path,
            )
            .map(PreparedGatewayFileResponse::without_namespace_decision);
        }
    };
    let network = parsed_headers.network;
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = network_base_path(input.data_dir, network);
    if let Err(error) = fs::create_dir_all(&base) {
        return plain_response_to_file_for_request(
            &input,
            500,
            "Gateway Storage Error",
            &format!("create gateway directory: {error}"),
            body_path,
        )
        .map(PreparedGatewayFileResponse::without_namespace_decision);
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("open resource cache: {error}"),
                body_path,
            )
            .map(PreparedGatewayFileResponse::without_namespace_decision);
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        GatewayResolverContext {
            network,
            mode,
            configured_hns_doh: parsed_headers.configured_hns_doh,
            experimental_p2p_dns_relay: parsed_headers.experimental_p2p_dns_relay,
            peer_state,
            relay: None,
            http: resolver_http,
        },
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let stateless_dane = stateless_dane_config(&base, parsed_headers.stateless_dane_certificates);
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Strict,
            stateless_dane,
            allow_non_public_origin_addresses: network == NetworkKind::Regtest || cfg!(test),
            allow_unsafe_origin_ports: network == NetworkKind::Regtest,
            ..GatewayConfig::default()
        },
        resolver,
        transport,
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Configuration Error",
                &error.to_string(),
                body_path,
            )
            .map(PreparedGatewayFileResponse::without_namespace_decision);
        }
    };

    let parent = body_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("create response directory: {error}"))?;
    let (pending_body, mut body_file) = create_pending_body_file(body_path)?;
    match gateway.handle_to_writer(&request, &mut body_file) {
        Ok(response) => {
            body_file
                .flush()
                .map_err(|error| format!("flush pending response body: {error}"))?;
            drop(body_file);
            pending_body.publish(body_path)?;
            let namespace_decision = response.namespace_decision.clone();
            let resolver_policy = fallback_marker
                .used()
                .then_some("user-configured-recursive-hns-doh");
            let selected_namespace = response
                .namespace_decision
                .as_ref()
                .and_then(NamespaceDecision::selected_namespace);
            let security_path = security_path_name(
                &input,
                response.origin_request.port,
                response.origin_request.tls.service_transport,
                &response.origin.dane_decision,
                selected_namespace,
                &dns_trace.snapshot(),
            );
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                    origin_address: response.origin_request.connect_host.as_deref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            Ok(PreparedGatewayFileResponse {
                encoded_head: origin_response_head_with_resolver_policy_and_trace(
                    response.origin,
                    resolver_policy,
                    security_path,
                    &trace,
                ),
                namespace_decision,
            })
        }
        Err(error) => {
            let (status, reason, detail) =
                map_gateway_error_for_namespace(dns_trace.selected_namespace(), &error, &dns_trace);
            let trace = resolution_trace_json(
                &input,
                network,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            gateway_error_response_to_file_for_request_with_trace(
                &input, status, reason, detail, body_path, &trace, &dns_trace,
            )
            .map(PreparedGatewayFileResponse::without_namespace_decision)
        }
    }
}

fn gateway_request(
    input: &GatewayHttpRequestInput<'_>,
    headers: Vec<(String, String)>,
) -> GatewayRequest {
    GatewayRequest {
        auth_token: None,
        origin: OriginRequest {
            method: input.method.to_owned(),
            scheme: input.scheme.to_ascii_lowercase(),
            host: input.host.to_owned(),
            connect_host: None,
            port: input.port,
            path_and_query: input.path_and_query.to_owned(),
            protocol: OriginProtocol::Http11,
            tls: if input.scheme.eq_ignore_ascii_case("https")
                || input.scheme.eq_ignore_ascii_case("wss")
            {
                TlsValidation::hns_strict(false, Vec::new())
            } else {
                TlsValidation::default()
            },
            headers,
            body: input.body.to_vec(),
        },
        resolution: ResolutionRequest {
            qname: input.host.to_owned(),
            qtype: RecordType::A.code(),
        },
    }
}

fn stateless_dane_config(base: &Path, enabled: bool) -> StatelessDaneConfig {
    if !enabled {
        return StatelessDaneConfig::default();
    }
    StatelessDaneConfig {
        enabled: true,
        accepted_tree_roots: recent_stateless_dane_tree_roots(base).unwrap_or_default(),
    }
}

fn recent_stateless_dane_tree_roots(base: &Path) -> Result<Vec<[u8; 32]>, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = HeaderChain::new(header_store);
    let Some(best) = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
    else {
        return Ok(Vec::new());
    };

    let mut roots = Vec::new();
    let mut height = best.height.0;
    let mut steps = 0usize;
    while steps < MAX_STATELESS_DANE_ROOTS {
        if let Some(header) = chain.canonical_header(Height(height)) {
            let root = header.header.tree_root.into_bytes();
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        if height == 0 {
            break;
        }
        height -= 1;
        steps += 1;
    }
    Ok(roots)
}

fn android_gateway_resolver(
    base: PathBuf,
    values: SqliteResourceValueProvider,
    context: GatewayResolverContext,
    fallback_marker: FallbackMarker,
    dns_trace: DnsTraceRecorder,
) -> AndroidGatewayResolver {
    let GatewayResolverContext {
        network,
        mode,
        configured_hns_doh,
        experimental_p2p_dns_relay,
        peer_state,
        relay,
        http,
    } = context;
    let endpoint_policy = DnsEndpointPolicy::for_network(network);
    let authoritative_dns_transport =
        android_authoritative_dns_transport(mode, dns_trace.clone(), endpoint_policy, http.clone());
    let proof_peer = Arc::new(Mutex::new(None));
    let direct =
        AuthoritativeDnssecResolver::new(authoritative_dns_transport, SystemDnssecVerifier);
    let mut delegated = BoxedDelegatedResolver::new(direct);

    if experimental_p2p_dns_relay {
        let relay_transport = HnsP2pDnsTransport::new(
            &base,
            network,
            peer_state.clone(),
            relay,
            Arc::clone(&proof_peer),
            dns_trace.clone(),
            endpoint_policy,
        );
        let relay_feedback = relay_transport.dnssec_feedback();
        let relay = RelayDnssecRetryDelegatedResolver::new(
            AuthoritativeDnssecResolver::new(relay_transport, SystemDnssecVerifier)
                .without_authoritative_doh(),
            relay_feedback,
        );
        delegated =
            BoxedDelegatedResolver::new(P2pFallbackDelegatedResolver::new(delegated, relay));
    }

    if let Some(endpoint) = configured_hns_doh {
        let configured_transport = ConfiguredRecursiveHnsDohTransport::new(
            endpoint,
            dns_trace.clone(),
            http.clone(),
            endpoint_policy,
        );
        let configured =
            AuthoritativeDnssecResolver::new(configured_transport, SystemDnssecVerifier)
                .without_authoritative_doh();
        delegated = BoxedDelegatedResolver::new(ConfiguredDohFallbackDelegatedResolver::new(
            delegated,
            configured,
            fallback_marker.clone(),
        ));
    }
    delegated = BoxedDelegatedResolver::new(TracedHnsDelegatedResolver::new(
        delegated,
        dns_trace.clone(),
    ));

    let hns_lineage = HnsProofLineage::default();
    let proof_provider = GatewayProofProvider::new(base.clone(), values, network)
        .with_peer_state(peer_state)
        .with_proof_peer(proof_peer)
        .with_lineage(hns_lineage.clone());
    let primary = DelegatingResolver::new(proof_provider, delegated);
    let icann_evidence = IcannDohEvidence::default();
    let icann = IcannDohResolver::new(dns_trace.clone(), http.clone())
        .with_evidence(icann_evidence.clone());
    #[cfg(test)]
    let icann = icann.with_test_single_label_absence();

    AndroidGatewayResolver::new(DualRootBrowserResolver {
        hns: Box::new(primary),
        icann: Box::new(icann),
        network,
        hns_lineage,
        icann_evidence,
        binding_store_path: base.join("namespace-bindings.sqlite"),
        trace: dns_trace,
    })
}

struct GatewayResolverContext {
    network: NetworkKind,
    mode: GatewayResolutionMode,
    configured_hns_doh: Option<HnsDohEndpoint>,
    experimental_p2p_dns_relay: bool,
    peer_state: Option<Arc<Mutex<()>>>,
    relay: Option<SharedDnsRelayState>,
    http: TcpHttpTransport,
}

fn android_authoritative_dns_transport(
    mode: GatewayResolutionMode,
    dns_trace: DnsTraceRecorder,
    endpoint_policy: DnsEndpointPolicy,
    http: TcpHttpTransport,
) -> AndroidAuthoritativeDnsTransport {
    let mut transport = UdpTcpDnsTransport {
        endpoint_policy,
        ..UdpTcpDnsTransport::default()
    };
    if mode == GatewayResolutionMode::Compatibility {
        transport.timeout = ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT;
    }
    AndroidAuthoritativeDnsTransport::new(transport, dns_trace, http)
}

fn parse_gateway_headers(header_text: &str) -> Result<ParsedGatewayHeaders, String> {
    if header_text.len() > MAX_GATEWAY_HEADER_TEXT_BYTES {
        return Err("request headers are too large".to_owned());
    }

    let mut headers = Vec::new();
    let mut strict_hns_mode = false;
    let mut configured_hns_doh = None;
    let mut experimental_p2p_dns_relay = false;
    let mut stateless_dane_certificates = false;
    let mut network = NetworkKind::Mainnet;
    for line in header_text.split("\r\n").filter(|line| !line.is_empty()) {
        let Some(separator) = line.find(':') else {
            return Err("request header is malformed".to_owned());
        };
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if !is_valid_gateway_header_name(name) || !is_valid_gateway_header_value(value) {
            return Err("request header is invalid".to_owned());
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_STRICT_MODE_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                strict_hns_mode = true;
            }
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_DOH_RESOLVER_HEADER) {
            if configured_hns_doh.is_some() {
                return Err("configured HNS DoH resolver header is duplicated".to_owned());
            }
            configured_hns_doh = Some(parse_configured_hns_doh_endpoint(value)?);
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_P2P_DNS_RELAY_HEADER) {
            experimental_p2p_dns_relay = value == "1" || value.eq_ignore_ascii_case("true");
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_LEGACY_DOH_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                return Err("legacy HNS DoH compatibility is prohibited".to_owned());
            }
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_STATELESS_DANE_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                stateless_dane_certificates = true;
            }
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_NETWORK_HEADER) {
            network = value
                .parse()
                .map_err(|_| "Handshake network is invalid".to_owned())?;
            continue;
        }
        if name.eq_ignore_ascii_case(HNS_SECURITY_PATH_HEADER) {
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    Ok(ParsedGatewayHeaders {
        headers,
        strict_hns_mode,
        configured_hns_doh,
        experimental_p2p_dns_relay,
        stateless_dane_certificates,
        network,
    })
}

#[cfg(test)]
fn origin_response(response: OriginResponse) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, None, None, "{}")
}

fn origin_response_with_resolver_policy_and_trace(
    response: OriginResponse,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let body = response.body;
    let mut out = origin_response_head_with_resolver_policy_and_trace(
        OriginResponseHead {
            status: response.status,
            headers: response.headers,
            body_len: body.len(),
            dane_decision: response.dane_decision,
            tls_inspection: response.tls_inspection,
        },
        resolver_policy,
        security_path,
        trace_json,
    );
    out.extend(body);
    out
}

#[cfg(test)]
fn origin_response_with_resolver_policy(
    response: OriginResponse,
    resolver_policy: Option<&str>,
) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, resolver_policy, None, "{}")
}

fn origin_response_head_with_resolver_policy_and_trace(
    response: OriginResponseHead,
    resolver_policy: Option<&str>,
    security_path: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let mut out = response_head(response.status, "OK", None, response.body_len);
    for (name, value) in response.headers {
        if suppressed_origin_response_header(&name) {
            continue;
        }
        out.extend(format!("{name}: {value}\r\n").as_bytes());
    }
    if let Some(policy) = hns_tls_policy_header(&response.dane_decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(path) = security_path {
        out.extend(format!("{HNS_SECURITY_PATH_HEADER}: {path}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

#[cfg(test)]
fn upgrade_response_head_with_resolver_policy_and_trace(
    response_head: &[u8],
    decision: &DaneDecision,
    resolver_policy: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let header_text = String::from_utf8_lossy(response_head);
    let header_text = header_text.strip_suffix("\r\n\r\n").unwrap_or(&header_text);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("HTTP/1.1 101 Switching Protocols");
    let header_lines = lines.filter(|line| !line.is_empty()).collect::<Vec<_>>();
    let connection_nominated = header_lines
        .iter()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect::<HashSet<_>>();
    let mut out = format!("{status_line}\r\n").into_bytes();
    for line in header_lines {
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || connection_nominated.contains(&name.to_ascii_lowercase())
            || suppressed_origin_response_header(name)
        {
            continue;
        }
        out.extend(line.as_bytes());
        out.extend(b"\r\n");
    }
    // The Android bridge validates the browser-visible WebSocket handshake itself. Preserve the
    // required hop-by-hop pair in canonical form while stripping every other Connection-nominated
    // field from the origin response.
    out.extend(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
    if let Some(policy) = hns_tls_policy_header(decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

fn suppressed_origin_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("trailer")
        || is_reserved_hns_header(name)
}

#[derive(Clone, Copy, Default)]
struct TlsTraceInput<'a> {
    validation: Option<&'a TlsValidation>,
    decision: Option<&'a DaneDecision>,
    inspection: Option<&'a TlsCertificateInspection>,
    origin_address: Option<&'a str>,
}

// The trace deliberately keeps its independent resolution, TLS, fallback, and DNS inputs
// explicit so security diagnostics cannot silently inherit state from a mutable context object.
#[allow(clippy::too_many_arguments)]
fn resolution_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    network: NetworkKind,
    mode: GatewayResolutionMode,
    resolution: Option<&ResolutionAnswer>,
    tls: TlsTraceInput<'_>,
    error: Option<&GatewayError>,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> String {
    let dns_events = dns_trace.snapshot();
    let selected_namespace = dns_trace.selected_namespace();
    let resource_types = resolution
        .map(|answer| {
            answer
                .records
                .iter()
                .map(|record| record_type_name(&record.record_type))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let authoritative_dns_used = dns_events
        .iter()
        .any(|event| event.protocol == "udp53" || event.protocol == "tcp53");
    let delegation = resolution
        .map(|answer| {
            authoritative_dns_used
                || answer.records.iter().any(|record| {
                    matches!(
                        record.record_type,
                        RecordType::Ns | RecordType::Ds | RecordType::Unknown(6)
                    )
                })
        })
        .unwrap_or(false);
    let origin_address = tls.origin_address.is_some()
        || resolution
            .map(|answer| {
                answer
                    .records
                    .iter()
                    .any(|record| matches!(record.record_type, RecordType::A | RecordType::Aaaa))
            })
            .unwrap_or(false);
    let hns_proof = hns_proof_trace_status(input, network, selected_namespace, resolution, error);
    let fallback_reason = fallback_marker.reason().unwrap_or("none");
    let fallback_type = if fallback_marker.used() {
        r#""USER_CONFIGURED_RECURSIVE_HNS_DOH""#
    } else {
        "null"
    };
    let fallback_reason_json = if fallback_marker.used() {
        format!(r#""{}""#, json_escape(fallback_reason))
    } else {
        "null".to_owned()
    };
    let final_error = error
        .map(|error| format!(r#""{}""#, json_escape(&error.to_string())))
        .unwrap_or_else(|| "null".to_owned());
    let authoritative_dns = authoritative_dns_trace_json(&dns_events);
    let p2p_dns_relay = p2p_dns_relay_trace_json(dns_trace.relay_snapshot());
    let port53_interception = dns_protocol_status(&dns_events, "dns_interception_probe");
    let dns_attempts = dns_trace_attempts_json(&dns_events);
    let namespace_resolution = dns_trace.namespace_resolution_json();
    let resolution_source = resolution_source_name(
        input.host,
        selected_namespace,
        resolution,
        authoritative_dns_used,
        error,
        &dns_events,
    );
    let local_currentness = local_chain_currentness_for_trace(input.data_dir, network);
    let local_best_height =
        optional_u32_json(local_currentness.and_then(|value| value.best_height));
    let target_height = optional_u32_json(local_currentness.and_then(|value| value.target_height));
    let estimated_tip_height =
        optional_u32_json(local_currentness.and_then(|value| value.estimated_tip_height));
    let local_chain_lag_blocks =
        optional_u32_json(local_currentness.and_then(|value| value.lag_blocks));
    let local_chain_freshness = local_currentness
        .map(|value| value.freshness.as_str())
        .unwrap_or(ChainFreshness::Unknown.as_str());
    let local_chain_target_source = if local_currentness
        .and_then(|value| value.target_height)
        .is_some()
    {
        CurrentnessTargetSource::CorroboratedPeers.as_str()
    } else {
        CurrentnessTargetSource::Unknown.as_str()
    };
    let local_chain_stale = optional_bool_json(local_currentness.and_then(|value| value.stale));
    let authoritative_tree_root_height =
        optional_u32_json(local_currentness.and_then(|value| value.authoritative_tree_root_height));
    let local_tree_root_height =
        optional_u32_json(local_currentness.and_then(|value| value.local_tree_root_height));
    let tree_root_ready =
        optional_bool_json(local_currentness.and_then(|value| value.tree_root_ready));
    let blocks_until_authoritative_tree_root = optional_u32_json(
        local_currentness.and_then(|value| value.blocks_until_authoritative_tree_root),
    );

    format!(
        r#"{{"host":"{}","url":"{}","nameClass":"{}","root":"{}","namespaceResolution":{},"network":"{}","mode":"{}","hnsProof":"{}","localBestHeight":{},"targetHeight":{},"estimatedTargetHeight":{},"localChainLagBlocks":{},"localChainFreshness":"{}","localChainTargetSource":"{}","localChainFreshnessThresholdBlocks":{},"localChainStale":{},"authoritativeTreeRootHeight":{},"localTreeRootHeight":{},"treeRootReady":{},"blocksUntilAuthoritativeTreeRoot":{},"delegation":{},"resolutionSource":"{}","resourceRecords":[{}],"nameserverCandidates":{},"authoritativeDns":{},"p2pDnsRelay":{},"port53Interception":"{}","dnssec":"{}","originAddress":"{}","tls":{},"fallback":{{"used":{},"type":{},"reason":{}}},"dnsAttempts":[{}],"finalError":{}}}"#,
        json_escape(input.host),
        json_escape(&gateway_request_address(input)),
        selected_namespace
            .map(namespace_trace_name)
            .unwrap_or("indeterminate"),
        match selected_namespace {
            Some(Namespace::Hns) => hns_trace_root(input.host),
            Some(Namespace::Icann) => "icann".to_owned(),
            None => "indeterminate".to_owned(),
        },
        namespace_resolution,
        network.as_str(),
        mode.as_str(),
        hns_proof,
        local_best_height,
        target_height,
        estimated_tip_height,
        local_chain_lag_blocks,
        local_chain_freshness,
        local_chain_target_source,
        LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
        local_chain_stale,
        authoritative_tree_root_height,
        local_tree_root_height,
        tree_root_ready,
        blocks_until_authoritative_tree_root,
        delegation,
        resolution_source,
        resource_types,
        nameserver_candidates_json(&dns_events),
        authoritative_dns,
        p2p_dns_relay,
        port53_interception,
        dnssec_trace_status(resolution, error),
        if origin_address { "found" } else { "missing" },
        tls_trace_json(input, tls.validation, tls.decision, tls.inspection, error),
        fallback_marker.used(),
        fallback_type,
        fallback_reason_json,
        dns_attempts,
        final_error,
    )
}

const fn namespace_trace_name(namespace: Namespace) -> &'static str {
    match namespace {
        Namespace::Hns => "hns",
        Namespace::Icann => "icann",
    }
}

fn resolution_source_name(
    host: &str,
    selected_namespace: Option<Namespace>,
    resolution: Option<&ResolutionAnswer>,
    authoritative_dns_used: bool,
    error: Option<&GatewayError>,
    dns_events: &[DnsTraceEvent],
) -> &'static str {
    if selected_namespace == Some(Namespace::Icann) {
        if dns_events.iter().any(|event| event.protocol == "icann_doh")
            || matches!(
                error,
                Some(GatewayError::Resolver(ResolverError::DnsTransport(message)))
                    if message.contains("ICANN DoH")
            )
        {
            return "trusted_icann_doh";
        }
        if resolution.is_some() {
            return "icann_dns";
        }
        return "unknown";
    }

    if selected_namespace != Some(Namespace::Hns) {
        return "unknown";
    }
    if resolution.is_some() {
        match successful_dns_path_for_namespace(
            dns_events,
            host,
            &[RecordType::A, RecordType::Aaaa],
            Namespace::Hns,
        ) {
            Some("authoritative_doh") => return "authoritative_doh",
            Some("udp53" | "tcp53") => return "authoritative_dns",
            Some("p2p_dns_relay") => return "p2p_dns_relay",
            Some("user_configured_recursive_hns_doh") => {
                return "user_configured_recursive_hns_doh";
            }
            _ => return "hns_resource",
        }
    }
    if let Some(last) = dns_events.iter().rev().find(|event| {
        matches!(
            event.protocol,
            "authoritative_doh"
                | "udp53"
                | "tcp53"
                | "p2p_dns_relay"
                | "user_configured_recursive_hns_doh"
        )
    }) {
        return match last.protocol {
            "p2p_dns_relay" => "p2p_dns_relay",
            "user_configured_recursive_hns_doh" => "user_configured_recursive_hns_doh",
            "authoritative_doh" => "authoritative_doh",
            _ => "authoritative_dns",
        };
    }
    if matches!(
        error,
        Some(GatewayError::Resolver(ResolverError::DnsTransport(_)))
            | Some(GatewayError::Resolver(
                ResolverError::Port53InterceptionDetected
            ))
            | Some(GatewayError::Resolver(ResolverError::DnsResponseCode(_)))
            | Some(GatewayError::Resolver(ResolverError::InvalidDnsResponse))
            | Some(GatewayError::Resolver(ResolverError::DnssecFailed))
    ) {
        return "authoritative_dns";
    }
    if authoritative_dns_used {
        "authoritative_dns"
    } else {
        "unknown"
    }
}

fn hns_proof_trace_status(
    input: &GatewayHttpRequestInput<'_>,
    network: NetworkKind,
    selected_namespace: Option<Namespace>,
    resolution: Option<&ResolutionAnswer>,
    error: Option<&GatewayError>,
) -> &'static str {
    if selected_namespace == Some(Namespace::Icann) {
        return "not_applicable";
    }
    if selected_namespace != Some(Namespace::Hns) {
        return "unknown";
    }

    match (resolution, error) {
        (Some(answer), _) if answer.secure => "verified",
        (_, Some(GatewayError::Resolver(ResolverError::ProofUnavailable))) => "unavailable",
        (_, Some(GatewayError::Resolver(ResolverError::NameNotFound))) => "not_found",
        (_, Some(GatewayError::Resolver(ResolverError::LocalChainNotCurrent))) => {
            match local_chain_currentness_for_trace(input.data_dir, network)
                .and_then(|currentness| currentness.tree_root_ready)
            {
                Some(false) => "stale",
                Some(true) => "verified",
                None => "currentness_unknown",
            }
        }
        (_, Some(GatewayError::Resolver(ResolverError::ProofNameMismatch))) => "failed",
        _ => {
            hns_cached_proof_trace_status(input.data_dir, network, input.host).unwrap_or("unknown")
        }
    }
}

fn hns_cached_proof_trace_status(
    data_dir: &str,
    network: NetworkKind,
    host: &str,
) -> Option<&'static str> {
    let (_, root_name) = hns_proof_host_and_root(host).ok()?;
    let name_hash = NameHash::from_name(&root_name).ok()?;
    let resources_path = network_base_path(data_dir, network).join("resources.sqlite");
    if !resources_path.exists() {
        return Some("unavailable");
    }
    let provider = SqliteResourceValueProvider::open(resources_path).ok()?;
    match provider.prove_resource_value(&root_name, name_hash) {
        Ok(verified) if !verified.secure => Some("failed"),
        Ok(verified) if verified.value.is_some() => Some("verified"),
        Ok(_) => match local_chain_currentness_for_trace(data_dir, network)
            .and_then(|currentness| currentness.tree_root_ready)
        {
            Some(true) => Some("not_found"),
            Some(false) => Some("stale"),
            None => Some("currentness_unknown"),
        },
        Err(ResolverError::ProofUnavailable) => Some("unavailable"),
        Err(ResolverError::ProofNameMismatch) => Some("failed"),
        Err(_) => None,
    }
}

fn local_chain_currentness_for_trace(
    data_dir: &str,
    network: NetworkKind,
) -> Option<LocalChainCurrentness> {
    local_chain_currentness(&network_base_path(data_dir, network), network).ok()
}

fn optional_u32_json(value: Option<u32>) -> String {
    value
        .map(|height| height.to_string())
        .unwrap_or_else(|| "null".to_owned())
}

fn optional_bool_json(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn authoritative_dns_trace_json(events: &[DnsTraceEvent]) -> String {
    format!(
        r#"{{"udp53":"{}","tcp53":"{}","doh":"{}","p2pDnsRelay":"{}"}}"#,
        dns_protocol_status(events, "udp53"),
        dns_protocol_status(events, "tcp53"),
        dns_protocol_status(events, "authoritative_doh"),
        dns_protocol_status(events, "p2p_dns_relay"),
    )
}

fn p2p_dns_relay_trace_json(metadata: Option<DnsRelayTraceMetadata>) -> String {
    let Some(metadata) = metadata else {
        return r#"{"attempted":false,"peer":null,"serviceAdvertised":null,"retryCount":0,"error":null}"#
            .to_owned();
    };
    let peer = metadata
        .peer
        .map(|peer| format!(r#""{}""#, json_escape(&peer.to_string())))
        .unwrap_or_else(|| "null".to_owned());
    let advertised = match metadata.service_advertised {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    };
    let error = metadata
        .error
        .map(|error| format!(r#""{}""#, json_escape(&error)))
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"attempted":true,"peer":{},"serviceAdvertised":{},"retryCount":{},"error":{}}}"#,
        peer, advertised, metadata.retries, error,
    )
}

fn tls_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    tls_validation: Option<&TlsValidation>,
    dane_decision: Option<&DaneDecision>,
    tls_inspection: Option<&TlsCertificateInspection>,
    error: Option<&GatewayError>,
) -> String {
    if !input.scheme.eq_ignore_ascii_case("https")
        && tls_validation
            .map(|tls| tls.tlsa_records.is_empty())
            .unwrap_or(true)
        && dane_decision.is_none()
    {
        return "null".to_owned();
    }

    let owner = tlsa_owner_name(
        input.host,
        tls_validation
            .map(|tls| tls.service_port)
            .unwrap_or(input.port),
        tls_validation
            .map(|tls| tls.service_transport)
            .unwrap_or(TlsaTransport::Tcp),
    );
    let stateless_dane = matches!(dane_decision, Some(DaneDecision::StatelessMatched(_)));
    let tlsa_evaluated = tls_validation.is_some();
    let tlsa_status = if stateless_dane {
        "present"
    } else {
        tlsa_status_name(tls_validation)
    };
    let tlsa_blocked_by = tlsa_blocked_by_json(tls_validation, error);
    let records = tls_validation
        .map(|tls| tlsa_records_json(&tls.tlsa_records))
        .unwrap_or_else(|| "[]".to_owned());
    let records_found = stateless_dane
        || tls_validation
            .map(|tls| !tls.tlsa_records.is_empty())
            .unwrap_or(false);
    let dnssec_secure = if stateless_dane {
        "true"
    } else {
        tls_validation
            .map(|tls| if tls.dnssec_secure { "true" } else { "false" })
            .unwrap_or("null")
    };
    let tlsa_source = if stateless_dane {
        r#""stateless_certificate""#.to_owned()
    } else {
        tls_validation
            .and_then(|tls| tls.tlsa_source)
            .map(|source| format!(r#""{}""#, tlsa_record_source_name(source)))
            .unwrap_or_else(|| "null".to_owned())
    };
    let mode = tls_validation
        .map(|tls| format!(r#""{}""#, json_escape(tls_mode_name(tls))))
        .unwrap_or_else(|| "null".to_owned());
    let decision = dane_trace_decision(dane_decision, error);
    let matched_usage = dane_decision
        .and_then(|decision| match decision {
            DaneDecision::Matched(usage) | DaneDecision::StatelessMatched(usage) => {
                Some(format!(r#""{}""#, tlsa_usage_name(*usage)))
            }
            _ => None,
        })
        .unwrap_or_else(|| "null".to_owned());
    let certificate_match = dane_certificate_match(dane_decision, error);
    let fallback = matches!(dane_decision, Some(DaneDecision::WebPkiFallback));

    format!(
        r#"{{"mode":{},"tlsaOwner":"{}","tlsaEvaluated":{},"tlsaStatus":"{}","tlsaBlockedBy":{},"tlsaFound":{},"dnssecSecure":{},"tlsaSource":{},"records":{},"certificate":{},"dane":{{"decision":"{}","matchedUsage":{},"certificateMatch":"{}","webPkiFallback":{}}}}}"#,
        mode,
        json_escape(&owner),
        tlsa_evaluated,
        tlsa_status,
        tlsa_blocked_by,
        records_found,
        dnssec_secure,
        tlsa_source,
        records,
        tls_certificate_inspection_json(tls_inspection),
        decision,
        matched_usage,
        certificate_match,
        fallback,
    )
}

fn tlsa_record_source_name(source: TlsaRecordSource) -> &'static str {
    match source {
        TlsaRecordSource::NativeTlsa => "native_tlsa",
        TlsaRecordSource::HnsProofTxt => "hns_proof_txt",
    }
}

fn tls_certificate_inspection_json(inspection: Option<&TlsCertificateInspection>) -> String {
    let Some(inspection) = inspection else {
        return "null".to_owned();
    };
    format!(
        r#"{{"webPkiStatus":"{}","endEntitySha256":"{}","spkiSha256":"{}","spkiDerHex":"{}","intermediateCount":{},"intermediateSha256":[{}]}}"#,
        webpki_status_name(inspection.webpki_status),
        sha256_hex(&inspection.end_entity_der),
        sha256_hex(&inspection.end_entity_spki_der),
        hex_lower(&inspection.end_entity_spki_der),
        inspection.intermediate_der.len(),
        inspection
            .intermediate_der
            .iter()
            .map(|certificate| format!(r#""{}""#, sha256_hex(certificate)))
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn webpki_status_name(status: hns_dane::WebPkiStatus) -> &'static str {
    match status {
        hns_dane::WebPkiStatus::Valid => "valid",
        hns_dane::WebPkiStatus::Invalid => "invalid",
        hns_dane::WebPkiStatus::NotEvaluated => "not_evaluated",
    }
}

fn sha256_hex(value: &[u8]) -> String {
    hex_lower(&Sha256::digest(value))
}

fn tlsa_owner_name(host: &str, port: u16, transport: TlsaTransport) -> String {
    TlsaOwner::derive(host, port, transport)
        .map(|owner| owner.resolver_name().to_owned())
        .unwrap_or_default()
}

fn tlsa_status_name(tls_validation: Option<&TlsValidation>) -> &'static str {
    match tls_validation {
        Some(tls) if tls.tlsa_records.is_empty() => "absent",
        Some(_) => "present",
        None => "not_evaluated",
    }
}

fn tlsa_blocked_by_json(
    tls_validation: Option<&TlsValidation>,
    error: Option<&GatewayError>,
) -> String {
    if tls_validation.is_some() {
        return "null".to_owned();
    }
    tlsa_blocked_by(error)
        .map(|reason| format!(r#""{}""#, json_escape(reason)))
        .unwrap_or_else(|| "null".to_owned())
}

fn tlsa_blocked_by(error: Option<&GatewayError>) -> Option<&'static str> {
    match error {
        Some(GatewayError::Resolver(ResolverError::ProofUnavailable)) => {
            Some("local_hns_proof_unavailable")
        }
        Some(GatewayError::Resolver(ResolverError::LocalChainNotCurrent)) => {
            Some("local_chain_not_current")
        }
        Some(GatewayError::Resolver(ResolverError::NoNameserverAddress)) => {
            Some("no_verified_nameserver_address")
        }
        Some(GatewayError::Resolver(ResolverError::NonPublicDnsEndpoint)) => {
            Some("authoritative_nameserver_address_blocked")
        }
        Some(GatewayError::Resolver(ResolverError::UnsafeAuthoritativeDohPort(_))) => {
            Some("authoritative_nameserver_port_blocked")
        }
        Some(GatewayError::Resolver(ResolverError::DnsTransport(_))) => {
            Some("authoritative_nameserver_transport_failed")
        }
        Some(GatewayError::Resolver(ResolverError::Port53InterceptionDetected)) => {
            Some("port53_interception_detected")
        }
        Some(GatewayError::Resolver(ResolverError::DnsResponseCode(_))) => {
            Some("authoritative_nameserver_response_code")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidDnsResponse)) => {
            Some("authoritative_nameserver_invalid_response")
        }
        Some(GatewayError::Resolver(ResolverError::DnssecFailed)) => {
            Some("delegated_dnssec_validation_failed")
        }
        Some(GatewayError::Resolver(ResolverError::RelayDnssecFailed)) => {
            Some("p2p_dns_relay_dnssec_validation_failed")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidResource(_))) => {
            Some("hns_resource_invalid")
        }
        Some(GatewayError::Resolver(ResolverError::InvalidAuthoritativeDoh)) => {
            Some("hns_authoritative_doh_invalid")
        }
        Some(GatewayError::Resolver(ResolverError::ProofNameMismatch)) => {
            Some("hns_proof_validation_failed")
        }
        Some(GatewayError::Resolver(ResolverError::UnsupportedBackend)) => {
            Some("resolver_backend_unsupported")
        }
        Some(GatewayError::Resolver(ResolverError::NamespaceValidation(_))) => {
            Some("dual_root_origin_invalid")
        }
        Some(GatewayError::Resolver(ResolverError::NamespaceClassification(_))) => {
            Some("dual_root_classification_failed")
        }
        Some(GatewayError::Resolver(ResolverError::NamespaceUnavailable)) => {
            Some("dual_root_origin_absent")
        }
        Some(GatewayError::Resolver(ResolverError::CachePoisoned))
        | Some(GatewayError::Resolver(ResolverError::Storage(_))) => {
            Some("resolver_storage_failed")
        }
        Some(GatewayError::NonLoopbackBind | GatewayError::EmptyAuthToken) => {
            Some("gateway_configuration_invalid")
        }
        Some(GatewayError::Unauthorized) => Some("gateway_authentication_failed"),
        Some(GatewayError::InsecureResolution) => Some("insecure_resolution"),
        Some(GatewayError::NoResolvedAddress) => Some("origin_address_missing"),
        Some(GatewayError::NonPublicOriginAddress) => Some("origin_address_blocked"),
        Some(GatewayError::UnsafeOriginPort(_)) => Some("origin_port_blocked"),
        Some(GatewayError::InvalidSvcb(_)) | Some(GatewayError::UnsupportedSvcb) => {
            Some("https_service_unsupported")
        }
        Some(GatewayError::IcannDane(_)) => Some("icann_dane_discovery_failed"),
        Some(GatewayError::HostResolutionMismatch) => Some("hns_request_mismatch"),
        Some(GatewayError::Transport(TransportError::UnsupportedTransport)) => {
            Some("transport_unsupported")
        }
        Some(GatewayError::Transport(TransportError::UnsupportedScheme)) => {
            Some("scheme_unsupported")
        }
        Some(GatewayError::Transport(error))
            if transport_certificate_failure_reason(error).is_some() =>
        {
            transport_certificate_failure_reason(error)
        }
        Some(GatewayError::Transport(TransportError::Tls(_))) => Some("tls_failed"),
        Some(GatewayError::Transport(TransportError::Io(_))) => Some("origin_transport_failed"),
        Some(GatewayError::Transport(TransportError::Http3(_))) => Some("http3_failed"),
        Some(GatewayError::Transport(TransportError::Quic(_))) => Some("quic_failed"),
        Some(GatewayError::Transport(TransportError::DaneFailed))
        | Some(GatewayError::InvalidTlsa(_)) => Some("dane_validation_failed"),
        Some(GatewayError::Transport(_)) => Some("origin_transport_failed"),
        Some(GatewayError::Resolver(ResolverError::NameNotFound))
        | Some(GatewayError::Resolver(ResolverError::InvalidName(_)))
        | None => None,
    }
}

fn transport_certificate_failure_reason(error: &TransportError) -> Option<&'static str> {
    let message = transport_error_message(error)?;
    if transport_certificate_message_is_expired(message) {
        return Some("origin_certificate_expired");
    }
    if message
        .to_ascii_lowercase()
        .contains("invalid peer certificate")
    {
        return Some("origin_certificate_invalid");
    }
    None
}

fn transport_certificate_expired(error: &TransportError) -> bool {
    transport_certificate_failure_reason(error) == Some("origin_certificate_expired")
}

fn transport_error_message(error: &TransportError) -> Option<&str> {
    match error {
        TransportError::Io(message)
        | TransportError::Tls(message)
        | TransportError::Http2(message)
        | TransportError::Http3(message)
        | TransportError::Quic(message) => Some(message),
        _ => None,
    }
}

fn transport_certificate_message_is_expired(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("certificate expired")
        || message.contains("certificate has expired")
        || message.contains("cert has expired")
        || message.contains("not valid after")
}

fn tls_mode_name(tls: &TlsValidation) -> &'static str {
    match tls.mode {
        hns_dane::DomainTrustMode::HnsStrict => "hns_strict",
        hns_dane::DomainTrustMode::IcannWebPki => "icann_webpki",
    }
}

fn dane_trace_decision(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_)), _) => "verified",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_fallback",
        (Some(DaneDecision::NoTlsa), _) => "no_tlsa",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "not_evaluated",
    }
}

fn dane_certificate_match(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_)), _) => "pass",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_valid",
        (Some(DaneDecision::NoTlsa), _) => "not_checked",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "unknown",
    }
}

fn tlsa_records_json(records: &[TlsaRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(tlsa_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn tlsa_record_json(record: &TlsaRecord) -> String {
    format!(
        r#"{{"usage":"{}","selector":"{}","matching":"{}","associationDataHex":"{}"}}"#,
        tlsa_usage_name(record.usage),
        tlsa_selector_name(record.selector),
        tlsa_matching_name(record.matching),
        hex_lower(&record.association_data),
    )
}

fn tlsa_usage_name(usage: TlsaUsage) -> &'static str {
    match usage {
        TlsaUsage::PkixTa => "PKIX-TA",
        TlsaUsage::PkixEe => "PKIX-EE",
        TlsaUsage::DaneTa => "DANE-TA",
        TlsaUsage::DaneEe => "DANE-EE",
    }
}

fn tlsa_selector_name(selector: TlsaSelector) -> &'static str {
    match selector {
        TlsaSelector::FullCertificate => "Cert",
        TlsaSelector::SubjectPublicKeyInfo => "SPKI",
    }
}

fn tlsa_matching_name(matching: TlsaMatching) -> &'static str {
    match matching {
        TlsaMatching::Exact => "Exact",
        TlsaMatching::Sha256 => "SHA-256",
        TlsaMatching::Sha512 => "SHA-512",
    }
}

fn dns_protocol_status(events: &[DnsTraceEvent], protocol: &str) -> String {
    let statuses = events
        .iter()
        .filter(|event| event.protocol == protocol)
        .map(|event| event.status.as_str())
        .collect::<Vec<_>>();
    if statuses.is_empty() {
        return "not_attempted".to_owned();
    }
    if statuses.contains(&"ok") {
        return "ok".to_owned();
    }
    if statuses.contains(&"timeout") {
        return "timeout".to_owned();
    }
    statuses.last().copied().unwrap_or("error").to_owned()
}

fn dns_trace_attempts_json(events: &[DnsTraceEvent]) -> String {
    events
        .iter()
        .map(|event| {
            let error = event
                .error
                .as_ref()
                .map(|error| format!(r#""{}""#, json_escape(error)))
                .unwrap_or_else(|| "null".to_owned());
            let question_name = event
                .question_name
                .as_ref()
                .map(|name| format!(r#""{}""#, json_escape(name)))
                .unwrap_or_else(|| "null".to_owned());
            let question_type = event
                .question_type
                .map(|record_type| record_type.to_string())
                .unwrap_or_else(|| "null".to_owned());
            format!(
                r#"{{"protocol":"{}","server":"{}","root":"{}","questionName":{},"questionType":{},"status":"{}","elapsedMs":{},"error":{}}}"#,
                event.protocol,
                json_escape(&event.server),
                dns_trace_root(event.protocol),
                question_name,
                question_type,
                json_escape(&event.status),
                event.elapsed_ms,
                error,
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn dns_trace_root(protocol: &str) -> &'static str {
    match protocol {
        "icann_doh" => "icann",
        "udp53"
        | "tcp53"
        | "authoritative_doh"
        | "p2p_dns_relay"
        | "user_configured_recursive_hns_doh" => "hns",
        _ => "diagnostic",
    }
}

fn successful_dns_path<'a>(
    events: &'a [DnsTraceEvent],
    qname: &str,
    qtype: RecordType,
    namespace: Namespace,
) -> Option<&'a str> {
    successful_dns_path_for_namespace(events, qname, &[qtype], namespace)
}

fn successful_dns_path_for_namespace<'a>(
    events: &'a [DnsTraceEvent],
    qname: &str,
    qtypes: &[RecordType],
    namespace: Namespace,
) -> Option<&'a str> {
    let qname = qname.trim_end_matches('.');
    events
        .iter()
        .rev()
        .find(|event| {
            event.status == "ok"
                && dns_protocol_namespace(event.protocol) == Some(namespace)
                && event
                    .question_type
                    .is_some_and(|code| qtypes.iter().any(|qtype| qtype.code() == code))
                && event
                    .question_name
                    .as_deref()
                    .is_some_and(|name| name.trim_end_matches('.').eq_ignore_ascii_case(qname))
        })
        .map(|event| event.protocol)
}

fn dns_protocol_namespace(protocol: &str) -> Option<Namespace> {
    match protocol {
        "icann_doh" => Some(Namespace::Icann),
        "udp53"
        | "tcp53"
        | "authoritative_doh"
        | "p2p_dns_relay"
        | "user_configured_recursive_hns_doh" => Some(Namespace::Hns),
        _ => None,
    }
}

fn security_path_name(
    input: &GatewayHttpRequestInput<'_>,
    effective_port: u16,
    service_transport: TlsaTransport,
    decision: &DaneDecision,
    selected_namespace: Option<Namespace>,
    events: &[DnsTraceEvent],
) -> Option<&'static str> {
    match decision {
        DaneDecision::StatelessMatched(_) => return Some("stateless-dane"),
        DaneDecision::Matched(_) => {
            let namespace = selected_namespace?;
            let owner = tlsa_owner_name(input.host, effective_port, service_transport);
            return match successful_dns_path(events, &owner, RecordType::Tlsa, namespace) {
                Some("authoritative_doh") => Some("dane-authoritative-doh"),
                Some("udp53" | "tcp53") => Some("dane-authoritative-dns53"),
                Some("p2p_dns_relay") => Some("dane-p2p-dns-relay"),
                Some("user_configured_recursive_hns_doh") => {
                    Some("dane-user-configured-recursive-hns-doh")
                }
                Some("icann_doh") => Some("dane-icann-doh"),
                None if namespace == Namespace::Hns && !has_hns_dns_transport_event(events) => {
                    Some("dane-local-hns-proof")
                }
                _ => None,
            };
        }
        DaneDecision::WebPkiFallback | DaneDecision::Failed => return None,
        DaneDecision::NoTlsa => {}
    }

    if !input.scheme.eq_ignore_ascii_case("http") && !input.scheme.eq_ignore_ascii_case("ws") {
        return None;
    }
    if selected_namespace != Some(Namespace::Hns) {
        return None;
    }
    match successful_dns_path_for_namespace(
        events,
        input.host,
        &[RecordType::A, RecordType::Aaaa],
        Namespace::Hns,
    ) {
        Some("authoritative_doh") => Some("hns-authoritative-doh"),
        Some("udp53" | "tcp53") => Some("hns-authoritative-dns53"),
        Some("p2p_dns_relay") => Some("hns-p2p-dns-relay"),
        Some("user_configured_recursive_hns_doh") => Some("hns-user-configured-recursive-hns-doh"),
        None if !has_hns_dns_transport_event(events) => Some("hns-local-hns-proof"),
        _ => None,
    }
}

fn nameserver_candidates_json(events: &[DnsTraceEvent]) -> String {
    let servers = events
        .iter()
        .filter(|event| matches!(event.protocol, "udp53" | "tcp53" | "authoritative_doh"))
        .map(|event| event.server.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    format!(
        "[{}]",
        servers
            .into_iter()
            .map(|server| format!(r#""{}""#, json_escape(server)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn dnssec_trace_status(
    resolution: Option<&ResolutionAnswer>,
    error: Option<&GatewayError>,
) -> &'static str {
    if matches!(
        error,
        Some(GatewayError::Resolver(
            ResolverError::DnssecFailed | ResolverError::RelayDnssecFailed
        ))
    ) {
        "bogus"
    } else if resolution.map(|answer| answer.secure).unwrap_or(false) {
        "secure"
    } else if resolution.is_some() {
        "unsigned"
    } else {
        "unknown"
    }
}

fn hns_trace_root(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .unwrap_or(host)
        .to_owned()
}

#[cfg(test)]
fn hns_proof_details(data_dir: &str, host_or_url: &str) -> String {
    hns_proof_details_for_network(data_dir, host_or_url, NetworkKind::Mainnet)
}

pub fn hns_proof_details_for_network(
    data_dir: &str,
    host_or_url: &str,
    network: NetworkKind,
) -> String {
    let (host, root_name) = match hns_proof_host_and_root(host_or_url) {
        Ok(value) => value,
        Err(error) => return hns_proof_details_error_json(host_or_url, &error),
    };
    let name_hash = match NameHash::from_name(&root_name) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: None,
                proof_status: "failed",
                cache_status: "invalid_name",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: None,
                network,
                error: &format!("invalid HNS name: {error}"),
            });
        }
    };

    let base = network_base_path(data_dir, network);
    let resources_path = base.join("resources.sqlite");
    if !resources_path.exists() {
        return hns_proof_details_base_json(HnsProofDetailsJson {
            host: &host,
            root_name: &root_name,
            name_hash: Some(name_hash),
            proof_status: "unavailable",
            cache_status: "resource_cache_missing",
            anchor: None,
            secure: None,
            exists: None,
            records: Vec::new(),
            raw_resource: None,
            current_tip_base: Some(&base),
            network,
            error: "resource cache is not initialized",
        });
    }

    let provider = match SqliteResourceValueProvider::open(resources_path) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "resource_cache_open_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: &format!("open resource cache: {error}"),
            });
        }
    };

    let verified = match provider.prove_resource_value(&root_name, name_hash) {
        Ok(value) => value,
        Err(ResolverError::ProofUnavailable) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "unavailable",
                cache_status: "not_cached",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: "no cached proof is available for this HNS root",
            });
        }
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "proof_read_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                network,
                error: &error.to_string(),
            });
        }
    };

    let raw_resource = verified.value.as_deref();
    let records = match ProvenNameRecords::from_verified_resource_value(verified.clone()) {
        Ok(proven) => proven.records,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "invalid_resource",
                cache_status: &proof_cache_status(&base, network, verified.anchor),
                anchor: verified.anchor,
                secure: Some(verified.secure),
                exists: Some(verified.value.is_some()),
                records: Vec::new(),
                raw_resource,
                current_tip_base: Some(&base),
                network,
                error: &format!("decode resource records: {error}"),
            });
        }
    };
    let status = match (verified.secure, verified.value.is_some()) {
        (false, _) => "failed",
        (true, false) => "not_found",
        (true, true) => "verified",
    };

    hns_proof_details_base_json(HnsProofDetailsJson {
        host: &host,
        root_name: &root_name,
        name_hash: Some(name_hash),
        proof_status: status,
        cache_status: &proof_cache_status(&base, network, verified.anchor),
        anchor: verified.anchor,
        secure: Some(verified.secure),
        exists: Some(verified.value.is_some()),
        records,
        raw_resource,
        current_tip_base: Some(&base),
        network,
        error: "",
    })
}

fn hns_proof_host_and_root(host_or_url: &str) -> Result<(String, String), String> {
    let mut value = host_or_url.trim();
    if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("http://") {
        value = rest;
    }
    let authority = value
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or(value)
        .trim();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => authority,
    }
    .trim_end_matches('.')
    .to_ascii_lowercase();
    if host.is_empty() {
        return Err("missing HNS host".to_owned());
    }
    let root = hns_trace_root(&host).to_ascii_lowercase();
    if root.is_empty() {
        return Err("missing HNS root".to_owned());
    }
    Ok((host, root))
}

pub fn hns_proof_details_error_json(host_or_url: &str, error: &str) -> String {
    format!(
        r#"{{"host":"{}","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"{}"}}"#,
        json_escape(host_or_url),
        json_escape(error),
    )
}

struct HnsProofDetailsJson<'a> {
    host: &'a str,
    root_name: &'a str,
    name_hash: Option<NameHash>,
    proof_status: &'a str,
    cache_status: &'a str,
    anchor: Option<ResourceValueAnchor>,
    secure: Option<bool>,
    exists: Option<bool>,
    records: Vec<ResourceRecord>,
    raw_resource: Option<&'a [u8]>,
    current_tip_base: Option<&'a Path>,
    network: NetworkKind,
    error: &'a str,
}

fn hns_proof_details_base_json(details: HnsProofDetailsJson<'_>) -> String {
    let name_hash = details
        .name_hash
        .map(|value| format!(r#""{}""#, value.as_hash()))
        .unwrap_or_else(|| "null".to_owned());
    let tree_root = details
        .anchor
        .map(|value| format!(r#""{}""#, value.tree_root))
        .unwrap_or_else(|| "null".to_owned());
    let block_height = details
        .anchor
        .map(|value| value.height.0.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let secure = json_bool_or_null(details.secure);
    let exists = json_bool_or_null(details.exists);
    let raw_resource = details
        .raw_resource
        .map(|value| format!(r#""{}""#, hex_lower(value)))
        .unwrap_or_else(|| "null".to_owned());
    let record_types = record_types_json(&details.records);
    let records_json = resource_records_json(&details.records);
    let current_tip = details
        .current_tip_base
        .map(|base| current_tip_json(base, details.network))
        .unwrap_or_else(|| "null".to_owned());
    let error = if details.error.is_empty() {
        "null".to_owned()
    } else {
        format!(r#""{}""#, json_escape(details.error))
    };

    format!(
        r#"{{"host":"{}","name":"{}","network":"{}","nameHash":{},"hnsProof":"{}","proofStatus":"{}","secure":{},"exists":{},"treeRoot":{},"blockHeight":{},"cacheStatus":"{}","resourceValueHex":{},"recordTypes":{},"resourceRecords":{},"currentTip":{},"error":{}}}"#,
        json_escape(details.host),
        json_escape(details.root_name),
        details.network.as_str(),
        name_hash,
        json_escape(details.proof_status),
        json_escape(details.proof_status),
        secure,
        exists,
        tree_root,
        block_height,
        json_escape(details.cache_status),
        raw_resource,
        record_types,
        records_json,
        current_tip,
        error,
    )
}

fn proof_cache_status(
    base: &Path,
    network: NetworkKind,
    anchor: Option<ResourceValueAnchor>,
) -> String {
    match anchor {
        None => "no_anchor".to_owned(),
        Some(anchor)
            if hns_anchor_matches_authoritative_tree_root(base, network, anchor)
                .unwrap_or(false) =>
        {
            "anchored_to_authoritative_tree_root".to_owned()
        }
        Some(_) if best_synced_header(base, network).is_ok() => "anchored_to_height".to_owned(),
        Some(_) => "anchored_no_current_tip".to_owned(),
    }
}

fn current_tip_json(base: &Path, network: NetworkKind) -> String {
    match best_synced_header(base, network) {
        Ok(best) => format!(
            r#"{{"height":{},"treeRoot":"{}"}}"#,
            best.height.0, best.header.tree_root,
        ),
        Err(_) => "null".to_owned(),
    }
}

fn json_bool_or_null(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn record_types_json(records: &[ResourceRecord]) -> String {
    let values = records
        .iter()
        .map(|record| record_type_name(&record.record_type))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn resource_records_json(records: &[ResourceRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(resource_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn resource_record_json(record: &ResourceRecord) -> String {
    format!(
        r#"{{"name":"{}","type":"{}","class":{},"ttl":{},"rdataHex":"{}"}}"#,
        json_escape(&record.name.to_string()),
        json_escape(record_type_name(&record.record_type)),
        record.class,
        record.ttl,
        hex_lower(&record.rdata),
    )
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn record_type_name(record_type: &RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::Aaaa => "AAAA",
        RecordType::Ns => "NS",
        RecordType::Ds => "DS",
        RecordType::Txt => "TXT",
        RecordType::Soa => "SOA",
        RecordType::Srv => "SRV",
        RecordType::Rrsig => "RRSIG",
        RecordType::Nsec => "NSEC",
        RecordType::Dnskey => "DNSKEY",
        RecordType::Nsec3 => "NSEC3",
        RecordType::Tlsa => "TLSA",
        RecordType::Svcb => "SVCB",
        RecordType::Https => "HTTPS",
        RecordType::Cname => "CNAME",
        RecordType::Unknown(1) => "GLUE4",
        RecordType::Unknown(2) => "GLUE6",
        RecordType::Unknown(6) => "SYNTH4",
        RecordType::Unknown(7) => "SYNTH6",
        RecordType::Unknown(_) => "UNKNOWN",
    }
}

fn trace_mode(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""mode":"strict""#) {
        "strict"
    } else {
        "compatibility"
    }
}

fn trace_doh_fallback(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""used":true"#) {
        "yes"
    } else {
        "no"
    }
}

fn hns_tls_policy_header(decision: &DaneDecision) -> Option<&'static str> {
    match decision {
        DaneDecision::Matched(_) | DaneDecision::StatelessMatched(_) => Some("dane"),
        DaneDecision::WebPkiFallback => Some("webpki-fallback"),
        DaneDecision::Failed => Some("failed"),
        DaneDecision::NoTlsa => None,
    }
}

fn map_gateway_error_for_namespace(
    selected_namespace: Option<Namespace>,
    error: &GatewayError,
    dns_trace: &DnsTraceRecorder,
) -> (u16, &'static str, &'static str) {
    if classification_has_hns_transport_failure(error)
        && dns_trace_has_detected_port53_interception(dns_trace)
    {
        return interception_recovery_error(dns_trace);
    }
    if selected_namespace == Some(Namespace::Icann) {
        match error {
            GatewayError::Resolver(ResolverError::DnsTransport(_)) => (
                502,
                "ICANN DNS Unavailable",
                "Trusted ICANN DNS resolver transport failed closed.",
            ),
            GatewayError::Resolver(ResolverError::DnsResponseCode(_)) => (
                502,
                "ICANN DNS Response Code",
                "Trusted ICANN DNS resolver returned a DNS failure response code.",
            ),
            GatewayError::Resolver(ResolverError::InvalidDnsResponse) => (
                502,
                "ICANN DNS Response Invalid",
                "Trusted ICANN DNS resolver returned an invalid response.",
            ),
            GatewayError::Resolver(
                ResolverError::DnssecFailed | ResolverError::RelayDnssecFailed,
            )
            | GatewayError::InsecureResolution => (
                502,
                "ICANN DNSSEC Validation Failed",
                "Secure ICANN DNS resolution was required but validation failed closed.",
            ),
            GatewayError::NoResolvedAddress => (
                502,
                "ICANN Origin Address Missing",
                "Secure ICANN DNS resolution did not produce an origin A or AAAA address.",
            ),
            GatewayError::NonPublicOriginAddress => (
                403,
                "ICANN Origin Address Blocked",
                "Native gateway policy blocked a non-public origin address.",
            ),
            GatewayError::UnsafeOriginPort(_) => (
                403,
                "ICANN Origin Port Blocked",
                "Native gateway policy blocked a browser-unsafe origin port.",
            ),
            GatewayError::InvalidTlsa(_) | GatewayError::Transport(TransportError::DaneFailed) => (
                502,
                "ICANN DANE Validation Failed",
                "ICANN DANE/TLSA validation failed closed.",
            ),
            GatewayError::InvalidSvcb(_) | GatewayError::UnsupportedSvcb => (
                502,
                "ICANN HTTPS Service Unsupported",
                "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
            ),
            GatewayError::HostResolutionMismatch => (
                400,
                "ICANN Request Mismatch",
                "Origin host does not match the resolved ICANN name.",
            ),
            GatewayError::Transport(TransportError::UnsupportedTransport) => (
                501,
                "ICANN Transport Unsupported",
                "Requested ICANN origin transport is not available.",
            ),
            GatewayError::Transport(TransportError::UnsupportedScheme) => (
                501,
                "ICANN Scheme Unsupported",
                "Requested ICANN origin scheme is not available.",
            ),
            GatewayError::Transport(error) if transport_certificate_expired(error) => (
                502,
                "ICANN Origin Certificate Expired",
                "Origin HTTPS certificate is expired; renew the certificate and retry.",
            ),
            GatewayError::Transport(TransportError::Tls(_)) => (
                502,
                "ICANN TLS Failed",
                "Origin TLS negotiation failed closed.",
            ),
            GatewayError::Transport(TransportError::InvalidRequest) => (
                400,
                "ICANN Origin Request Invalid",
                "Origin request could not be safely forwarded.",
            ),
            GatewayError::Transport(TransportError::RequestTooLarge) => (
                413,
                "ICANN Origin Request Too Large",
                "Origin request body exceeds the configured gateway limit.",
            ),
            GatewayError::Transport(TransportError::UnsupportedTransferEncoding)
            | GatewayError::Transport(TransportError::MalformedResponse) => (
                502,
                "ICANN Origin Response Invalid",
                "Origin HTTP response framing failed closed.",
            ),
            GatewayError::Transport(TransportError::UnsupportedUpgrade) => (
                501,
                "ICANN Protocol Upgrade Unsupported",
                "ICANN WebSocket/HTTP Upgrade must use the native tunnel path and the request failed validation.",
            ),
            GatewayError::Transport(TransportError::ResponseTooLarge) => (
                502,
                "ICANN Origin Response Too Large",
                "Origin response exceeds the configured gateway limit.",
            ),
            GatewayError::Transport(TransportError::Io(_)) => (
                502,
                "ICANN Origin Transport Failed",
                "Origin connection failed closed.",
            ),
            GatewayError::Transport(TransportError::Http2(_)) => (
                502,
                "ICANN HTTP/2 Transport Failed",
                "Origin HTTP/2 exchange failed closed.",
            ),
            GatewayError::Transport(TransportError::Http3(_)) => (
                502,
                "ICANN HTTP/3 Transport Failed",
                "Origin HTTP/3 exchange failed closed.",
            ),
            GatewayError::Transport(TransportError::Quic(_)) => (
                502,
                "ICANN QUIC Transport Failed",
                "Origin QUIC connection failed closed.",
            ),
            _ => map_gateway_error(error),
        }
    } else {
        map_gateway_error(error)
    }
}

fn interception_recovery_error(dns_trace: &DnsTraceRecorder) -> (u16, &'static str, &'static str) {
    let p2p_attempted = dns_trace.relay_snapshot().is_some();
    let configured_doh_attempted = dns_trace
        .snapshot()
        .iter()
        .any(|event| event.protocol == "user_configured_recursive_hns_doh");
    let detail = match (p2p_attempted, configured_doh_attempted) {
        (false, false) => {
            "This network intercepted direct authoritative DNS and no authenticated alternate completed.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443 (an HNS hnsdns=1 declaration with proven glue plus a TLSA pin, or supported authenticated _dns.<NS> SVCB).\n\nUsers can enable the requester-only P2P DNS relay or configure an explicit recursive HNS DoH URL in extension settings; both retain local DNSSEC and DANE verification."
        }
        (true, false) => {
            "This network intercepted direct authoritative DNS. The opted-in P2P DNS relay requester was attempted and exhausted.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443 (an HNS hnsdns=1 declaration with proven glue plus a TLSA pin, or supported authenticated _dns.<NS> SVCB).\n\nUsers can configure an explicit recursive HNS DoH URL in extension settings; local DNSSEC and DANE verification remains mandatory."
        }
        (false, true) => {
            "This network intercepted direct authoritative DNS. The configured recursive HNS DoH recovery endpoint was attempted and exhausted.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443 (an HNS hnsdns=1 declaration with proven glue plus a TLSA pin, or supported authenticated _dns.<NS> SVCB).\n\nUsers can enable the requester-only P2P DNS relay or update the resolver URL in extension settings; local DNSSEC and DANE verification remains mandatory."
        }
        (true, true) => {
            "This network intercepted direct authoritative DNS. Both the opted-in P2P DNS relay requester and configured recursive HNS DoH recovery endpoint were attempted and exhausted.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443 (an HNS hnsdns=1 declaration with proven glue plus a TLSA pin, or supported authenticated _dns.<NS> SVCB)."
        }
    };
    (502, HNS_PORT53_INTERCEPTION_REASON, detail)
}

fn classification_has_hns_transport_failure(error: &GatewayError) -> bool {
    let GatewayError::Resolver(ResolverError::NamespaceClassification(
        ClassificationError::RootFailed { hns, .. },
    )) = error
    else {
        return false;
    };
    matches!(
        hns,
        RootResolutionState::Failed(failure)
            if failure.kind() == RootFailureKind::Transport
    )
}

fn dns_trace_has_detected_port53_interception(dns_trace: &DnsTraceRecorder) -> bool {
    dns_trace
        .snapshot()
        .iter()
        .any(|event| event.protocol == "dns_interception_probe" && event.status == "detected")
}

fn map_gateway_error(error: &GatewayError) -> (u16, &'static str, &'static str) {
    match error {
        GatewayError::Resolver(ResolverError::UnsupportedBackend) => (
            503,
            "HNS Resolution Unavailable",
            "Rust HNS resolver backend is not ready.",
        ),
        GatewayError::Resolver(ResolverError::ProofUnavailable) => (
            503,
            "HNS Proof Unavailable",
            "No current verified HNS proof is available for this name.",
        ),
        GatewayError::Resolver(ResolverError::NameNotFound) => (
            404,
            "HNS Name Not Found",
            "A verified HNS non-inclusion proof says this name does not exist.",
        ),
        GatewayError::Resolver(ResolverError::LocalChainNotCurrent) => (
            503,
            "HNS Sync Incomplete",
            "The local HNS chain is not current enough to determine this name's current state.",
        ),
        GatewayError::Resolver(ResolverError::NoNameserverAddress) => (
            502,
            "HNS Nameserver Unavailable",
            "No verified nameserver address is available for this HNS delegation.",
        ),
        GatewayError::Resolver(ResolverError::NonPublicDnsEndpoint) => (
            403,
            "HNS Nameserver Address Blocked",
            "Native gateway policy blocked a non-public delegated nameserver address.",
        ),
        GatewayError::Resolver(ResolverError::UnsafeAuthoritativeDohPort(_)) => (
            403,
            "HNS Nameserver Port Blocked",
            "Native gateway policy blocked an unsafe delegated authoritative DoH port.",
        ),
        GatewayError::Resolver(ResolverError::DnsTransport(_)) => (
            502,
            "HNS Nameserver Unavailable",
            "Delegated HNS nameserver transport failed closed.",
        ),
        GatewayError::Resolver(ResolverError::Port53InterceptionDetected) => (
            502,
            HNS_PORT53_INTERCEPTION_REASON,
            "This network intercepted direct authoritative DNS.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443.\n\nUsers can enable the requester-only P2P DNS relay or configure an explicit recursive HNS DoH URL in extension settings.",
        ),
        GatewayError::Resolver(ResolverError::DnsResponseCode(_)) => (
            502,
            "HNS Nameserver Response Code",
            "Delegated HNS nameserver returned a DNS failure response code.",
        ),
        GatewayError::Resolver(ResolverError::InvalidDnsResponse) => (
            502,
            "HNS Nameserver Response Invalid",
            "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
        ),
        GatewayError::Resolver(ResolverError::DnssecFailed | ResolverError::RelayDnssecFailed) => (
            502,
            "HNS DNSSEC Validation Failed",
            "Delegated HNS DNSSEC validation failed closed.",
        ),
        GatewayError::Resolver(ResolverError::InvalidName(_)) => {
            (400, "HNS Name Invalid", "Requested HNS name is invalid.")
        }
        GatewayError::Resolver(ResolverError::InvalidResource(_)) => (
            502,
            "HNS Resource Invalid",
            "Verified HNS resource data is malformed or unsupported.",
        ),
        GatewayError::Resolver(ResolverError::InvalidAuthoritativeDoh) => (
            502,
            "HNS Authoritative DoH Invalid",
            "Verified HNS authoritative DoH discovery data is malformed or unsupported.",
        ),
        GatewayError::Resolver(ResolverError::ProofNameMismatch) => (
            502,
            "HNS Proof Validation Failed",
            "HNS proof validation failed closed.",
        ),
        GatewayError::Resolver(ResolverError::NamespaceValidation(_)) => (
            400,
            "Origin Namespace Input Invalid",
            "The browser origin could not be represented by the dual-root classifier.",
        ),
        GatewayError::Resolver(ResolverError::NamespaceClassification(_)) => (
            502,
            "Origin Namespace Indeterminate",
            "HNS and ICANN could not both be classified with current authenticated evidence.",
        ),
        GatewayError::Resolver(ResolverError::NamespaceUnavailable) => (
            404,
            "Origin Not Found",
            "Neither HNS nor ICANN has a usable origin plan for this hostname.",
        ),
        GatewayError::InsecureResolution => (
            502,
            "HNS DNSSEC Validation Failed",
            "Secure HNS resolution was required but the resolver returned an insecure result.",
        ),
        GatewayError::NoResolvedAddress => (
            502,
            "HNS Origin Address Missing",
            "Secure HNS resolution did not produce an origin A or AAAA address.",
        ),
        GatewayError::NonPublicOriginAddress => (
            403,
            "HNS Origin Address Blocked",
            "Native gateway policy blocked a non-public origin address.",
        ),
        GatewayError::UnsafeOriginPort(_) => (
            403,
            "HNS Origin Port Blocked",
            "Native gateway policy blocked a browser-unsafe origin port.",
        ),
        GatewayError::Unauthorized => (
            403,
            "HNS Gateway Authentication Failed",
            "Local gateway authentication failed closed.",
        ),
        GatewayError::InvalidTlsa(_) | GatewayError::Transport(TransportError::DaneFailed) => (
            502,
            "HNS DANE Validation Failed",
            "DANE/TLSA validation failed closed.",
        ),
        GatewayError::IcannDane(_) => (
            502,
            "ICANN DANE Discovery Failed",
            "Automatic ICANN TLSA discovery failed closed.",
        ),
        GatewayError::InvalidSvcb(_) | GatewayError::UnsupportedSvcb => (
            502,
            "HNS HTTPS Service Unsupported",
            "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
        ),
        GatewayError::HostResolutionMismatch => (
            400,
            "HNS Request Mismatch",
            "Origin host does not match the HNS resolution name.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransport) => (
            501,
            "HNS Transport Unsupported",
            "Requested HNS origin transport is not available.",
        ),
        GatewayError::Transport(TransportError::UnsupportedScheme) => (
            501,
            "HNS Scheme Unsupported",
            "Requested HNS origin scheme is not available.",
        ),
        GatewayError::Transport(error) if transport_certificate_expired(error) => (
            502,
            "HNS Origin Certificate Expired",
            "Origin HTTPS certificate is expired; renew the certificate and retry.",
        ),
        GatewayError::Transport(TransportError::Tls(_)) => (
            502,
            "HNS TLS Failed",
            "Origin TLS negotiation failed closed.",
        ),
        GatewayError::Transport(TransportError::InvalidRequest) => (
            400,
            "HNS Origin Request Invalid",
            "Origin request could not be safely forwarded.",
        ),
        GatewayError::Transport(TransportError::RequestTooLarge) => (
            413,
            "HNS Origin Request Too Large",
            "Origin request body exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransferEncoding)
        | GatewayError::Transport(TransportError::MalformedResponse) => (
            502,
            "HNS Origin Response Invalid",
            "Origin HTTP response framing failed closed.",
        ),
        GatewayError::Transport(TransportError::UnsupportedUpgrade) => (
            501,
            "HNS Protocol Upgrade Unsupported",
            "HNS WebSocket/HTTP Upgrade must use the native tunnel path and the request failed validation.",
        ),
        GatewayError::Transport(TransportError::ResponseTooLarge) => (
            502,
            "HNS Origin Response Too Large",
            "Origin response exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::Io(_)) => (
            502,
            "HNS Origin Transport Failed",
            "Origin connection failed closed.",
        ),
        GatewayError::Transport(TransportError::Http2(_)) => (
            502,
            "HNS HTTP/2 Transport Failed",
            "Origin HTTP/2 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Http3(_)) => (
            502,
            "HNS HTTP/3 Transport Failed",
            "Origin HTTP/3 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Quic(_)) => (
            502,
            "HNS QUIC Transport Failed",
            "Origin QUIC connection failed closed.",
        ),
        GatewayError::Resolver(ResolverError::CachePoisoned)
        | GatewayError::Resolver(ResolverError::Storage(_))
        | GatewayError::NonLoopbackBind
        | GatewayError::EmptyAuthToken => (
            500,
            "HNS Gateway Storage Error",
            "Local HNS gateway state is unavailable.",
        ),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GatewayErrorDocument {
    body: Vec<u8>,
    content_type: &'static str,
    headers: Vec<(String, String)>,
}

fn canonical_nameserver_target(record: &ResourceRecord) -> Option<String> {
    let (target, end) = DnsName::parse_wire(&record.rdata, 0).ok()?;
    if end != record.rdata.len() || target == DnsName::root() {
        return None;
    }
    CanonicalHost::parse(&target.to_string())
        .ok()
        .map(|target| target.as_str().to_owned())
}

fn query_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn interception_generator_handoff(
    host: &str,
    dns_trace: &DnsTraceRecorder,
) -> Option<(String, String)> {
    let host = CanonicalHost::parse(host).ok()?;
    let root_name = hns_trace_root(host.as_str()).to_ascii_lowercase();
    if root_name.is_empty() || DnsName::from_ascii(&root_name).is_err() {
        return None;
    }
    let domain = format!("{root_name}/");
    let mut url = format!(
        "{HNS_DANE_GENERATOR_URL}?domain={}&domain_type=hns&intent=authoritative_doh&mode=delegated",
        query_component(&domain)
    );
    let nameserver = dns_trace
        .hns_delegation_snapshot()
        .filter(|delegation| delegation.root_name.eq_ignore_ascii_case(&root_name))
        .and_then(|delegation| delegation.nameservers.into_iter().next());
    if let Some(nameserver) = nameserver {
        url.push_str("&nameserver=");
        url.push_str(&query_component(&nameserver));
    }
    Some((url, domain))
}

fn interception_error_document(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    dns_trace: &DnsTraceRecorder,
) -> GatewayErrorDocument {
    let address = html_escape(&gateway_request_address(input));
    let title = html_escape(&format!("{status} {reason}"));
    let handoff = interception_generator_handoff(input.host, dns_trace);
    let mut body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><p><code>{address}</code></p><h1>{title}</h1>"
    );
    for (index, paragraph) in detail.split("\n\n").enumerate() {
        body.push_str("<p>");
        body.push_str(&html_escape(paragraph));
        if index == 1
            && let Some((url, domain)) = handoff.as_ref()
        {
            body.push_str(" <a href=\"");
            body.push_str(&html_escape(url));
            body.push_str("\">Open the DANE generator for ");
            body.push_str(&html_escape(domain));
            body.push_str("</a>.");
        }
        body.push_str("</p>");
    }
    body.push_str("</body></html>\n");
    GatewayErrorDocument {
        body: body.into_bytes(),
        content_type: "text/html; charset=utf-8",
        headers: vec![
            (
                "Content-Security-Policy".to_owned(),
                INTERCEPTION_ERROR_CSP.to_owned(),
            ),
            ("Referrer-Policy".to_owned(), "no-referrer".to_owned()),
            ("X-Content-Type-Options".to_owned(), "nosniff".to_owned()),
            ("Cache-Control".to_owned(), "no-store".to_owned()),
        ],
    }
}

fn gateway_error_document(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    dns_trace: &DnsTraceRecorder,
) -> GatewayErrorDocument {
    if status == 502 && reason == HNS_PORT53_INTERCEPTION_REASON {
        interception_error_document(input, status, reason, detail, dns_trace)
    } else {
        let address = gateway_request_address(input);
        GatewayErrorDocument {
            body: plain_response_body(status, reason, detail, Some(&address)),
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
        }
    }
}

fn plain_response_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
) -> Vec<u8> {
    let address = gateway_request_address(input);
    plain_response_with_address(status, reason, detail, Some(&address))
}

fn gateway_error_response_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    trace_json: &str,
    dns_trace: &DnsTraceRecorder,
) -> Vec<u8> {
    let document = gateway_error_document(input, status, reason, detail, dns_trace);
    let mut out = response_head(
        status,
        reason,
        Some(document.content_type),
        document.body.len(),
    );
    append_encoded_headers(&mut out, &document.headers);
    append_resolution_trace_headers(&mut out, trace_json);
    out.extend(b"\r\n");
    out.extend(document.body);
    out
}

pub fn plain_response_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
) -> Vec<u8> {
    plain_response_with_address_and_optional_trace(status, reason, detail, address, None)
}

fn plain_response_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    trace_json: Option<&str>,
) -> Vec<u8> {
    let body = plain_response_body(status, reason, detail, address);
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        append_resolution_trace_headers(&mut out, trace_json);
    }
    out.extend(b"\r\n");
    out.extend(body);
    out
}

fn plain_response_to_file_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    let address = gateway_request_address(input);
    plain_response_to_file_with_address(status, reason, detail, Some(&address), body_path)
}

fn gateway_error_response_to_file_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
    trace_json: &str,
    dns_trace: &DnsTraceRecorder,
) -> Result<Vec<u8>, String> {
    let document = gateway_error_document(input, status, reason, detail, dns_trace);
    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    fs::write(body_path, &document.body)
        .map_err(|error| format!("write response body: {error}"))?;
    let mut out = response_head(
        status,
        reason,
        Some(document.content_type),
        document.body.len(),
    );
    append_encoded_headers(&mut out, &document.headers);
    append_resolution_trace_headers(&mut out, trace_json);
    out.extend(b"\r\n");
    Ok(out)
}

pub fn plain_response_to_file_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    plain_response_to_file_with_address_and_optional_trace(
        status, reason, detail, address, body_path, None,
    )
}

fn plain_response_to_file_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
    trace_json: Option<&str>,
) -> Result<Vec<u8>, String> {
    let body = plain_response_body(status, reason, detail, address);
    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    fs::write(body_path, &body).map_err(|error| format!("write response body: {error}"))?;
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        append_resolution_trace_headers(&mut out, trace_json);
    }
    out.extend(b"\r\n");
    Ok(out)
}

fn append_encoded_headers(out: &mut Vec<u8>, headers: &[(String, String)]) {
    for (name, value) in headers {
        out.extend(format!("{name}: {value}\r\n").as_bytes());
    }
}

fn append_resolution_trace_headers(out: &mut Vec<u8>, trace_json: &str) {
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
}

fn plain_response_body(status: u16, reason: &str, detail: &str, address: Option<&str>) -> Vec<u8> {
    match address {
        Some(address) => format!("{address}\n{status} {reason}\n{detail}\n").into_bytes(),
        None => format!("{status} {reason}\n{detail}\n").into_bytes(),
    }
}

fn gateway_request_address(input: &GatewayHttpRequestInput<'_>) -> String {
    let scheme = input.scheme.to_ascii_lowercase();
    let port = match (scheme.as_str(), input.port) {
        ("http" | "ws", 80) | ("https" | "wss", 443) => String::new(),
        (_, port) => format!(":{port}"),
    };
    let path = if input.path_and_query.is_empty() {
        "/"
    } else {
        input.path_and_query
    };
    format!("{scheme}://{}{}{}", input.host, port, path)
}

fn response_head(
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    body_len: usize,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {body_len}\r\n"
    )
    .into_bytes();
    if let Some(content_type) = content_type {
        out.extend(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    out
}

struct PreparedHeaderSyncStage {
    root: PathBuf,
    baseline_peers: hns_p2p::PeerManager,
    baseline_storage_identity: HeaderSyncStorageIdentity,
}

impl PreparedHeaderSyncStage {
    fn create(data_dir: &str, network: NetworkKind) -> Result<Self, String> {
        let parent = Path::new(data_dir);
        fs::create_dir_all(parent)
            .map_err(|error| format!("create header sync staging parent: {error}"))?;
        let prefix = format!(".header-sync-stage-{}-", network.as_str());
        reclaim_stale_header_sync_stages(parent, &prefix)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        for _ in 0..64 {
            let sequence = HEADER_SYNC_STAGE_SEQUENCE.fetch_add(1, Ordering::AcqRel);
            let root = parent.join(format!(
                "{prefix}{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Ok(Self {
                        root,
                        baseline_peers: hns_p2p::PeerManager::default(),
                        baseline_storage_identity: HeaderSyncStorageIdentity {
                            header_generation: 0,
                            peer_generation: 0,
                            best_hash: None,
                        },
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("create header sync staging directory: {error}"));
                }
            }
        }
        Err("could not allocate a unique header sync staging directory".to_owned())
    }

    fn data_dir(&self) -> Result<&str, RuntimeError> {
        self.root.to_str().ok_or_else(|| {
            RuntimeError::InvalidConfiguration(
                "header sync staging path must be valid UTF-8".to_owned(),
            )
        })
    }

    fn network_base(&self, network: NetworkKind) -> Result<PathBuf, String> {
        let data_dir = self
            .root
            .to_str()
            .ok_or_else(|| "header sync staging path must be valid UTF-8".to_owned())?;
        Ok(network_base_path(data_dir, network))
    }
}

fn reclaim_stale_header_sync_stages(parent: &Path, prefix: &str) -> Result<(), String> {
    let now = SystemTime::now();
    let entries = fs::read_dir(parent)
        .map_err(|error| format!("scan header sync staging directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("inspect header sync stage entry: {error}"))?;
        if !entry.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect header sync stage type: {error}"))?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|error| format!("inspect header sync stage age: {error}"))?;
        let age = now.duration_since(modified).unwrap_or_default();
        if age.as_secs() < HEADER_SYNC_STAGE_STALE_AFTER_SECONDS {
            continue;
        }
        fs::remove_dir_all(entry.path())
            .map_err(|error| format!("reclaim stale header sync stage: {error}"))?;
    }
    Ok(())
}

impl Drop for PreparedHeaderSyncStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn prepare_header_sync_stage(
    data_dir: &str,
    network: NetworkKind,
    coordination: &RuntimeCoordination,
) -> Result<PreparedHeaderSyncStage, String> {
    let mut staged = PreparedHeaderSyncStage::create(data_dir, network)?;
    let live_base = network_base_path(data_dir, network);
    let staged_base = staged.network_base(network)?;
    fs::create_dir_all(&staged_base)
        .map_err(|error| format!("create staged sync directory: {error}"))?;

    let _maintenance = coordination
        .maintenance
        .read()
        .map_err(|_| "maintenance lock is poisoned".to_owned())?;
    let _header_state_lock = HeaderStateFileLock::shared(&coordination.header_state_lock_path)?;
    let live_chain = open_initialized_header_chain(&live_base, network)?;
    let live_header_store = live_chain.into_store();
    let header_generation = live_header_store
        .sync_generation()
        .map_err(|error| format!("read live header sync generation: {error}"))?;
    let best_hash = live_header_store.best_hash();
    live_header_store
        .snapshot_to(staged_base.join("headers.sqlite"))
        .map_err(|error| format!("snapshot live header store: {error}"))?;
    live_header_store
        .flush()
        .map_err(|error| format!("close live header snapshot source: {error}"))?;
    let mut staged_header_store = SqliteHeaderStore::open(staged_base.join("headers.sqlite"))
        .map_err(|error| format!("open staged header publication delta: {error}"))?;
    staged_header_store
        .begin_snapshot_publication_delta(header_generation, best_hash)
        .map_err(|error| format!("initialize staged header publication delta: {error}"))?;
    staged_header_store
        .flush()
        .map_err(|error| format!("close staged header publication delta: {error}"))?;

    let _peer_state = coordination
        .peer_state
        .lock()
        .map_err(|_| "peer-state lock is poisoned".to_owned())?;
    let live_peer_store_path = live_base.join("peers.sqlite");
    let _process_peer_state =
        HeaderStateFileLock::shared(&peer_state_lock_path(&live_peer_store_path)?)?;
    let live_peer_store = SqlitePeerStore::open(live_peer_store_path)
        .map_err(|error| format!("open live peer store for staging: {error}"))?;
    let peer_generation = live_peer_store
        .sync_generation()
        .map_err(|error| format!("read live peer sync generation: {error}"))?;
    staged.baseline_peers = live_peer_store
        .load_manager()
        .map_err(|error| format!("load live peer store for staging: {error}"))?;
    staged.baseline_storage_identity = HeaderSyncStorageIdentity {
        header_generation,
        peer_generation,
        best_hash,
    };
    live_peer_store
        .flush()
        .map_err(|error| format!("close live peer staging source: {error}"))?;
    drop((
        _process_peer_state,
        _peer_state,
        _header_state_lock,
        _maintenance,
    ));

    let staged_peer_store = SqlitePeerStore::open(staged_base.join("peers.sqlite"))
        .map_err(|error| format!("open staged peer store: {error}"))?;
    staged_peer_store
        .replace_manager_with_sync_generation(&staged.baseline_peers, header_generation)
        .map_err(|error| format!("seed staged peer store: {error}"))?;
    staged_peer_store
        .flush()
        .map_err(|error| format!("close seeded staged peer store: {error}"))?;
    Ok(staged)
}

fn target_evidence_deadline_advanced(before: Option<u64>, after: Option<u64>) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => after > before,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn staged_headers_match_baseline(
    staged: &PreparedHeaderSyncStage,
    network: NetworkKind,
) -> Result<bool, String> {
    if staged.baseline_storage_identity.header_generation
        != staged.baseline_storage_identity.peer_generation
    {
        return Ok(false);
    }
    let staged_base = staged.network_base(network)?;
    let staged_header_store = SqliteHeaderStore::open(staged_base.join("headers.sqlite"))
        .map_err(|error| format!("open completed staged header store: {error}"))?;
    let staged_generation = staged_header_store
        .sync_generation()
        .map_err(|error| format!("read completed staged header generation: {error}"))?;
    Ok(
        staged_generation == staged.baseline_storage_identity.header_generation
            && staged_header_store.best_hash() == staged.baseline_storage_identity.best_hash,
    )
}

fn publish_peer_only_sync_stage(
    data_dir: &str,
    staged: &PreparedHeaderSyncStage,
    network: NetworkKind,
    staged_status: NativeSyncStatus,
) -> Result<NativeSyncStatus, String> {
    let live_base = network_base_path(data_dir, network);
    let live_identity = read_header_sync_storage_identity(&live_base)?;
    if live_identity != staged.baseline_storage_identity {
        return Err("header sync stage was superseded before peer-only publication".to_owned());
    }
    if !staged_headers_match_baseline(staged, network)? {
        return Err(
            "peer-only publication requires an unchanged, generation-matched header stage"
                .to_owned(),
        );
    }

    let staged_base = staged.network_base(network)?;
    let staged_peer_store = SqlitePeerStore::open(staged_base.join("peers.sqlite"))
        .map_err(|error| format!("open completed staged peer store: {error}"))?;
    let staged_peers = staged_peer_store
        .load_manager()
        .map_err(|error| format!("load completed staged peer store: {error}"))?;
    let live_peer_store = SqlitePeerStore::open(live_base.join("peers.sqlite"))
        .map_err(|error| format!("open live peer store for peer refresh: {error}"))?;
    let live_peers = live_peer_store
        .load_manager()
        .map_err(|error| format!("load live peer store for peer refresh: {error}"))?;
    let merged_peers = merge_staged_peer_manager(
        &staged.baseline_peers,
        &staged_peers,
        &live_peers,
        &network.network(),
    );
    live_peer_store
        .replace_manager_with_sync_generation(
            &merged_peers,
            staged.baseline_storage_identity.header_generation,
        )
        .map_err(|error| format!("publish refreshed peer evidence: {error}"))?;

    let published_status = read_sync_status(data_dir, network)?;
    Ok(apply_staged_sync_outcome(
        published_status,
        staged_status,
        0,
    ))
}

fn publish_header_sync_stage(
    data_dir: &str,
    staged: &PreparedHeaderSyncStage,
    network: NetworkKind,
    resource_cache_limit_bytes: usize,
    staged_status: NativeSyncStatus,
) -> Result<NativeSyncStatus, String> {
    let live_base = network_base_path(data_dir, network);
    let staged_base = staged.network_base(network)?;
    let staged_header_path = staged_base.join("headers.sqlite");
    let staged_peer_store = SqlitePeerStore::open(staged_base.join("peers.sqlite"))
        .map_err(|error| format!("open completed staged peer store: {error}"))?;
    let staged_peers = staged_peer_store
        .load_manager()
        .map_err(|error| format!("load completed staged peer store: {error}"))?;

    let live_peer_store = SqlitePeerStore::open(live_base.join("peers.sqlite"))
        .map_err(|error| format!("open live peer store for publication: {error}"))?;
    let live_peers = live_peer_store
        .load_manager()
        .map_err(|error| format!("load live peer store for publication: {error}"))?;
    let merged_peers = merge_staged_peer_manager(
        &staged.baseline_peers,
        &staged_peers,
        &live_peers,
        &network.network(),
    );

    let mut live_header_store = SqliteHeaderStore::open(live_base.join("headers.sqlite"))
        .map_err(|error| format!("open live header store for publication: {error}"))?;
    let live_header_generation = live_header_store
        .sync_generation()
        .map_err(|error| format!("read live header sync generation: {error}"))?;
    let live_best_hash = live_header_store.best_hash();
    let live_peer_generation = live_peer_store
        .sync_generation()
        .map_err(|error| format!("read live peer sync generation: {error}"))?;
    let live_storage_identity = HeaderSyncStorageIdentity {
        header_generation: live_header_generation,
        peer_generation: live_peer_generation,
        best_hash: live_best_hash,
    };
    if live_storage_identity != staged.baseline_storage_identity {
        return Err(
            "header sync stage was superseded by another process before publication".to_owned(),
        );
    }
    let mut staged_header_store = SqliteHeaderStore::open(&staged_header_path)
        .map_err(|error| format!("open staged header store for publication: {error}"))?;
    let staged_header_generation = staged_header_store
        .sync_generation()
        .map_err(|error| format!("read staged header sync generation: {error}"))?;
    if staged_header_generation != staged.baseline_storage_identity.header_generation {
        return Err("completed header sync stage has an unexpected base generation".to_owned());
    }
    let next_generation = staged
        .baseline_storage_identity
        .header_generation
        .max(staged.baseline_storage_identity.peer_generation)
        .checked_add(1)
        .ok_or_else(|| "header sync publication generation is exhausted".to_owned())?;
    staged_header_store
        .set_sync_generation(next_generation)
        .map_err(|error| format!("stage header sync generation: {error}"))?;
    staged_header_store
        .flush()
        .map_err(|error| format!("close staged header publication source: {error}"))?;

    // Header state is committed first. If the peer transaction fails or the
    // process exits between the two databases, their generation mismatch is
    // detected by every readiness check and fails closed until the next sync.
    let published = live_header_store
        .publish_snapshot_from_if_current(
            &staged_header_path,
            staged.baseline_storage_identity.header_generation,
            staged.baseline_storage_identity.best_hash,
        )
        .map_err(|error| format!("publish staged header store: {error}"))?;
    if !published {
        return Err("header sync stage was superseded during conditional publication".to_owned());
    }
    live_peer_store
        .replace_manager_with_sync_generation(&merged_peers, next_generation)
        .map_err(|error| format!("publish staged peer store: {error}"))?;

    let live_chain = chain_for_network(live_header_store, network);
    let resource_cache_evicted =
        prune_resource_cache_to_best_chain(&live_base, &live_chain)?.saturating_add(
            enforce_resource_cache_limit(&live_base, resource_cache_limit_bytes)?,
        );
    let published_status = read_sync_status(data_dir, network)?;
    Ok(apply_staged_sync_outcome(
        published_status,
        staged_status,
        resource_cache_evicted,
    ))
}

fn apply_staged_sync_outcome(
    mut published_status: NativeSyncStatus,
    staged_status: NativeSyncStatus,
    resource_cache_evicted: usize,
) -> NativeSyncStatus {
    published_status.status = staged_status.status;
    published_status.attempted = staged_status.attempted;
    published_status.successful = staged_status.successful;
    published_status.accepted = staged_status.accepted;
    published_status.failed = staged_status.failed;
    published_status.resource_cache_evicted = resource_cache_evicted;
    published_status.error = staged_status.error;
    published_status.failures = staged_status.failures;
    published_status
}

fn merge_staged_peer_manager(
    baseline: &hns_p2p::PeerManager,
    staged: &hns_p2p::PeerManager,
    live: &hns_p2p::PeerManager,
    network: &hns_core::network::Network,
) -> hns_p2p::PeerManager {
    let mut addresses = HashSet::new();
    addresses.extend(staged.iter().map(|peer| peer.address));
    addresses.extend(live.iter().map(|peer| peer.address));
    let mut merged = Vec::with_capacity(addresses.len());

    for address in addresses {
        let baseline_peer = baseline.get(address);
        let staged_peer = staged.get(address);
        let live_peer = live.get(address);
        let mut peer = match (live_peer, staged_peer) {
            (Some(live_peer), Some(staged_peer)) => {
                let mut peer = merge_dns_relay_peer_state(live_peer, staged_peer);
                peer.score = merge_peer_score(
                    baseline_peer.map(|peer| peer.score),
                    live_peer.score,
                    staged_peer.score,
                );
                peer.successes = merge_monotonic_peer_counter(
                    baseline_peer.map(|peer| peer.successes),
                    live_peer.successes,
                    staged_peer.successes,
                );
                peer.failures = merge_monotonic_peer_counter(
                    baseline_peer.map(|peer| peer.failures),
                    live_peer.failures,
                    staged_peer.failures,
                );
                if baseline_peer.map(peer_height_tuple) != Some(peer_height_tuple(staged_peer)) {
                    peer.last_height = staged_peer.last_height;
                    peer.last_height_observed_at = staged_peer.last_height_observed_at;
                }
                peer
            }
            (Some(peer), None) | (None, Some(peer)) => peer.clone(),
            (None, None) => continue,
        };
        if is_allowed_peer_endpoint(network, peer.address) {
            // Normalize expired zero-height evidence before it can enter the
            // coordinated snapshot through a transport-only concurrent peer.
            if peer.last_height.0 == 0 {
                peer.last_height_observed_at = None;
            }
            merged.push(peer);
        }
    }

    hns_p2p::PeerManager::from_states(merged)
}

fn peer_height_tuple(peer: &hns_p2p::PeerState) -> (Height, Option<u64>) {
    (peer.last_height, peer.last_height_observed_at)
}

fn merge_monotonic_peer_counter(baseline: Option<u32>, live: u32, staged: u32) -> u32 {
    let baseline = baseline.unwrap_or(0);
    baseline
        .saturating_add(live.saturating_sub(baseline))
        .saturating_add(staged.saturating_sub(baseline))
        .max(live)
        .max(staged)
}

fn merge_peer_score(baseline: Option<i32>, live: i32, staged: i32) -> i32 {
    let baseline = i64::from(baseline.unwrap_or(0));
    let live_delta = i64::from(live).saturating_sub(baseline);
    let staged_delta = i64::from(staged).saturating_sub(baseline);
    baseline
        .saturating_add(live_delta)
        .saturating_add(staged_delta)
        .clamp(0, i64::from(i32::MAX)) as i32
}

fn run_sync_once(
    data_dir: &str,
    network_kind: NetworkKind,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network_kind);
    let peer_store_path = base.join("peers.sqlite");
    let _process_peer_state =
        HeaderStateFileLock::exclusive(&peer_state_lock_path(&peer_store_path)?)?;
    let chain = open_initialized_header_chain(&base, network_kind)?;
    let mut coordinator = HeaderSyncCoordinator::new(chain);

    let peer_store = SqlitePeerStore::open(peer_store_path)
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    let network = network_kind.network();
    let pruned_peers = retain_allowed_peer_endpoints(&mut peers, &network);
    if pruned_peers > 0 {
        peer_store
            .save_manager(&peers)
            .map_err(|error| format!("save pruned peer store: {error}"))?;
    }
    let mut seed_error = None;
    if seed_on_empty && allowed_peer_count(&peers, &network) < ANDROID_MIN_PEER_TARGET {
        let was_empty = allowed_peer_count(&peers, &network) == 0;
        match seed_peers_for_network(&mut peers, &network, network_kind) {
            Ok(inserted) => {
                if inserted > 0 {
                    peer_store
                        .save_manager(&peers)
                        .map_err(|error| format!("save seeded peers: {error}"))?;
                }
            }
            Err(error) => {
                if was_empty {
                    seed_error = Some(error.to_string());
                }
            }
        }
    }

    let runner = HeaderSyncRunner::with_config(
        network,
        TcpHeaderPeerConnector,
        HeaderSyncRunnerConfig {
            preferred_peers: ANDROID_HEADER_SYNC_PEERS,
            max_header_batches_per_peer: ANDROID_HEADER_SYNC_BATCHES_PER_PEER,
            peer_discovery_target: ANDROID_MIN_PEER_TARGET,
            parallel_peer_probes: ANDROID_PARALLEL_PEER_PROBES,
            parallel_header_fetch_peers: ANDROID_PARALLEL_HEADER_FETCH_PEERS,
            peer_height_refresh_interval: ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS,
            checkpoint_header_prefetch: sync_checkpoints_for_network(network_kind),
            timeout,
            ..HeaderSyncRunnerConfig::default()
        },
    );
    let result = runner
        .sync_once_parallel_and_persist_with_completion_time(
            &mut coordinator,
            &mut peers,
            &peer_store,
            now_unix_seconds(),
            now_unix_seconds,
        )
        .map_err(|error| format!("sync headers: {error}"))?;
    let best = coordinator
        .chain()
        .best_header()
        .map_err(|error| format!("read synced best header: {error}"))?;
    let now = now_unix_seconds();
    let peer_count = peers.len();
    let peer_groups = peers.address_group_count(now);
    let best_peer_height = best_peer_height(&peers);
    let best_height = best.as_ref().map(|header| header.height.0);
    let estimated_tip_height = estimated_tip_height_for_network(network_kind, now);
    let peer_target = assess_peer_target(&peers, &network_kind.network(), now);
    let currentness = LocalChainCurrentness::new(
        network_kind,
        best_height,
        peer_target.height,
        estimated_tip_height,
    );
    let resource_cache_evicted =
        prune_resource_cache_to_best_chain(&base, coordinator.chain())?.saturating_add(
            enforce_resource_cache_limit(&base, resource_cache_limit_bytes)?,
        );
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;
    let failed = result.failures.len();
    let status = classify_sync_status(
        result.attempted,
        result.successful,
        result.accepted,
        failed,
        seed_error.is_some(),
        best_height,
        currentness.target_height,
    );
    let error = if status == "peer_failed" {
        Some(format!(
            "all {} attempted sync peers failed; see failures",
            result.attempted,
        ))
    } else {
        seed_error
    };

    Ok(NativeSyncStatus {
        network: network_kind,
        status,
        attempted: result.attempted,
        successful: result.successful,
        accepted: result.accepted,
        failed,
        peer_count,
        peer_groups,
        best_height,
        best_peer_height,
        estimated_tip_height,
        effective_target_height: currentness.target_height,
        lag_blocks: currentness.lag_blocks,
        freshness: currentness.freshness.as_str(),
        freshness_threshold_blocks: LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
        tree_interval_blocks: canonical_name_tree_interval(canonical_network(network_kind)),
        authoritative_tree_root_height: currentness.authoritative_tree_root_height,
        local_tree_root_height: currentness.local_tree_root_height,
        tree_root_ready: currentness.tree_root_ready,
        blocks_until_authoritative_tree_root: currentness.blocks_until_authoritative_tree_root,
        target_source: peer_target
            .height
            .map(|_| CurrentnessTargetSource::CorroboratedPeers.as_str())
            .unwrap_or_else(|| CurrentnessTargetSource::Unknown.as_str()),
        target_peer_groups: peer_target.peer_groups,
        target_evidence_expired: peer_target.evidence_expired,
        target_evidence_valid_until_unix: peer_target.evidence_valid_until_unix,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted,
        error,
        failures: result
            .failures
            .into_iter()
            .map(|failure| NativePeerFailure {
                address: failure.address.to_string(),
                stage: failure.stage.as_str(),
                error: failure.error,
            })
            .collect(),
    })
}

fn classify_sync_status(
    attempted: usize,
    successful: usize,
    accepted: usize,
    failed: usize,
    seed_failed: bool,
    best_height: Option<u32>,
    effective_target_height: Option<u32>,
) -> &'static str {
    if successful > 0 && accepted > 0 {
        if is_sync_behind(best_height, effective_target_height)
            || is_sync_target_unknown(best_height, effective_target_height)
        {
            "syncing"
        } else {
            "synced"
        }
    } else if successful > 0 {
        if is_sync_behind(best_height, effective_target_height) {
            "syncing"
        } else {
            "up_to_date"
        }
    } else if attempted > 0 && failed == attempted {
        "peer_failed"
    } else if attempted > 0 {
        "attempted"
    } else if seed_failed {
        "seed_failed"
    } else {
        "idle"
    }
}

fn is_sync_behind(best_height: Option<u32>, effective_target_height: Option<u32>) -> bool {
    matches!((best_height, effective_target_height), (Some(best), Some(target)) if target > best)
}

fn is_sync_target_unknown(best_height: Option<u32>, effective_target_height: Option<u32>) -> bool {
    matches!((best_height, effective_target_height), (Some(best), None) if best > 0)
}

fn best_peer_height(peers: &hns_p2p::PeerManager) -> Option<u32> {
    peers
        .iter()
        .map(|peer| peer.last_height.0)
        .filter(|height| *height > 0)
        .max()
}

/// Derives an outlier-resistant currentness target from advisory peer heights.
///
/// One observation per network address group is retained, preferring the most
/// recent header-sync observation. At least three groups must corroborate a
/// target, and the lower median prevents one isolated high claim from forcing
/// the browser permanently stale. Old observations cannot certify currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerTargetAssessment {
    height: Option<u32>,
    peer_groups: usize,
    evidence_expired: bool,
    evidence_valid_until_unix: Option<u64>,
}

fn assess_peer_target(
    peers: &hns_p2p::PeerManager,
    network: &hns_core::network::Network,
    now: u64,
) -> PeerTargetAssessment {
    let mut by_group = HashMap::<PeerAddressGroup, (u64, u32)>::new();
    let mut evidence_expired = false;
    for peer in peers.iter().filter(|peer| {
        !peer.is_banned(now)
            && peer.successes > 0
            && peer.last_height.0 > 0
            && is_allowed_peer_endpoint(network, peer.address)
    }) {
        let Some(observed_at) = peer.last_height_observed_at else {
            continue;
        };
        if observed_at > now {
            continue;
        }
        if now.saturating_sub(observed_at) > LOCAL_CHAIN_TARGET_OBSERVATION_MAX_AGE_SECONDS {
            evidence_expired = true;
            continue;
        }
        let group = PeerAddressGroup::from_socket_addr(peer.address);
        let candidate = (observed_at, peer.last_height.0);
        by_group
            .entry(group)
            .and_modify(|current| {
                if candidate > *current {
                    *current = candidate;
                }
            })
            .or_insert(candidate);
    }

    let peer_groups = by_group.len();
    let observations = by_group.into_values().collect::<Vec<_>>();
    let mut heights = observations
        .iter()
        .map(|(_, height)| *height)
        .collect::<Vec<_>>();
    heights.sort_unstable();
    let height = (heights.len() >= LOCAL_CHAIN_TARGET_MIN_PEER_GROUPS)
        .then(|| heights[(heights.len() - 1) / 2]);
    let evidence_valid_until_unix = height.map(|_| {
        let mut expirations = observations
            .iter()
            .map(|(observed_at, _)| {
                observed_at.saturating_add(LOCAL_CHAIN_TARGET_OBSERVATION_MAX_AGE_SECONDS)
            })
            .collect::<Vec<_>>();
        expirations.sort_unstable();
        expirations[peer_groups - LOCAL_CHAIN_TARGET_MIN_PEER_GROUPS]
    });
    PeerTargetAssessment {
        height,
        peer_groups,
        evidence_expired: height.is_none() && evidence_expired,
        evidence_valid_until_unix,
    }
}

fn open_initialized_header_chain(
    base: &Path,
    network: NetworkKind,
) -> Result<HeaderChain<SqliteHeaderStore>, String> {
    fs::create_dir_all(base).map_err(|error| format!("create sync directory: {error}"))?;
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| format!("open header store: {error}"))?;
    let mut chain = chain_for_network(header_store, network);
    if chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?
        .is_none()
    {
        chain
            .insert_genesis(BlockHeader::genesis_for_network(network))
            .map_err(|error| format!("insert genesis header: {error}"))?;
    }
    Ok(chain)
}

fn install_header_snapshot_inner(
    data_dir: &str,
    snapshot_path: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    if network != NetworkKind::Mainnet {
        return Err("bundled header snapshot is only available for mainnet".to_owned());
    }
    let base = network_base_path(data_dir, network);
    let mut snapshot =
        fs::File::open(snapshot_path).map_err(|error| format!("open header snapshot: {error}"))?;
    let metadata = read_header_snapshot_metadata(&mut snapshot)?;
    let mut chain = open_initialized_header_chain(&base, network)?;
    if chain
        .best_header()
        .map_err(|error| format!("read best header before snapshot import: {error}"))?
        .is_some_and(|header| header.height.0 >= metadata.target_height)
    {
        return sync_status_with_override(data_dir, network, "snapshot_present", 1, 1, 0);
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    snapshot
        .read_exact(&mut header_bytes)
        .map_err(|error| format!("read snapshot genesis header: {error}"))?;
    let genesis = BlockHeader::parse(&header_bytes)
        .map_err(|error| format!("parse snapshot genesis header: {error}"))?;
    if genesis != BlockHeader::mainnet_genesis() {
        return Err("snapshot genesis header does not match mainnet".to_owned());
    }

    let mut accepted_total = 0usize;
    let mut batch = Vec::with_capacity(HEADER_SNAPSHOT_IMPORT_BATCH);
    for height in 1..=metadata.target_height {
        snapshot
            .read_exact(&mut header_bytes)
            .map_err(|error| format!("read snapshot header {height}: {error}"))?;
        let header = BlockHeader::parse(&header_bytes)
            .map_err(|error| format!("parse snapshot header {height}: {error}"))?;
        batch.push(header);
        if batch.len() >= HEADER_SNAPSHOT_IMPORT_BATCH {
            accepted_total = accepted_total
                .saturating_add(insert_header_snapshot_batch(&mut chain, &mut batch)?);
        }
    }
    accepted_total =
        accepted_total.saturating_add(insert_header_snapshot_batch(&mut chain, &mut batch)?);

    let mut trailing = [0u8; 1];
    if snapshot
        .read(&mut trailing)
        .map_err(|error| format!("read snapshot trailer: {error}"))?
        != 0
    {
        return Err("header snapshot has trailing bytes".to_owned());
    }

    let tip = chain
        .canonical_header(Height(metadata.target_height))
        .ok_or_else(|| "snapshot target height is not canonical after import".to_owned())?;
    if tip.hash != metadata.tip_hash {
        return Err(format!(
            "snapshot tip hash mismatch at height {}: got {}, expected {}",
            metadata.target_height, tip.hash, metadata.tip_hash
        ));
    }

    sync_status_with_override(data_dir, network, "snapshot_imported", 1, 1, accepted_total)
}

fn insert_header_snapshot_batch(
    chain: &mut HeaderChain<SqliteHeaderStore>,
    batch: &mut Vec<BlockHeader>,
) -> Result<usize, String> {
    if batch.is_empty() {
        return Ok(0);
    }
    let headers = std::mem::take(batch);
    let accepted = chain
        .insert_headers(headers)
        .map_err(|error| format!("import header snapshot batch: {error}"))?
        .len();
    batch.reserve(HEADER_SNAPSHOT_IMPORT_BATCH);
    Ok(accepted)
}

struct HeaderSnapshotMetadata {
    target_height: u32,
    tip_hash: hns_core::Hash,
}

fn read_header_snapshot_metadata<R: Read>(
    reader: &mut R,
) -> Result<HeaderSnapshotMetadata, String> {
    let mut magic = vec![0u8; HEADER_SNAPSHOT_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("read header snapshot magic: {error}"))?;
    if magic != HEADER_SNAPSHOT_MAGIC {
        return Err("header snapshot magic mismatch".to_owned());
    }

    let target_height = read_u32_be(reader, "target height")?;
    if target_height > HEADER_SNAPSHOT_MAX_HEIGHT {
        return Err(format!(
            "header snapshot target height {target_height} exceeds import limit {HEADER_SNAPSHOT_MAX_HEIGHT}"
        ));
    }
    let header_count = read_u32_be(reader, "header count")?;
    let expected_count = target_height.saturating_add(1);
    if header_count != expected_count {
        return Err(format!(
            "header snapshot count mismatch: got {header_count}, expected {expected_count}"
        ));
    }

    let mut tip_hash = [0u8; 32];
    reader
        .read_exact(&mut tip_hash)
        .map_err(|error| format!("read header snapshot tip hash: {error}"))?;
    let tip_hash = hns_core::Hash::from_slice(&tip_hash)
        .map_err(|error| format!("parse header snapshot tip hash: {error}"))?;

    Ok(HeaderSnapshotMetadata {
        target_height,
        tip_hash,
    })
}

fn read_u32_be<R: Read>(reader: &mut R, field: &str) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("read header snapshot {field}: {error}"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn reset_headers_from_peers_inner(
    data_dir: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;
    remove_sqlite_database(&base.join("headers.sqlite"))?;
    clear_resource_cache_at_base(&base)?;
    let _chain = open_initialized_header_chain(&base, network)?;
    let mut status = read_sync_status(data_dir, network)
        .unwrap_or_else(|_| NativeSyncStatus::empty_for(network));
    status.status = "headers_reset";
    status.resource_cache_entries = 0;
    status.resource_cache_bytes = 0;
    status.resource_cache_evicted = 0;
    Ok(status)
}

fn remove_sqlite_database(path: &Path) -> Result<(), String> {
    let mut paths = Vec::with_capacity(3);
    paths.push(path.to_path_buf());
    paths.push(PathBuf::from(format!("{}-wal", path.display())));
    paths.push(PathBuf::from(format!("{}-shm", path.display())));

    for candidate in paths {
        match fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove sqlite database file {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    Ok(())
}

fn sync_status_with_override(
    data_dir: &str,
    network: NetworkKind,
    status_label: &'static str,
    attempted: usize,
    successful: usize,
    accepted: usize,
) -> Result<NativeSyncStatus, String> {
    let mut status = read_sync_status(data_dir, network)?;
    status.status = status_label;
    status.attempted = attempted;
    status.successful = successful;
    status.accepted = accepted;
    Ok(status)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalChainCurrentness {
    best_height: Option<u32>,
    target_height: Option<u32>,
    estimated_tip_height: Option<u32>,
    lag_blocks: Option<u32>,
    freshness: ChainFreshness,
    stale: Option<bool>,
    authoritative_tree_root_height: Option<u32>,
    local_tree_root_height: Option<u32>,
    tree_root_ready: Option<bool>,
    blocks_until_authoritative_tree_root: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainFreshness {
    Current,
    Stale,
    Unknown,
}

impl ChainFreshness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentnessTargetSource {
    CorroboratedPeers,
    Unknown,
}

impl CurrentnessTargetSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CorroboratedPeers => "corroboratedPeers",
            Self::Unknown => "unknown",
        }
    }
}

impl LocalChainCurrentness {
    fn new(
        network: NetworkKind,
        best_height: Option<u32>,
        target_height: Option<u32>,
        estimated_tip_height: Option<u32>,
    ) -> Self {
        // A schedule-derived height is useful diagnostic context, but Handshake
        // production does not track the ideal ten-minute schedule closely
        // enough for it to authorize browser name decisions.
        let target_height = match (best_height, target_height) {
            (Some(best), Some(target)) if best > 0 => Some(target.max(best)),
            _ => None,
        };
        let lag_blocks = match (best_height, target_height) {
            (Some(best), Some(target)) if best > 0 => Some(target.saturating_sub(best)),
            _ => None,
        };
        let freshness = match lag_blocks {
            Some(lag) if lag <= LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG => ChainFreshness::Current,
            Some(_) => ChainFreshness::Stale,
            None => ChainFreshness::Unknown,
        };
        let stale = match freshness {
            ChainFreshness::Current => Some(false),
            ChainFreshness::Stale => Some(true),
            ChainFreshness::Unknown => None,
        };
        let authority_target_height = match network {
            NetworkKind::Mainnet | NetworkKind::Testnet => target_height,
            NetworkKind::Regtest => target_height.or(best_height),
        };
        let name_tree = CanonicalNameTreeCurrentness::assess(
            canonical_network(network),
            best_height,
            authority_target_height,
        );
        let authoritative_tree_root_height = name_tree.target_authority_height();
        let local_tree_root_height = name_tree.local_authority_height();
        let tree_root_ready = match (local_tree_root_height, authoritative_tree_root_height) {
            (Some(_), Some(_)) => Some(name_tree.is_ready()),
            _ => None,
        };
        Self {
            best_height,
            target_height,
            estimated_tip_height,
            lag_blocks,
            freshness,
            stale,
            authoritative_tree_root_height,
            local_tree_root_height,
            tree_root_ready,
            blocks_until_authoritative_tree_root: name_tree.blocks_until_authority(),
        }
    }
}

fn local_chain_lacks_authoritative_tree_root(
    base: &Path,
    network: NetworkKind,
) -> Result<bool, ResolverError> {
    Ok(local_chain_currentness(base, network)?.tree_root_ready != Some(true))
}

fn authoritative_tree_root_header(
    base: &Path,
    network: NetworkKind,
) -> Result<hns_chain::StoredHeader, ResolverError> {
    let currentness = local_chain_currentness(base, network)?;
    if currentness.tree_root_ready != Some(true) {
        return Err(ResolverError::LocalChainNotCurrent);
    }
    let required_height = currentness
        .authoritative_tree_root_height
        .or(currentness.local_tree_root_height)
        .ok_or(ResolverError::LocalChainNotCurrent)?;
    let store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    chain_for_network(store, network)
        .canonical_header(Height(required_height))
        .ok_or(ResolverError::LocalChainNotCurrent)
}

fn hns_anchor_matches_authoritative_tree_root(
    base: &Path,
    network: NetworkKind,
    anchor: ResourceValueAnchor,
) -> Result<bool, ResolverError> {
    let authority = authoritative_tree_root_header(base, network)?;
    let store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = chain_for_network(store, network);
    let canonical_anchor = chain.canonical_header(anchor.height);
    Ok(canonical_anchor.is_some_and(|header| {
        header.header.tree_root == anchor.tree_root
            && authority.header.tree_root == anchor.tree_root
    }))
}

fn local_chain_currentness(
    base: &Path,
    network: NetworkKind,
) -> Result<LocalChainCurrentness, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let header_generation = header_store
        .sync_generation()
        .map_err(|error| ResolverError::Storage(format!("read header sync generation: {error}")))?;
    let chain = chain_for_network(header_store, network);
    let best_height = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
        .map(|header| header.height.0);
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
    let peer_generation = peer_store
        .sync_generation()
        .map_err(|error| ResolverError::Storage(format!("read peer sync generation: {error}")))?;
    if header_generation != peer_generation {
        return Err(ResolverError::Storage(
            "header and peer sync generations do not match".to_owned(),
        ));
    }
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| ResolverError::Storage(format!("load peer store: {error}")))?;
    let network_policy = network.network();
    retain_allowed_peer_endpoints(&mut peers, &network_policy);
    let now = now_unix_seconds();
    let target_height = assess_peer_target(&peers, &network_policy, now).height;
    Ok(LocalChainCurrentness::new(
        network,
        best_height,
        target_height,
        estimated_tip_height_for_network(network, now),
    ))
}

fn select_live_proof_peers(
    peers: &hns_p2p::PeerManager,
    network: &hns_core::network::Network,
    preferred_count: usize,
    now: u64,
    proof_height: Height,
) -> Vec<SocketAddr> {
    let mut candidates = peers
        .iter()
        .filter(|peer| {
            !peer.is_banned(now)
                && peer.last_height >= proof_height
                && is_allowed_peer_endpoint(network, peer.address)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| right.last_height.cmp(&left.last_height))
            .then_with(|| left.address.cmp(&right.address))
    });
    candidates
        .into_iter()
        .take(preferred_count)
        .map(|peer| peer.address)
        .collect()
}

fn estimated_mainnet_tip_height(now: u64) -> Option<u32> {
    now.checked_sub(MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / MAINNET_TARGET_SPACING_SECONDS)
        .and_then(|height| u32::try_from(height).ok())
}

fn read_sync_status(data_dir: &str, network: NetworkKind) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    let chain = open_initialized_header_chain(&base, network)?;
    let header_generation = chain
        .into_store()
        .sync_generation()
        .map_err(|error| format!("read header sync generation: {error}"))?;
    let chain = open_initialized_header_chain(&base, network)?;
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store: {error}"))?;
    let peer_generation = peer_store
        .sync_generation()
        .map_err(|error| format!("read peer sync generation: {error}"))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    retain_allowed_peer_endpoints(&mut peers, &network.network());
    let best = chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?;
    let now = now_unix_seconds();
    let best_height = best.map(|header| header.height.0);
    let best_peer_height = best_peer_height(&peers);
    let estimated_tip_height = estimated_tip_height_for_network(network, now);
    let network_policy = network.network();
    let generations_match = header_generation == peer_generation;
    let peer_target = if generations_match {
        assess_peer_target(&peers, &network_policy, now)
    } else {
        PeerTargetAssessment {
            height: None,
            peer_groups: 0,
            evidence_expired: false,
            evidence_valid_until_unix: None,
        }
    };
    let currentness = LocalChainCurrentness::new(
        network,
        best_height,
        peer_target.height,
        estimated_tip_height,
    );
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;

    Ok(NativeSyncStatus {
        network,
        status: classify_cached_sync_status(best_height, currentness.target_height),
        attempted: 0,
        successful: 0,
        accepted: 0,
        failed: 0,
        peer_count: peers.len(),
        peer_groups: peers.address_group_count(now),
        best_height,
        best_peer_height,
        estimated_tip_height,
        effective_target_height: currentness.target_height,
        lag_blocks: currentness.lag_blocks,
        freshness: currentness.freshness.as_str(),
        freshness_threshold_blocks: LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
        tree_interval_blocks: canonical_name_tree_interval(canonical_network(network)),
        authoritative_tree_root_height: currentness.authoritative_tree_root_height,
        local_tree_root_height: currentness.local_tree_root_height,
        tree_root_ready: currentness.tree_root_ready,
        blocks_until_authoritative_tree_root: currentness.blocks_until_authoritative_tree_root,
        target_source: peer_target
            .height
            .map(|_| CurrentnessTargetSource::CorroboratedPeers.as_str())
            .unwrap_or_else(|| CurrentnessTargetSource::Unknown.as_str()),
        target_peer_groups: peer_target.peer_groups,
        target_evidence_expired: peer_target.evidence_expired,
        target_evidence_valid_until_unix: peer_target.evidence_valid_until_unix,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted: 0,
        error: (!generations_match)
            .then(|| "header and peer sync generations do not match".to_owned()),
        failures: Vec::new(),
    })
}

fn classify_cached_sync_status(
    best_height: Option<u32>,
    effective_target_height: Option<u32>,
) -> &'static str {
    match (best_height, effective_target_height) {
        (Some(best), Some(target)) if best > 0 && target <= best => "up_to_date",
        (Some(best), Some(target)) if target > best => "syncing",
        (Some(best), None) if best > 0 => "syncing",
        _ => "idle",
    }
}

fn best_synced_header(
    base: &Path,
    network: NetworkKind,
) -> Result<hns_chain::StoredHeader, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = chain_for_network(header_store, network);
    let best = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
        .ok_or(ResolverError::ProofUnavailable)?;
    if best.height.0 == 0 {
        return Err(ResolverError::ProofUnavailable);
    }
    Ok(best)
}

fn clear_resolver_cache_inner(
    data_dir: &str,
    network: NetworkKind,
) -> Result<NativeSyncStatus, String> {
    let base = network_base_path(data_dir, network);
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;
    clear_resource_cache_at_base(&base)?;

    let mut status = read_sync_status(data_dir, network)
        .unwrap_or_else(|_| NativeSyncStatus::empty_for(network));
    status.status = "cleared";
    status.resource_cache_entries = 0;
    status.resource_cache_bytes = 0;
    status.resource_cache_evicted = 0;
    Ok(status)
}

fn clear_resource_cache_at_base(base: &Path) -> Result<(), String> {
    let path = base.join("resources.sqlite");
    if path.exists() {
        let provider = SqliteResourceValueProvider::open(path)
            .map_err(|error| format!("open resource cache: {error}"))?;
        provider
            .clear()
            .map_err(|error| format!("clear resource cache: {error}"))?;
    }
    Ok(())
}

fn enforce_resource_cache_limit(base: &Path, max_bytes: usize) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    provider
        .enforce_value_byte_limit(max_bytes)
        .map_err(|error| format!("enforce resource cache limit: {error}"))
}

fn prune_resource_cache_to_best_chain(
    base: &Path,
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let valid_anchors = recent_canonical_resource_anchors(chain)?;
    provider
        .prune_invalid_anchors(&valid_anchors, true)
        .map_err(|error| format!("prune resource cache anchors: {error}"))
}

fn recent_canonical_resource_anchors(
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<Vec<ResourceValueAnchor>, String> {
    let Some(best) = chain
        .best_header()
        .map_err(|error| format!("read best header for resource cache anchors: {error}"))?
    else {
        return Ok(Vec::new());
    };
    if best.height.0 == 0 {
        return Ok(Vec::new());
    }

    let first_height = best
        .height
        .0
        .saturating_sub(RESOURCE_PROOF_CACHE_CANONICAL_WINDOW)
        .max(1);
    let mut anchors = Vec::new();
    for height in first_height..=best.height.0 {
        if let Some(header) = chain.canonical_header(Height(height)) {
            anchors.push(ResourceValueAnchor {
                tree_root: header.header.tree_root,
                height: header.height,
            });
        }
    }
    Ok(anchors)
}

fn resource_cache_stats(base: &Path) -> Result<(usize, usize), String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok((0, 0));
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let stats = provider
        .stats()
        .map_err(|error| format!("read resource cache stats: {error}"))?;
    Ok((stats.entries, stats.value_bytes))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    pub network: NetworkKind,
    pub status: &'static str,
    pub attempted: usize,
    pub successful: usize,
    pub accepted: usize,
    pub failed: usize,
    pub peer_count: usize,
    pub peer_groups: usize,
    pub best_height: Option<u32>,
    pub best_peer_height: Option<u32>,
    pub estimated_tip_height: Option<u32>,
    pub effective_target_height: Option<u32>,
    pub lag_blocks: Option<u32>,
    pub freshness: &'static str,
    pub freshness_threshold_blocks: u32,
    pub tree_interval_blocks: u32,
    pub authoritative_tree_root_height: Option<u32>,
    pub local_tree_root_height: Option<u32>,
    pub tree_root_ready: Option<bool>,
    pub blocks_until_authoritative_tree_root: Option<u32>,
    pub target_source: &'static str,
    pub target_peer_groups: usize,
    pub target_evidence_expired: bool,
    pub target_evidence_valid_until_unix: Option<u64>,
    pub resource_cache_entries: usize,
    pub resource_cache_bytes: usize,
    pub resource_cache_evicted: usize,
    pub error: Option<String>,
    pub failures: Vec<NativePeerFailure>,
}

pub type NativeSyncStatus = SyncStatus;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePeerFailure {
    pub address: String,
    pub stage: &'static str,
    pub error: String,
}

impl SyncStatus {
    fn empty_for(network: NetworkKind) -> Self {
        Self {
            network,
            status: "idle",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            effective_target_height: None,
            lag_blocks: None,
            freshness: ChainFreshness::Unknown.as_str(),
            freshness_threshold_blocks: LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
            tree_interval_blocks: canonical_name_tree_interval(canonical_network(network)),
            authoritative_tree_root_height: None,
            local_tree_root_height: None,
            tree_root_ready: None,
            blocks_until_authoritative_tree_root: None,
            target_source: CurrentnessTargetSource::Unknown.as_str(),
            target_peer_groups: 0,
            target_evidence_expired: false,
            target_evidence_valid_until_unix: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: None,
            failures: Vec::new(),
        }
    }

    pub fn error(error: String) -> Self {
        Self::error_for(NetworkKind::Mainnet, error)
    }

    pub fn error_for(network: NetworkKind, error: String) -> Self {
        Self {
            network,
            status: "error",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            effective_target_height: None,
            lag_blocks: None,
            freshness: ChainFreshness::Unknown.as_str(),
            freshness_threshold_blocks: LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
            tree_interval_blocks: canonical_name_tree_interval(canonical_network(network)),
            authoritative_tree_root_height: None,
            local_tree_root_height: None,
            tree_root_ready: None,
            blocks_until_authoritative_tree_root: None,
            target_source: CurrentnessTargetSource::Unknown.as_str(),
            target_peer_groups: 0,
            target_evidence_expired: false,
            target_evidence_valid_until_unix: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some(error),
            failures: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let best_height = self
            .best_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let best_peer_height = self
            .best_peer_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let estimated_tip_height = self
            .estimated_tip_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let effective_target_height = self
            .effective_target_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let lag_blocks = self
            .lag_blocks
            .map(|lag| lag.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let authoritative_tree_root_height = self
            .authoritative_tree_root_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let local_tree_root_height = self
            .local_tree_root_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let tree_root_ready = json_bool_or_null(self.tree_root_ready);
        let blocks_until_authoritative_tree_root = self
            .blocks_until_authoritative_tree_root
            .map(|blocks| blocks.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let target_evidence_valid_until_unix = self
            .target_evidence_valid_until_unix
            .map(|deadline| deadline.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let error = self
            .error
            .as_ref()
            .map(|error| format!(r#""{}""#, json_escape(error)))
            .unwrap_or_else(|| "null".to_owned());
        let failures = self
            .failures
            .iter()
            .map(NativePeerFailure::to_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"{{"network":"{}","status":"{}","attempted":{},"successful":{},"accepted":{},"failed":{},"peerCount":{},"peerGroups":{},"bestHeight":{},"bestPeerHeight":{},"estimatedTipHeight":{},"effectiveTargetHeight":{},"lagBlocks":{},"freshness":"{}","freshnessThresholdBlocks":{},"treeIntervalBlocks":{},"authoritativeTreeRootHeight":{},"localTreeRootHeight":{},"treeRootReady":{},"blocksUntilAuthoritativeTreeRoot":{},"targetSource":"{}","targetPeerGroups":{},"targetEvidenceExpired":{},"targetEvidenceValidUntilUnix":{},"resourceCacheEntries":{},"resourceCacheBytes":{},"resourceCacheEvicted":{},"error":{},"failures":[{}]}}"#,
            self.network.as_str(),
            self.status,
            self.attempted,
            self.successful,
            self.accepted,
            self.failed,
            self.peer_count,
            self.peer_groups,
            best_height,
            best_peer_height,
            estimated_tip_height,
            effective_target_height,
            lag_blocks,
            self.freshness,
            self.freshness_threshold_blocks,
            self.tree_interval_blocks,
            authoritative_tree_root_height,
            local_tree_root_height,
            tree_root_ready,
            blocks_until_authoritative_tree_root,
            self.target_source,
            self.target_peer_groups,
            self.target_evidence_expired,
            target_evidence_valid_until_unix,
            self.resource_cache_entries,
            self.resource_cache_bytes,
            self.resource_cache_evicted,
            error,
            failures,
        )
    }
}

impl NativePeerFailure {
    fn to_json(&self) -> String {
        format!(
            r#"{{"address":"{}","stage":"{}","error":"{}"}}"#,
            json_escape(&self.address),
            self.stage,
            json_escape(&self.error),
        )
    }
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            character if character.is_control() => {
                format!("\\u{:04x}", character as u32).chars().collect()
            }
            character => vec![character],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::{HeaderStore, StoredHeader};
    use hns_core::dns::DnsName;
    use hns_core::hash::blake2b_256;
    use hns_core::pow::Chainwork;
    use hns_core::resource::ResourceError;
    use hns_core::{Hash, Height, NameHash};
    use hns_loopback_proxy::{ProxyConfig, ProxyInstanceId, ProxySessionId, RunningProxy};
    use hns_p2p::{Packet, PeerManager, ProofPacket};
    use hns_resolver::{HnsResourceValueProvider, VerifiedResourceValue};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    fn test_header_state_lease(coordination: &Arc<RuntimeCoordination>) -> HeaderStateLease {
        HeaderStateLease {
            coordination: Arc::clone(coordination),
            identity: read_header_sync_storage_identity(&coordination.header_state_base).unwrap(),
        }
    }

    struct FailingCanonicalTransportReadinessProbe;

    impl CanonicalTransportReadinessProbe for FailingCanonicalTransportReadinessProbe {
        fn verify(&self, _plan: &CanonicalTransportPlan) -> std::io::Result<()> {
            Err(std::io::Error::new(
                ErrorKind::AddrNotAvailable,
                "test transport readiness failure",
            ))
        }
    }

    struct OriginMapResolver {
        responses: HashMap<ResolutionRequest, ResolutionAnswer>,
        requests: Arc<Mutex<Vec<ResolutionRequest>>>,
    }

    impl Resolver for OriginMapResolver {
        fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .get(request)
                .cloned()
                .ok_or(ResolverError::UnsupportedBackend)
        }
    }

    #[test]
    fn version_is_stable() {
        assert_eq!(
            core_version(),
            concat!("hns-dane-browser-rust-core/", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn chromium_dane_pac_routes_secure_dns_origins_without_local_targets() {
        assert_eq!(
            chromium_dane_pac_script(0),
            Err(ChromiumPacError::ZeroProxyPort)
        );
        let script = chromium_dane_pac_script(43123).unwrap();

        assert!(script.contains("schema 3"));
        assert!(script.contains("hnsRequiresNativeGateway(url, host)"));
        assert!(script.contains(r#"/^(http|https|ws|wss):/i"#));
        assert!(!script.contains("HNS_ICANN_TLDS"));
        assert!(!script.contains(r#""com":1"#));
        assert!(script.contains(r#""localhost":1"#));
        assert!(script.contains(r#""PROXY 127.0.0.1:43123""#));
        assert!(!script.contains("dnsResolve"));
        assert!(!script.contains("SOCKS"));
    }

    #[test]
    fn browser_runtime_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BrowserRuntime>();
        assert_send_sync::<BrowserProxy>();
        assert_send_sync::<BrowserProxyStatus>();
        assert_send_sync::<RuntimeProxyBackend>();
        assert_send_sync::<NoopBrowserProxyStatusObserver>();
        let data_dir = temp_dir_path("runtime-proxy-debug");
        assert_eq!(
            format!(
                "{:?}",
                BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest,))
                    .unwrap()
                    .proxy_backend()
            ),
            "RuntimeProxyBackend(<redacted runtime>)"
        );
        cleanup_dir(&data_dir);
    }

    fn trusted_proxy_metadata(headers: &[(&str, &str)]) -> InternalResponseMetadata {
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        hns_loopback_proxy::sanitize_response_headers(&headers)
            .unwrap()
            .metadata()
            .clone()
    }

    #[test]
    fn browser_proxy_status_parses_only_known_trusted_metadata_values() {
        let metadata = trusted_proxy_metadata(&[
            (HNS_TLS_POLICY_HEADER, " DaNe "),
            (
                HNS_RESOLVER_POLICY_HEADER,
                " USER-CONFIGURED-RECURSIVE-HNS-DOH ",
            ),
            (HNS_SECURITY_PATH_HEADER, " Dane-Authoritative-DoH "),
            (HNS_RESOLUTION_TRACE_HEADER, r#"{"mode":"strict"}"#),
            ("X-HNS-Future-Metadata", "must-not-surface"),
        ]);
        let status = browser_proxy_status_from_metadata(
            7,
            "welcome",
            204,
            true,
            BrowserProxyObservationKind::OriginResponse,
            None,
            None,
            &metadata,
            None,
            CanonicalStatusAvailability::Pending,
        );

        assert_eq!(
            status,
            BrowserProxyStatus {
                generation: 7,
                host: "welcome".to_owned(),
                status_code: 204,
                likely_main_frame: true,
                observation_kind: BrowserProxyObservationKind::OriginResponse,
                port: None,
                correlation_epoch: None,
                tls_policy: Some(BrowserProxyTlsPolicy::Dane),
                resolver_policy: Some(BrowserProxyResolverPolicy::UserConfiguredRecursiveHnsDoh,),
                security_path: Some(BrowserProxySecurityPath::DaneAuthoritativeDoh),
                resolution_trace_json: Some(r#"{"mode":"strict"}"#.to_owned()),
                canonical_observation: None,
                canonical_status: CanonicalStatusAvailability::Pending,
            }
        );
        assert_eq!(metadata.get("X-HNS-Future-Metadata"), None);

        let unknown = trusted_proxy_metadata(&[
            (HNS_TLS_POLICY_HEADER, "origin-defined"),
            (HNS_RESOLVER_POLICY_HEADER, "future-policy"),
            (HNS_SECURITY_PATH_HEADER, "future-path"),
        ]);
        let status = browser_proxy_status_from_metadata(
            8,
            "welcome",
            200,
            false,
            BrowserProxyObservationKind::OriginResponse,
            None,
            None,
            &unknown,
            None,
            CanonicalStatusAvailability::Pending,
        );
        assert_eq!(status.tls_policy, None);
        assert_eq!(status.resolver_policy, None);
        assert_eq!(status.security_path, None);
        assert_eq!(
            parse_browser_proxy_tls_policy(Some(" WebPKI-Fallback ")),
            Some(BrowserProxyTlsPolicy::WebPkiFallback)
        );
    }

    #[test]
    fn browser_proxy_security_path_parser_covers_the_native_status_vocabulary() {
        for (value, expected) in [
            (
                "dane-authoritative-doh",
                BrowserProxySecurityPath::DaneAuthoritativeDoh,
            ),
            (
                "dane-authoritative-dns53",
                BrowserProxySecurityPath::DaneAuthoritativeDns53,
            ),
            (
                "dane-p2p-dns-relay",
                BrowserProxySecurityPath::DaneP2pDnsRelay,
            ),
            (
                "dane-user-configured-recursive-hns-doh",
                BrowserProxySecurityPath::DaneUserConfiguredRecursiveHnsDoh,
            ),
            ("stateless-dane", BrowserProxySecurityPath::StatelessDane),
            ("dane-icann-doh", BrowserProxySecurityPath::DaneIcannDoh),
            (
                "hns-authoritative-doh",
                BrowserProxySecurityPath::HnsAuthoritativeDoh,
            ),
            (
                "hns-authoritative-dns53",
                BrowserProxySecurityPath::HnsAuthoritativeDns53,
            ),
            (
                "hns-p2p-dns-relay",
                BrowserProxySecurityPath::HnsP2pDnsRelay,
            ),
            (
                "hns-user-configured-recursive-hns-doh",
                BrowserProxySecurityPath::HnsUserConfiguredRecursiveHnsDoh,
            ),
        ] {
            assert_eq!(
                parse_browser_proxy_security_path(Some(value)),
                Some(expected)
            );
        }
    }

    #[test]
    fn browser_proxy_resolution_trace_is_preserved_only_within_the_explicit_bound() {
        let maximum = "x".repeat(MAX_BROWSER_PROXY_RESOLUTION_TRACE_JSON_BYTES);
        assert_eq!(
            bounded_browser_proxy_resolution_trace(Some(&maximum)),
            Some(maximum.clone())
        );

        let oversized = format!("{maximum}x");
        assert_eq!(
            bounded_browser_proxy_resolution_trace(Some(&oversized)),
            None
        );
        assert_eq!(bounded_browser_proxy_resolution_trace(None), None);
    }

    #[test]
    fn browser_proxy_status_debug_redacts_resolution_trace_contents() {
        let secret = "https://welcome/private?token=secret";
        let status = BrowserProxyStatus {
            generation: 4,
            host: "welcome".to_owned(),
            status_code: 200,
            likely_main_frame: true,
            observation_kind: BrowserProxyObservationKind::OriginResponse,
            port: None,
            correlation_epoch: None,
            tls_policy: Some(BrowserProxyTlsPolicy::Dane),
            resolver_policy: None,
            security_path: Some(BrowserProxySecurityPath::DaneAuthoritativeDoh),
            resolution_trace_json: Some(format!(r#"{{"url":"{secret}"}}"#)),
            canonical_observation: None,
            canonical_status: CanonicalStatusAvailability::Pending,
        };

        let debug = format!("{status:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains("token=secret"));
        assert!(debug.contains("resolution_trace_present: true"));
        assert!(debug.contains("resolution_trace_bytes: Some("));
    }

    #[test]
    fn browser_runtime_starts_fresh_authenticated_proxy_generations() {
        let data_dir = temp_dir_path("browser-runtime-proxy-session");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        let first = runtime.start_proxy("welcome").unwrap();
        assert_ne!(first.port(), 0);
        assert_eq!(first.generation(), 1);
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .runtime
                .lock()
                .unwrap()
                .snapshot()
                .session_bytes(),
            *runtime.inner.proxy_session.as_bytes()
        );
        assert!(first.matches_instance(first.session_id(), 1));
        assert!(!first.matches_instance("stale-session", 1));
        assert!(!first.matches_instance(first.session_id(), 2));
        assert_eq!(first.authorization_username(), "hns-browser");
        assert!(!first.authorization_realm().is_empty());
        assert!(!first.authorization_password().is_empty());
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.session_id()));
        assert!(!debug.contains(first.authorization_realm()));
        assert!(!debug.contains(first.authorization_password()));

        let mut unauthenticated = TcpStream::connect((Ipv4Addr::LOCALHOST, first.port())).unwrap();
        unauthenticated
            .write_all(b"GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        unauthenticated.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));

        let second = runtime.start_proxy("welcome").unwrap();
        assert_eq!(second.generation(), 2);
        assert_eq!(first.session_id(), second.session_id());
        assert_ne!(first.port(), second.port());
        assert_ne!(
            first.authorization_password(),
            second.authorization_password()
        );
        first.stop();
        second.stop();
        assert!(first.is_stopped());
        assert!(second.is_stopped());
        cleanup_dir(&data_dir);
    }

    #[test]
    fn replacement_proxy_revokes_old_binding_before_new_activation() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("replacement-proxy-binding");
        let authority = &runtime.inner.canonical_authority;
        let first = runtime.start_proxy("welcome").unwrap();
        let old_stamp = authority.admit(first.generation()).unwrap();
        assert!(authority.admits(old_stamp));
        let old_status = runtime
            .inner
            .canonical_statuses
            .insert_with_epoch(
                authority,
                old_stamp,
                CanonicalStatusAvailability::Pending,
                MaintenanceEpoch(runtime.security_maintenance_epoch().unwrap()),
            )
            .unwrap();

        let second = runtime.start_proxy("welcome").unwrap();
        assert_eq!(second.generation(), first.generation() + 1);
        assert_eq!(
            authority.active_proxy_generation.load(Ordering::Acquire),
            second.generation()
        );
        assert!(!authority.admits(old_stamp));
        assert!(authority.admit(first.generation()).is_err());

        let new_stamp = authority.admit(second.generation()).unwrap();
        assert!(authority.admits(new_stamp));
        let new_epoch = MaintenanceEpoch(runtime.security_maintenance_epoch().unwrap());
        let new_status = runtime
            .inner
            .canonical_statuses
            .insert_with_epoch(
                authority,
                new_stamp,
                CanonicalStatusAvailability::Pending,
                new_epoch,
            )
            .unwrap();
        first.stop();
        assert_eq!(
            authority.active_proxy_generation.load(Ordering::Acquire),
            second.generation()
        );
        assert!(authority.admits(new_stamp));
        assert!(
            runtime
                .inner
                .canonical_statuses
                .take(old_status, authority)
                .is_none()
        );
        assert!(matches!(
            runtime.inner.canonical_statuses.take(new_status, authority),
            Some(CanonicalStatusObservation {
                maintenance_epoch,
                status: CanonicalStatusAvailability::Pending,
                ..
            }) if maintenance_epoch == new_epoch
        ));

        second.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn fresh_proxy_listener_stays_non_admitting_until_factual_readiness_arrives() {
        let data_dir = temp_dir_path("fresh-proxy-canonical-readiness");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let proxy = runtime.start_proxy("welcome").unwrap();
        let authority = &runtime.inner.canonical_authority;

        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::HeaderSyncing
        );
        assert_eq!(
            authority.active_proxy_generation.load(Ordering::Acquire),
            proxy.generation()
        );
        assert!(authority.admit(proxy.generation()).is_err());
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Degraded
        );

        let base = data_dir.join("hns-regtest");
        SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Regtest,
            Hash::new([45; 32]),
        );
        let stamp = authority.admit(proxy.generation()).unwrap();
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Active
        );
        assert!(authority.admits(stamp));

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn status_context_retains_each_requests_exact_admission_event() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("exact-admission-status-context");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let authority = &runtime.inner.canonical_authority;

        let first = authority.admit(proxy.generation()).unwrap();
        let first_admitted_event = first.runtime.event_sequence();
        let second = authority.admit(proxy.generation()).unwrap();
        assert!(second.runtime.event_sequence() > first_admitted_event);

        let (first_snapshot, first_policy) = authority.status_context(first).unwrap();
        let (second_snapshot, second_policy) = authority.status_context(second).unwrap();
        assert_eq!(first_snapshot.event_sequence(), first_admitted_event);
        assert_eq!(
            second_snapshot.event_sequence(),
            second.runtime.event_sequence()
        );
        assert_ne!(
            first_snapshot.event_sequence(),
            second_snapshot.event_sequence()
        );
        assert_eq!(first_policy, second_policy);

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn unavailable_policy_transport_degrades_authority_and_blocks_admission() {
        let data_dir = temp_dir_path("canonical-transport-readiness-failure");
        let base = data_dir.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let anchor_height = store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Mainnet,
            Hash::new([46; 32]),
        );
        SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        store_peer_height(&base, anchor_height.0);
        let proxy_session = ProxySessionId::generate().unwrap();
        let session = CanonicalRuntimeSessionId::new(*proxy_session.as_bytes()).unwrap();
        let policy = canonical_policy_snapshot(&RuntimePolicy::compatibility(), 1).unwrap();
        let authority = CanonicalAuthority::new_with_transport_readiness(
            session,
            policy,
            base,
            NetworkKind::Mainnet,
            Arc::new(FailingCanonicalTransportReadinessProbe),
        )
        .unwrap();

        authority.prepare_proxy(1).unwrap();
        authority.activate_proxy(1).unwrap();
        assert!(authority.admit(1).is_err());
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Degraded
        );
        assert_eq!(authority.active_proxy_generation.load(Ordering::Acquire), 1);
        assert!(authority.admit(1).is_err());

        cleanup_dir(&data_dir);
    }

    #[test]
    fn cancelled_proxy_preparation_never_publishes_a_generation_binding() {
        let data_dir = temp_dir_path("cancelled-proxy-preparation");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let authority = &runtime.inner.canonical_authority;

        authority.prepare_proxy(1).unwrap();
        assert_eq!(
            authority.prepared_proxy_generation.load(Ordering::Acquire),
            1
        );
        assert_eq!(authority.active_proxy_generation.load(Ordering::Acquire), 0);
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::HeaderSyncing
        );
        authority.cancel_prepared_proxy(1);
        assert_eq!(
            authority.prepared_proxy_generation.load(Ordering::Acquire),
            0
        );
        assert_eq!(authority.active_proxy_generation.load(Ordering::Acquire), 0);
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Degraded
        );
        assert!(authority.admit(1).is_err());

        cleanup_dir(&data_dir);
    }

    #[test]
    fn superseded_proxy_preparation_cannot_activate_or_cancel_the_newer_generation() {
        let data_dir = temp_dir_path("superseded-proxy-preparation");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let authority = &runtime.inner.canonical_authority;

        authority.prepare_proxy(1).unwrap();
        authority.prepare_proxy(2).unwrap();
        assert_eq!(
            authority.prepared_proxy_generation.load(Ordering::Acquire),
            2
        );
        authority.cancel_prepared_proxy(1);
        assert_eq!(
            authority.prepared_proxy_generation.load(Ordering::Acquire),
            2
        );
        assert!(authority.activate_proxy(1).is_err());
        authority.activate_proxy(2).unwrap();
        assert_eq!(
            authority.prepared_proxy_generation.load(Ordering::Acquire),
            0
        );
        assert_eq!(authority.active_proxy_generation.load(Ordering::Acquire), 2);

        authority.revoke_proxy(2);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn stale_readiness_invalidates_old_work_and_recovers_only_with_a_new_stamp() {
        let (data_dir, runtime, anchor_height) =
            runtime_with_current_mainnet_authority("stale-canonical-readiness");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let authority = &runtime.inner.canonical_authority;
        let old_stamp = authority.admit(proxy.generation()).unwrap();
        assert!(authority.admits(old_stamp));

        let base = data_dir.join("hns");
        store_peer_height(&base, 37);
        assert!(!authority.admits(old_stamp));
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Degraded
        );
        assert_eq!(
            authority.active_proxy_generation.load(Ordering::Acquire),
            proxy.generation()
        );

        store_peer_height(&base, anchor_height.0);
        let new_stamp = authority.admit(proxy.generation()).unwrap();
        assert!(!authority.admits(old_stamp));
        assert!(authority.admits(new_stamp));

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn canonical_publication_permit_rechecks_after_backend_return() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("canonical-publication-recheck");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let response = runtime
            .proxy_backend()
            .execute(proxy_request(80, "http"), &ProxyCancellationToken::new())
            .unwrap();

        assert_eq!(
            runtime
                .set_policy(RuntimePolicy {
                    resolution_mode: ResolutionMode::Strict,
                    ..RuntimePolicy::compatibility()
                })
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .policy_snapshot()
                .unwrap()
                .generation(),
            2
        );
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .prepared_proxy_generation
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .active_proxy_generation
                .load(Ordering::Acquire),
            0
        );
        let mut published = Vec::new();
        assert!(
            response
                .publication_permit
                .publish(|| published.write_all(b"HTTP/1.1 200 OK\r\n\r\n"))
                .is_err()
        );
        assert!(published.is_empty());

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn connect_stream_cannot_touch_origin_before_connect_200_publication() {
        use std::sync::atomic::AtomicUsize;

        struct CountingReader(Arc<AtomicUsize>);

        impl Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                if let Some(first) = buffer.first_mut() {
                    *first = 0x41;
                    return Ok(1);
                }
                Ok(0)
            }
        }

        struct CountingWriter(Arc<AtomicUsize>);

        impl Write for CountingWriter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        let data_dir = temp_dir_path("connect-pre-publication-guard");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let epoch = MaintenanceEpoch(runtime.security_maintenance_epoch().unwrap());
        let signal = Arc::new(AtomicBool::new(false));
        let read_calls = Arc::new(AtomicUsize::new(0));
        let write_calls = Arc::new(AtomicUsize::new(0));
        let mut reader = MaintenanceBoundConnectReader {
            inner: Box::new(CountingReader(Arc::clone(&read_calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: Arc::clone(&signal),
        };
        let mut writer = MaintenanceBoundConnectWriter {
            inner: Box::new(CountingWriter(Arc::clone(&write_calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: Arc::clone(&signal),
        };

        assert_eq!(
            reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.write(b"blocked").unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.flush().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(read_calls.load(Ordering::Acquire), 0);
        assert_eq!(write_calls.load(Ordering::Acquire), 0);

        signal.store(true, Ordering::Release);
        assert_eq!(reader.read(&mut [0_u8; 1]).unwrap(), 1);
        assert_eq!(writer.write(b"published").unwrap(), 9);
        writer.flush().unwrap();
        assert_eq!(read_calls.load(Ordering::Acquire), 1);
        assert_eq!(write_calls.load(Ordering::Acquire), 2);
        cleanup_dir(&data_dir);
    }

    #[test]
    // The write guard is intentionally held for its exclusion semantics; the
    // epoch mutation itself is atomic inside `begin_maintenance`.
    #[allow(clippy::readonly_write_lock)]
    fn header_maintenance_epoch_revokes_both_connect_stream_halves() {
        use std::sync::atomic::AtomicUsize;

        struct CountingReader(Arc<AtomicUsize>);

        impl Read for CountingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(0)
            }
        }

        struct CountingWriter(Arc<AtomicUsize>);

        impl Write for CountingWriter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let data_dir = temp_dir_path("connect-maintenance-revocation");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let epoch = MaintenanceEpoch(runtime.security_maintenance_epoch().unwrap());
        let signal = Arc::new(AtomicBool::new(true));
        let read_calls = Arc::new(AtomicUsize::new(0));
        let write_calls = Arc::new(AtomicUsize::new(0));
        let mut reader = MaintenanceBoundConnectReader {
            inner: Box::new(CountingReader(Arc::clone(&read_calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: Arc::clone(&signal),
        };
        let mut writer = MaintenanceBoundConnectWriter {
            inner: Box::new(CountingWriter(Arc::clone(&write_calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: signal,
        };

        assert_eq!(reader.read(&mut [0_u8; 1]).unwrap(), 0);
        assert_eq!(writer.write(b"before").unwrap(), 6);
        {
            let maintenance = runtime.inner.coordination.maintenance.write().unwrap();
            runtime
                .inner
                .coordination
                .begin_maintenance(&maintenance)
                .unwrap();
        }
        assert_ne!(runtime.security_maintenance_epoch(), Some(epoch.0));
        assert_eq!(
            reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.write(b"after").unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.flush().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(read_calls.load(Ordering::Acquire), 1);
        assert_eq!(write_calls.load(Ordering::Acquire), 1);

        cleanup_dir(&data_dir);
    }

    #[test]
    fn active_header_maintenance_never_blocks_connect_io_guards() {
        use std::sync::atomic::AtomicUsize;

        struct ProbeReader(Arc<AtomicUsize>);

        impl Read for ProbeReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(0)
            }
        }

        struct ProbeWriter(Arc<AtomicUsize>);

        impl Write for ProbeWriter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        let data_dir = temp_dir_path("connect-active-maintenance");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let epoch = MaintenanceEpoch(runtime.security_maintenance_epoch().unwrap());
        let signal = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut reader = MaintenanceBoundConnectReader {
            inner: Box::new(ProbeReader(Arc::clone(&calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: Arc::clone(&signal),
        };
        let mut writer = MaintenanceBoundConnectWriter {
            inner: Box::new(ProbeWriter(Arc::clone(&calls))),
            coordination: Arc::clone(&runtime.inner.coordination),
            maintenance_epoch: epoch,
            publication_signal: signal,
        };
        let maintenance = runtime.inner.coordination.maintenance.write().unwrap();
        let started = Instant::now();

        assert_eq!(
            reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.write(b"blocked").unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            writer.flush().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert!(started.elapsed() < Duration::from_millis(50));
        assert_eq!(calls.load(Ordering::Acquire), 0);

        drop(maintenance);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn passthrough_wrappers_do_not_probe_readiness_per_chunk() {
        use std::sync::atomic::AtomicUsize;

        struct CountingReadinessProbe(Arc<AtomicUsize>);

        impl CanonicalTransportReadinessProbe for CountingReadinessProbe {
            fn verify(&self, _plan: &CanonicalTransportPlan) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        const TRANSFER_BYTES: usize = 4 * 1024 * 1024;
        const CHUNK_BYTES: usize = 16 * 1024;

        let data_dir = temp_dir_path("connect-readiness-probe-bounds");
        let base = data_dir.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let anchor_height = store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Mainnet,
            Hash::new([0x74; 32]),
        );
        SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        store_peer_height(&base, anchor_height.0);
        let coordination = runtime_coordination(&base, NetworkKind::Mainnet).unwrap();
        let proxy_session = ProxySessionId::generate().unwrap();
        let session = CanonicalRuntimeSessionId::new(*proxy_session.as_bytes()).unwrap();
        let policy = canonical_policy_snapshot(&RuntimePolicy::compatibility(), 1).unwrap();
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(
            CanonicalAuthority::new_with_transport_readiness(
                session,
                policy,
                base.clone(),
                NetworkKind::Mainnet,
                Arc::new(CountingReadinessProbe(Arc::clone(&probe_calls))),
            )
            .unwrap(),
        );
        authority.prepare_proxy(1).unwrap();
        authority.activate_proxy(1).unwrap();
        let stamp = authority.admit(1).unwrap();
        let lease = Arc::new(AuthorityPassthroughLease::new(
            Arc::clone(&authority),
            stamp,
            test_header_state_lease(&coordination),
        ));
        // Make the periodic deadline deterministic for the throughput portion.
        lease
            .next_readiness_check_ms
            .store(u64::MAX, Ordering::Release);
        let baseline = probe_calls.load(Ordering::Acquire);
        let mut reader = AuthorityBoundPassthroughReader {
            inner: Box::new(std::io::Cursor::new(vec![0x75; TRANSFER_BYTES])),
            lease: Arc::clone(&lease),
        };
        let mut writer = AuthorityBoundPassthroughWriter {
            inner: Box::new(std::io::sink()),
            lease: Arc::clone(&lease),
        };
        let mut buffer = [0_u8; CHUNK_BYTES];
        let mut read = 0;
        while read < TRANSFER_BYTES {
            read += reader.read(&mut buffer).unwrap();
        }
        for _ in 0..(TRANSFER_BYTES / CHUNK_BYTES) {
            writer.write_all(&buffer).unwrap();
        }
        writer.flush().unwrap();

        assert_eq!(read, TRANSFER_BYTES);
        assert_eq!(probe_calls.load(Ordering::Acquire), baseline);

        lease.next_readiness_check_ms.store(0, Ordering::Release);
        assert_eq!(reader.read(&mut buffer).unwrap(), 0);
        assert_eq!(probe_calls.load(Ordering::Acquire), baseline + 1);

        authority.revoke_proxy(1);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn webpki_endpoint_retry_stops_before_dial_when_authority_is_revoked() {
        use std::sync::atomic::AtomicUsize;

        struct RevokeBeforeSecondDialProbe {
            calls: Arc<AtomicUsize>,
        }

        impl CanonicalTransportReadinessProbe for RevokeBeforeSecondDialProbe {
            fn verify(&self, _plan: &CanonicalTransportPlan) -> std::io::Result<()> {
                let call = self.calls.fetch_add(1, Ordering::AcqRel);
                if call < 3 {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        ErrorKind::ConnectionAborted,
                        "test authority revocation before the second endpoint dial",
                    ))
                }
            }
        }

        let data_dir = temp_dir_path("webpki-endpoint-authority-revocation");
        let base = data_dir.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let anchor_height = store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Mainnet,
            Hash::new([0x76; 32]),
        );
        SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        store_peer_height(&base, anchor_height.0);
        let coordination = runtime_coordination(&base, NetworkKind::Mainnet).unwrap();
        let proxy_session = ProxySessionId::generate().unwrap();
        let session = CanonicalRuntimeSessionId::new(*proxy_session.as_bytes()).unwrap();
        let policy = canonical_policy_snapshot(&RuntimePolicy::compatibility(), 1).unwrap();
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(
            CanonicalAuthority::new_with_transport_readiness(
                session,
                policy,
                base.clone(),
                NetworkKind::Mainnet,
                Arc::new(RevokeBeforeSecondDialProbe {
                    calls: Arc::clone(&probe_calls),
                }),
            )
            .unwrap(),
        );
        authority.prepare_proxy(1).unwrap();
        authority.activate_proxy(1).unwrap();
        let stamp = authority.admit(1).unwrap();
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let transport = AuthorityOriginTransport::new(
            TcpHttpTransport::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                hns_transport::TransportLimits::default(),
            ),
            Arc::clone(&authority),
            stamp,
            test_header_state_lease(&coordination),
        );
        let mut unavailable = OriginRequest {
            method: "GET".to_owned(),
            scheme: "https".to_owned(),
            host: "example.com".to_owned(),
            connect_host: Some(Ipv4Addr::new(127, 0, 0, 2).to_string()),
            port: address.port(),
            path_and_query: "/".to_owned(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        unavailable.tls.dnssec_secure = true;
        unavailable.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        unavailable.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        let mut guarded = unavailable.clone();
        guarded.connect_host = Some(Ipv4Addr::LOCALHOST.to_string());

        let failure = transport
            .open_webpki_passthrough_candidates(&[unavailable, guarded])
            .err()
            .expect("revoked authority must stop before the second endpoint dial");

        assert!(matches!(failure, TransportError::Io(_)));
        assert_eq!(probe_calls.load(Ordering::Acquire), 4);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock,
            "the endpoint selected after revocation must never be dialed"
        );
        assert_eq!(
            authority.runtime.lock().unwrap().authority_state(),
            CanonicalAuthorityState::Degraded
        );

        cleanup_dir(&data_dir);
    }

    #[test]
    fn canonical_publication_holds_the_policy_invalidation_lock() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("canonical-publication-lock");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let maintenance = runtime.inner.coordination.maintenance.read().unwrap();
        let maintenance_epoch = runtime
            .inner
            .coordination
            .publication_epoch(&maintenance)
            .unwrap();
        let storage_identity = test_header_state_lease(&runtime.inner.coordination).identity;
        let permit = canonical_proxy_publication_permit(
            &runtime.inner.canonical_authority,
            &runtime.inner.coordination,
            maintenance_epoch,
            storage_identity,
            stamp,
        );
        drop(maintenance);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let publisher = thread::spawn(move || {
            permit
                .publish(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    Ok(())
                })
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let policy_runtime = runtime.clone();
        let (changed_tx, changed_rx) = std::sync::mpsc::channel();
        let policy_change = thread::spawn(move || {
            let result = policy_runtime.set_policy(RuntimePolicy {
                experimental_p2p_dns_relay: true,
                ..RuntimePolicy::compatibility()
            });
            changed_tx.send(result).unwrap();
        });
        assert!(changed_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        publisher.join().unwrap();
        assert_eq!(
            changed_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            1
        );
        policy_change.join().unwrap();

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn staged_origin_body_is_not_published_after_readiness_turns_stale() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("staged-origin-stale");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = listener.local_addr().unwrap().port();
        let stale_base = data_dir.join("hns");
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET /download HTTP/1.1\r\n"));
            store_peer_height(&stale_base, 37);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsecret-bytes",
                )
                .unwrap();
        });
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let transport = AuthorityOriginTransport::new(
            runtime.inner.transport.clone(),
            Arc::clone(&runtime.inner.canonical_authority),
            stamp,
            test_header_state_lease(&runtime.inner.coordination),
        );
        let request = OriginRequest {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "welcome".to_owned(),
            connect_host: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: origin_port,
            path_and_query: "/download".to_owned(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut published = Vec::new();
        assert!(transport.fetch_to_writer(&request, &mut published).is_err());
        assert!(published.is_empty());

        origin.join().unwrap();
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_proxy_rejects_non_hns_scope_before_binding() {
        let data_dir = temp_dir_path("browser-runtime-proxy-scope");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        assert!(matches!(
            runtime.start_proxy("example.com"),
            Err(BrowserProxyError::Scope(HostScopeError::NotHns))
        ));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_owns_network_and_storage_configuration() {
        let data_dir = temp_dir_path("browser-runtime-status");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        let status = runtime.sync_status().unwrap();

        let configuration = runtime.configuration().unwrap();
        assert_eq!(configuration.data_dir(), data_dir);
        assert_eq!(configuration.network(), NetworkKind::Regtest);
        assert_eq!(status.network, NetworkKind::Regtest);
        assert_eq!(status.best_height, Some(0));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn unknown_peer_evidence_publishes_a_fail_closed_generation() {
        let data_dir = temp_dir_path("browser-runtime-staged-sync");
        let runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest).with_sync_options(
                SyncOptions {
                    seed_peers: false,
                    timeout: Duration::from_millis(1),
                    resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
                },
            ),
        )
        .unwrap();

        let initial_epoch = runtime.security_maintenance_epoch();
        let initial_identity = test_header_state_lease(&runtime.inner.coordination).identity;
        let status = runtime.sync_once().unwrap();
        let base = data_dir.join("hns-regtest");
        let header_store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();

        assert_eq!(status.status, "idle");
        assert_eq!(header_store.sync_generation().unwrap(), 1);
        assert_eq!(peer_store.sync_generation().unwrap(), 1);
        assert_ne!(runtime.security_maintenance_epoch(), initial_epoch);
        assert_ne!(
            test_header_state_lease(&runtime.inner.coordination).identity,
            initial_identity
        );
        assert!(
            std::fs::read_dir(&data_dir)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".header-sync-stage-"))
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn mismatched_header_and_peer_generations_fail_readiness_closed() {
        let data_dir = temp_dir_path("browser-runtime-generation-mismatch");
        let base = data_dir.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let height = store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Regtest,
            Hash::new([0x62; 32]),
        );
        store_peer_height(&base, height.0);
        let mut header_store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        header_store.set_sync_generation(2).unwrap();
        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let peers = peer_store.load_manager().unwrap();
        peer_store
            .replace_manager_with_sync_generation(&peers, 1)
            .unwrap();

        assert!(
            local_chain_currentness(&base, NetworkKind::Regtest)
                .unwrap_err()
                .to_string()
                .contains("sync generations do not match")
        );
        let status = read_sync_status(data_dir.to_str().unwrap(), NetworkKind::Regtest).unwrap();
        assert_eq!(status.freshness, "unknown");
        assert_eq!(status.target_source, "unknown");
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("sync generations do not match"))
        );

        let runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest).with_sync_options(
                SyncOptions {
                    seed_peers: false,
                    timeout: Duration::from_millis(1),
                    resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
                },
            ),
        )
        .unwrap();
        let readiness_error = match runtime.inner.canonical_authority.verify_readiness() {
            Ok(_) => panic!("mismatched sync generations must fail readiness"),
            Err(error) => error,
        };
        assert!(
            readiness_error
                .to_string()
                .contains("sync generations do not match")
        );

        runtime.sync_once().unwrap();
        let repaired_header_store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        let repaired_peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        assert_eq!(repaired_header_store.sync_generation().unwrap(), 3);
        assert_eq!(repaired_peer_store.sync_generation().unwrap(), 3);
        let repaired_identity = test_header_state_lease(&runtime.inner.coordination).identity;
        assert_eq!(repaired_identity.header_generation, 3);
        assert_eq!(repaired_identity.peer_generation, 3);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn staged_peer_merge_preserves_concurrent_health_and_staged_height_clear() {
        let address: SocketAddr = "1.1.1.1:12038".parse().unwrap();
        let concurrent: SocketAddr = "8.8.8.8:12038".parse().unwrap();
        let mut baseline = PeerManager::default();
        baseline.record_success(address, Height(100), 100);
        let mut staged = PeerManager::from_states(baseline.iter().cloned());
        staged.clear_observed_height(address);
        staged.record_transient_failure(address);
        let mut live = PeerManager::from_states(baseline.iter().cloned());
        live.record_transport_success(address, 200);
        live.record_transport_success(concurrent, 200);

        let merged =
            merge_staged_peer_manager(&baseline, &staged, &live, &hns_core::network::mainnet());
        let peer = merged.get(address).unwrap();

        assert_eq!(peer.last_height, Height(0));
        assert_eq!(peer.last_height_observed_at, None);
        assert_eq!(peer.last_connected_at, Some(200));
        assert_eq!(peer.score, hns_p2p::TRANSIENT_FAILURE_SCORE);
        assert_eq!(peer.successes, 2);
        assert_eq!(peer.failures, 1);
        assert!(merged.get(concurrent).is_some());
    }

    #[test]
    fn staged_peer_score_merge_composes_rewards_penalties_and_bounds() {
        assert_eq!(
            merge_peer_score(Some(10), 10, 5),
            5,
            "a staged success reward must lower the live score"
        );
        assert_eq!(
            merge_peer_score(Some(10), 15, 7),
            12,
            "concurrent live penalty and staged reward must both survive"
        );
        assert_eq!(
            merge_peer_score(None, 5, 7),
            12,
            "a peer discovered independently by both snapshots composes both deltas"
        );
        assert_eq!(
            merge_peer_score(Some(2), 0, 0),
            0,
            "combined rewards are floored at zero"
        );
        assert_eq!(
            merge_peer_score(Some(i32::MAX - 1), i32::MAX, i32::MAX),
            i32::MAX,
            "combined penalties saturate at the maximum score"
        );
    }

    #[test]
    fn peer_only_sync_does_not_interrupt_response_or_tunnel_head_publication() {
        let exercise_race = |label: &str, boundary: &str, namespace_publication: bool| {
            let (data_dir, runtime, _anchor_height) = runtime_with_current_mainnet_authority(label);
            let initial_epoch = runtime.security_maintenance_epoch();
            let initial_identity = test_header_state_lease(&runtime.inner.coordination).identity;
            let sync_runtime = BrowserRuntime::open(
                RuntimeConfiguration::new(&data_dir, NetworkKind::Mainnet).with_sync_options(
                    SyncOptions {
                        seed_peers: false,
                        timeout: Duration::from_millis(1),
                        resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
                    },
                ),
            )
            .unwrap();
            let stamp = runtime.inner.canonical_authority.admit_direct().unwrap();
            let maintenance = runtime.inner.coordination.maintenance.read().unwrap();
            let epoch = runtime
                .inner
                .coordination
                .publication_epoch(&maintenance)
                .unwrap();
            let storage_identity = test_header_state_lease(&runtime.inner.coordination).identity;
            let permit = if namespace_publication {
                canonical_proxy_publication_permit_with_namespace(
                    &runtime.inner.canonical_authority,
                    &runtime.inner.coordination,
                    epoch,
                    storage_identity,
                    stamp,
                    &runtime.inner.coordination.namespace_bindings,
                    None,
                )
            } else {
                canonical_proxy_publication_permit(
                    &runtime.inner.canonical_authority,
                    &runtime.inner.coordination,
                    epoch,
                    storage_identity,
                    stamp,
                )
            };
            drop(maintenance);

            let stale_permit = permit.clone();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let publisher = thread::spawn(move || {
                permit.publish(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    Ok(())
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

            let (sent, received) = std::sync::mpsc::channel();
            let sync = thread::spawn(move || {
                sent.send(sync_runtime.sync_once()).unwrap();
            });
            assert!(
                received
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .is_ok(),
                "peer-only sync did not finish alongside {boundary} publication"
            );

            release_tx.send(()).unwrap();
            publisher.join().unwrap().unwrap();
            sync.join().unwrap();
            assert_eq!(runtime.security_maintenance_epoch(), initial_epoch);
            assert_eq!(
                test_header_state_lease(&runtime.inner.coordination).identity,
                initial_identity
            );

            let mut current_operation_called = false;
            assert!(
                stale_permit
                    .publish(|| {
                        current_operation_called = true;
                        Ok(())
                    })
                    .is_ok(),
                "peer-only sync invalidated a current {boundary} permit"
            );
            assert!(current_operation_called);
            cleanup_dir(&data_dir);
        };

        exercise_race(
            "runtime-sync-response-publication-exclusion",
            "normal response head",
            false,
        );
        exercise_race(
            "runtime-sync-tunnel-publication-exclusion",
            "tunnel response head",
            true,
        );
    }

    #[test]
    fn sync_repairs_an_updating_token_after_equal_generation_crash() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("runtime-sync-updating-token-repair");
        let baseline =
            read_header_sync_storage_identity(&runtime.inner.coordination.header_state_base)
                .unwrap();
        let initial_epoch = runtime.security_maintenance_epoch();
        let mut interrupted =
            HeaderStateFileLock::exclusive(&runtime.inner.coordination.header_state_lock_path)
                .unwrap();
        interrupted.mark_updating().unwrap();
        drop(interrupted);

        let repair_runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Mainnet).with_sync_options(
                SyncOptions {
                    seed_peers: false,
                    timeout: Duration::from_millis(1),
                    resource_cache_limit_bytes: DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
                },
            ),
        )
        .unwrap();
        let status = repair_runtime.sync_once().unwrap();
        assert_eq!(status.freshness, "current");
        let repaired = test_header_state_lease(&repair_runtime.inner.coordination).identity;
        assert_eq!(repaired.header_generation, baseline.header_generation + 1);
        assert_eq!(repaired.header_generation, repaired.peer_generation);
        assert_eq!(repaired.best_hash, baseline.best_hash);
        assert_ne!(repair_runtime.security_maintenance_epoch(), initial_epoch);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtimes_share_coordination_for_the_same_storage() {
        let data_dir = temp_dir_path("browser-runtime-shared-coordination");
        let first =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let second = BrowserRuntime::open(RuntimeConfiguration::new(
            data_dir.join("."),
            NetworkKind::Regtest,
        ))
        .unwrap();

        assert!(Arc::ptr_eq(
            &first.inner.coordination,
            &second.inner.coordination
        ));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn header_state_token_is_fail_closed_and_lock_admission_is_nonblocking() {
        let data_dir = temp_dir_path("header-state-token-fail-closed");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let lease = test_header_state_lease(&runtime.inner.coordination);
        assert!(
            lease.identity.best_hash.is_some(),
            "the token must be initialized after the genesis header exists"
        );
        assert!(lease.acquire().is_ok());

        let mut publication =
            HeaderStateFileLock::exclusive(&runtime.inner.coordination.header_state_lock_path)
                .unwrap();
        assert!(
            HeaderStateFileLock::try_shared(&runtime.inner.coordination.header_state_lock_path)
                .unwrap()
                .is_none(),
            "request admission must fail immediately while publication is exclusive"
        );
        publication.mark_updating().unwrap();
        drop(publication);

        assert!(
            lease.acquire().is_err(),
            "an interrupted publication token must invalidate prior leases"
        );
        assert!(matches!(
            runtime.acquire_proxy_maintenance(&ProxyCancellationToken::new()),
            Err(ProxyBackendError::Internal)
        ));

        let mut repair =
            HeaderStateFileLock::exclusive(&runtime.inner.coordination.header_state_lock_path)
                .unwrap();
        repair.mark_ready(lease.identity).unwrap();
        drop(repair);
        assert!(lease.acquire().is_ok());
        cleanup_dir(&data_dir);
    }

    #[test]
    fn namespace_binding_store_is_exact_origin_sticky_and_idempotent() {
        let store = NamespaceBindingStore::in_memory(NetworkKind::Mainnet).unwrap();
        let https =
            NamespaceOriginKey::new("HTTPS", "Example.COM.", 443).expect("valid HTTPS origin");
        let alternate_port =
            NamespaceOriginKey::new("https", "example.com", 8443).expect("valid alternate origin");

        assert_eq!(store.get(&https).unwrap(), None);
        assert_eq!(
            store
                .record_success(&https, StoredNamespace::Icann, 1_000)
                .unwrap(),
            StoredNamespaceBinding {
                namespace: StoredNamespace::Icann,
                revision: 1,
            }
        );
        assert_eq!(
            store
                .record_success(&https, StoredNamespace::Icann, 2_000)
                .unwrap(),
            StoredNamespaceBinding {
                namespace: StoredNamespace::Icann,
                revision: 1,
            }
        );
        assert_eq!(
            store.get(&https).unwrap(),
            Some(StoredNamespaceBinding {
                namespace: StoredNamespace::Icann,
                revision: 1,
            })
        );
        assert_eq!(store.get(&alternate_port).unwrap(), None);
        assert!(
            store
                .record_success(&https, StoredNamespace::Hns, 3_000)
                .is_err()
        );
        assert_eq!(
            store.get(&https).unwrap().map(|binding| binding.namespace),
            Some(StoredNamespace::Icann)
        );
    }

    #[test]
    fn page_and_websocket_share_the_same_namespace_binding() {
        let store = NamespaceBindingStore::in_memory(NetworkKind::Mainnet).unwrap();
        let page = OriginQuery::new(
            CanonicalHost::parse("dual.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let websocket = OriginQuery::new(
            CanonicalHost::parse("dual.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Wss,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        assert_ne!(page.scheme(), websocket.scheme());

        let page_binding = namespace_origin_key(&page).unwrap();
        let websocket_binding = namespace_origin_key(&websocket).unwrap();
        assert_eq!(page_binding, websocket_binding);
        store
            .record_success(&page_binding, StoredNamespace::Hns, 1_000)
            .unwrap();
        assert_eq!(
            store
                .get(&websocket_binding)
                .unwrap()
                .map(|binding| binding.namespace),
            Some(StoredNamespace::Hns)
        );

        let cleartext_page = OriginQuery::new(
            CanonicalHost::parse("dual.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let cleartext_websocket = OriginQuery::new(
            CanonicalHost::parse("dual.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Ws,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        assert_eq!(
            namespace_origin_key(&cleartext_page).unwrap(),
            namespace_origin_key(&cleartext_websocket).unwrap()
        );
    }

    #[test]
    fn namespace_binding_survives_reopen_and_is_network_partitioned() {
        let data_dir = temp_dir_path("namespace-binding-reopen");
        std::fs::create_dir_all(&data_dir).unwrap();
        let path = data_dir.join("namespace-bindings.sqlite");
        let origin = NamespaceOriginKey::new("https", "example.com", 443).unwrap();
        {
            let store = NamespaceBindingStore::open(&path, NetworkKind::Mainnet).unwrap();
            store
                .record_success(&origin, StoredNamespace::Icann, 1_000)
                .unwrap();
        }
        let reopened = NamespaceBindingStore::open(&path, NetworkKind::Mainnet).unwrap();
        assert_eq!(
            reopened.get(&origin).unwrap(),
            Some(StoredNamespaceBinding {
                namespace: StoredNamespace::Icann,
                revision: 1,
            })
        );
        let testnet = NamespaceBindingStore::open(&path, NetworkKind::Testnet).unwrap();
        assert_eq!(testnet.get(&origin).unwrap(), None);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_status_remains_available_while_peer_state_is_busy() {
        let data_dir = temp_dir_path("browser-runtime-concurrent-status");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        runtime.sync_status().unwrap();
        let peer_state = Arc::clone(&runtime.inner.coordination.peer_state);
        let peer_state_guard = peer_state.lock().unwrap();
        let call_runtime = runtime.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let call = thread::spawn(move || sender.send(call_runtime.sync_status()).unwrap());

        let status = receiver.recv_timeout(Duration::from_secs(2));
        drop(peer_state_guard);
        call.join().unwrap();

        assert!(status.unwrap().is_ok());
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_configuration_replaces_untrusted_control_headers() {
        let data_dir = temp_dir_path("browser-runtime-headers");
        let configuration = RuntimeConfiguration::new(&data_dir, NetworkKind::Testnet)
            .with_initial_policy(RuntimePolicy {
                resolution_mode: ResolutionMode::Strict,
                hns_doh_resolver: Some("https://hnsdoh.com/dns-query".to_owned()),
                experimental_p2p_dns_relay: true,
                legacy_hns_doh_compatibility: false,
                stateless_dane_certificates: true,
            });
        let runtime = BrowserRuntime::open(configuration).unwrap();
        let header_text = runtime
            .gateway_header_text(&[
                ("Accept".to_owned(), "text/html".to_owned()),
                (HNS_GATEWAY_NETWORK_HEADER.to_owned(), "regtest".to_owned()),
                (HNS_GATEWAY_STRICT_MODE_HEADER.to_owned(), "0".to_owned()),
                (
                    "x-hns-unrecognized-metadata".to_owned(),
                    "spoofed".to_owned(),
                ),
            ])
            .unwrap();

        let parsed = parse_gateway_headers(&header_text).unwrap();
        assert_eq!(
            parsed.headers,
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
        assert!(parsed.strict_hns_mode);
        assert!(parsed.experimental_p2p_dns_relay);
        assert!(parsed.stateless_dane_certificates);
        assert_eq!(parsed.network, NetworkKind::Testnet);
        assert_eq!(
            parsed.configured_hns_doh.map(|endpoint| endpoint.display()),
            Some("https://hnsdoh.com/dns-query".to_owned())
        );
        let normalized = runtime.policy().unwrap();
        assert_eq!(
            normalized.hns_doh_resolver.as_deref(),
            Some("https://hnsdoh.com/dns-query")
        );
        assert!(!normalized.legacy_hns_doh_compatibility);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_rejects_header_injection_before_adding_control_metadata() {
        let data_dir = temp_dir_path("browser-runtime-header-injection");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();

        let error = runtime
            .gateway_header_text(&[(
                "Accept".to_owned(),
                "text/html\r\nX-HNS-Browser-Network: mainnet".to_owned(),
            )])
            .unwrap_err();

        assert!(matches!(error, RuntimeError::InvalidConfiguration(_)));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_policy_updates_are_revisioned_and_normalized() {
        let data_dir = temp_dir_path("browser-runtime-policy");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Mainnet))
                .unwrap();
        assert_eq!(runtime.policy_revision(), 0);
        let initial_canonical = runtime.inner.canonical_authority.policy_snapshot().unwrap();
        assert_eq!(initial_canonical.generation(), 1);
        assert_eq!(
            initial_canonical.config().dns_relay_requester,
            CanonicalDnsRelayRequesterPolicy::Disabled
        );
        assert_eq!(
            initial_canonical.config().oblivious_dns,
            CanonicalObliviousDnsPolicy::Disabled
        );
        assert_eq!(
            initial_canonical.config().hnsr,
            CanonicalHnsrPolicy::disabled()
        );
        assert_eq!(
            initial_canonical.config().providers,
            CanonicalProviderPolicy {
                dns_relay: false,
                odoh_proxy: false,
                odoh_target: false,
                market_gossip: false,
            }
        );
        assert!(initial_canonical.config().authenticated_authoritative_doh);
        assert!(
            !initial_canonical
                .config()
                .allow_legacy_regtest_compatibility
        );

        let changed = RuntimePolicy {
            resolution_mode: ResolutionMode::Strict,
            hns_doh_resolver: Some("https://HNSDOH.COM:443/dns-query".to_owned()),
            experimental_p2p_dns_relay: true,
            legacy_hns_doh_compatibility: false,
            stateless_dane_certificates: true,
        };
        let revision = runtime.set_policy(changed.clone()).unwrap();
        let (policy, snapshot_revision) = runtime.policy_snapshot().unwrap();

        assert_eq!(revision, 1);
        assert_eq!(snapshot_revision, revision);
        assert_eq!(policy.resolution_mode, ResolutionMode::Strict);
        assert!(policy.experimental_p2p_dns_relay);
        assert!(!policy.legacy_hns_doh_compatibility);
        assert_eq!(
            policy.hns_doh_resolver.as_deref(),
            Some("https://hnsdoh.com/dns-query")
        );
        assert!(policy.stateless_dane_certificates);
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .policy_snapshot()
                .unwrap()
                .generation(),
            2
        );
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .policy_snapshot()
                .unwrap()
                .config()
                .dns_relay_requester,
            CanonicalDnsRelayRequesterPolicy::Auto
        );

        assert_eq!(runtime.set_policy(changed).unwrap(), 1);
        assert_eq!(runtime.policy_revision(), 1);
        assert_eq!(
            runtime
                .inner
                .canonical_authority
                .policy_snapshot()
                .unwrap()
                .generation(),
            2
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_runtime_rejects_oversized_gateway_inputs_before_execution() {
        let data_dir = temp_dir_path("browser-runtime-gateway-limits");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let mut request = GatewayHttpRequest {
            method: "POST".to_owned(),
            scheme: "http".to_owned(),
            host: "example".to_owned(),
            port: 80,
            path_and_query: "/".to_owned(),
            headers: Vec::new(),
            body: vec![0; DEFAULT_MAX_REQUEST_BODY_BYTES + 1],
        };
        assert!(matches!(
            runtime.gateway_request(request.clone()),
            Err(RuntimeError::InvalidConfiguration(_))
        ));

        request.body.clear();
        request.headers.push((
            "X-Large".to_owned(),
            "a".repeat(MAX_GATEWAY_HEADER_TEXT_BYTES),
        ));
        assert!(matches!(
            runtime.gateway_request(request),
            Err(RuntimeError::InvalidConfiguration(_))
        ));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn raw_gateway_operation_owns_validation_policy_and_preadmission_error_mapping() {
        let data_dir = temp_dir_path("browser-runtime-raw-gateway");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let request = |port, header_text: &str, body: Vec<u8>| RawGatewayHttpRequest {
            method: "GET".to_owned(),
            scheme: "https".to_owned(),
            host: "welcome".to_owned(),
            port,
            path_and_query: "/resource".to_owned(),
            header_text: header_text.to_owned(),
            body,
        };

        let invalid_port = runtime
            .raw_gateway_request(request(-1, "", Vec::new()), RuntimePolicy::compatibility())
            .unwrap()
            .into_bytes();
        assert!(invalid_port.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

        let oversized = runtime
            .raw_gateway_request(
                request(443, "", vec![0; DEFAULT_MAX_REQUEST_BODY_BYTES + 1]),
                RuntimePolicy::compatibility(),
            )
            .unwrap()
            .into_bytes();
        assert!(oversized.starts_with(b"HTTP/1.1 413 Origin Request Too Large\r\n"));

        let post_admission = runtime
            .raw_gateway_request(
                request(443, "Accept: text/html\r\n", Vec::new()),
                RuntimePolicy {
                    resolution_mode: ResolutionMode::Strict,
                    hns_doh_resolver: Some("not-a-doh-url".to_owned()),
                    experimental_p2p_dns_relay: true,
                    legacy_hns_doh_compatibility: false,
                    stateless_dane_certificates: true,
                },
            )
            .unwrap_err();
        assert!(matches!(
            post_admission,
            RuntimeError::InvalidConfiguration(_)
        ));
        assert!(!post_admission.to_string().contains("not-a-doh-url"));
        assert_eq!(
            parse_untrusted_gateway_headers(
                "Accept: text/html\r\nX-HNS-Browser-Network: mainnet\r\nx-hns-spoofed: yes\r\n",
            )
            .unwrap(),
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
        cleanup_dir(&data_dir);
    }

    #[test]
    fn raw_gateway_file_rejections_write_fixed_length_error_bodies() {
        let data_dir = temp_dir_path("browser-runtime-raw-gateway-file");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let body_path = data_dir.join("rejection.body");
        let head = runtime
            .raw_gateway_request_body_to_file(
                RawGatewayHttpRequest {
                    method: "GET".to_owned(),
                    scheme: "https".to_owned(),
                    host: "welcome".to_owned(),
                    port: -1,
                    path_and_query: "/resource".to_owned(),
                    header_text: String::new(),
                    body: Vec::new(),
                },
                RuntimePolicy::compatibility(),
                &body_path,
            )
            .unwrap();
        let body = fs::read(&body_path).unwrap();
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(head.ends_with("\r\n\r\n"));
        cleanup_dir(&data_dir);
    }

    #[test]
    fn exported_direct_gateway_apis_reject_stale_publication_and_sticky_commit() {
        let exercise_response = || {
            let (data_dir, runtime) =
                runtime_with_cached_loopback_name("direct-gateway-authority-rejection");
            let (port, request_seen, release_origin, origin) = delayed_http_origin();
            let call_runtime = runtime.clone();
            let call = thread::spawn(move || {
                call_runtime.gateway_request(GatewayHttpRequest {
                    method: "GET".to_owned(),
                    scheme: "http".to_owned(),
                    host: "welcome".to_owned(),
                    port,
                    path_and_query: "/".to_owned(),
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            });
            request_seen.recv_timeout(Duration::from_secs(2)).unwrap();
            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            release_origin.send(()).unwrap();
            origin.join().unwrap();

            let result = call.join().unwrap();
            assert!(matches!(
                result,
                Err(RuntimeError::Operation(detail))
                    if detail.contains("stale direct publication")
            ));
            let key = NamespaceOriginKey::new("http", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );
            cleanup_dir(&data_dir);
        };

        let exercise_file = || {
            let (data_dir, runtime) =
                runtime_with_cached_loopback_name("direct-file-authority-rejection");
            let destination = data_dir.join("direct.body");
            fs::write(&destination, b"existing").unwrap();
            let (port, request_seen, release_origin, origin) = delayed_http_origin();
            let call_runtime = runtime.clone();
            let call_destination = destination.clone();
            let call = thread::spawn(move || {
                call_runtime.gateway_request_body_to_file(
                    GatewayHttpRequest {
                        method: "GET".to_owned(),
                        scheme: "http".to_owned(),
                        host: "welcome".to_owned(),
                        port,
                        path_and_query: "/".to_owned(),
                        headers: Vec::new(),
                        body: Vec::new(),
                    },
                    call_destination,
                )
            });
            request_seen.recv_timeout(Duration::from_secs(2)).unwrap();
            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            release_origin.send(()).unwrap();
            origin.join().unwrap();

            let result = call.join().unwrap();
            assert!(matches!(
                result,
                Err(RuntimeError::Operation(detail))
                    if detail.contains("stale direct publication")
            ));
            assert_eq!(fs::read(&destination).unwrap(), b"existing");
            let key = NamespaceOriginKey::new("http", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );
            cleanup_dir(&data_dir);
        };

        exercise_response();
        exercise_file();
    }

    #[test]
    fn raw_gateway_wrappers_propagate_post_admission_authority_rejection() {
        let exercise_response = || {
            let (data_dir, runtime) =
                runtime_with_cached_loopback_name("raw-gateway-authority-rejection");
            let policy = runtime.policy().unwrap();
            let (port, request_seen, release_origin, origin) = delayed_http_origin();
            let call_runtime = runtime.clone();
            let call = thread::spawn(move || {
                call_runtime.raw_gateway_request(
                    RawGatewayHttpRequest {
                        method: "GET".to_owned(),
                        scheme: "http".to_owned(),
                        host: "welcome".to_owned(),
                        port: i32::from(port),
                        path_and_query: "/".to_owned(),
                        header_text: String::new(),
                        body: Vec::new(),
                    },
                    policy,
                )
            });
            request_seen.recv_timeout(Duration::from_secs(2)).unwrap();
            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            release_origin.send(()).unwrap();
            origin.join().unwrap();

            let result = call.join().unwrap();
            assert!(matches!(
                result,
                Err(RuntimeError::Operation(detail))
                    if detail.contains("stale direct publication")
            ));
            let key = NamespaceOriginKey::new("http", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );
            cleanup_dir(&data_dir);
        };

        let exercise_file = || {
            let (data_dir, runtime) =
                runtime_with_cached_loopback_name("raw-file-authority-rejection");
            let policy = runtime.policy().unwrap();
            let destination = data_dir.join("raw.body");
            fs::write(&destination, b"existing").unwrap();
            let (port, request_seen, release_origin, origin) = delayed_http_origin();
            let call_runtime = runtime.clone();
            let call_destination = destination.clone();
            let call = thread::spawn(move || {
                call_runtime.raw_gateway_request_body_to_file(
                    RawGatewayHttpRequest {
                        method: "GET".to_owned(),
                        scheme: "http".to_owned(),
                        host: "welcome".to_owned(),
                        port: i32::from(port),
                        path_and_query: "/".to_owned(),
                        header_text: String::new(),
                        body: Vec::new(),
                    },
                    policy,
                    call_destination,
                )
            });
            request_seen.recv_timeout(Duration::from_secs(2)).unwrap();
            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            release_origin.send(()).unwrap();
            origin.join().unwrap();

            let result = call.join().unwrap();
            assert!(matches!(
                result,
                Err(RuntimeError::Operation(detail))
                    if detail.contains("stale direct publication")
            ));
            assert_eq!(fs::read(&destination).unwrap(), b"existing");
            let key = NamespaceOriginKey::new("http", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );
            cleanup_dir(&data_dir);
        };

        exercise_response();
        exercise_file();
    }

    fn runtime_with_cached_loopback_name(label: &str) -> (PathBuf, BrowserRuntime) {
        let data_dir = temp_dir_path(label);
        let base = data_dir.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([33; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_dual_stack_resource(
                        &root_name,
                        [127, 0, 0, 1],
                        Ipv6Addr::LOCALHOST.octets(),
                    ),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        drop(resources);
        let runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest).with_initial_policy(
                RuntimePolicy {
                    resolution_mode: ResolutionMode::Strict,
                    hns_doh_resolver: None,
                    experimental_p2p_dns_relay: false,
                    legacy_hns_doh_compatibility: false,
                    stateless_dane_certificates: false,
                },
            ),
        )
        .unwrap();
        (data_dir, runtime)
    }

    fn runtime_with_cached_dual_root_absence(label: &str) -> (PathBuf, BrowserRuntime) {
        let data_dir = temp_dir_path(label);
        let base = data_dir.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "missing".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([34; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name, name_hash)
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        drop(resources);
        let runtime = BrowserRuntime::open(
            RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest).with_initial_policy(
                RuntimePolicy {
                    resolution_mode: ResolutionMode::Strict,
                    hns_doh_resolver: None,
                    experimental_p2p_dns_relay: false,
                    legacy_hns_doh_compatibility: false,
                    stateless_dane_certificates: false,
                },
            ),
        )
        .unwrap();
        (data_dir, runtime)
    }

    fn runtime_with_current_mainnet_authority(label: &str) -> (PathBuf, BrowserRuntime, Height) {
        let data_dir = temp_dir_path(label);
        let base = data_dir.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let anchor_height = store_best_header_for_network_with_tree_root(
            &base,
            NetworkKind::Mainnet,
            Hash::new([44; 32]),
        );
        SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        store_peer_height(&base, anchor_height.0);
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Mainnet))
                .unwrap();
        (data_dir, runtime, anchor_height)
    }

    fn selected_tls_test_decision(
        namespace: Namespace,
        tls_policy: TlsTrustPolicy,
    ) -> NamespaceDecision {
        let now = now_unix_seconds();
        let host = CanonicalHost::parse(match namespace {
            Namespace::Hns => "native-connect-test",
            Namespace::Icann => "native-connect-test.example",
        })
        .unwrap();
        let query = OriginQuery::new(
            host.clone(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::new(true, true, false).unwrap(),
        );
        let freshness = Freshness::new(now, now + 60).unwrap();
        let tlsa_records = if tls_policy == TlsTrustPolicy::Dane {
            vec![
                CanonicalTlsa::new({
                    let mut rdata = vec![3, 1, 1];
                    rdata.extend_from_slice(&[0x71; 32]);
                    rdata
                })
                .unwrap(),
            ]
        } else {
            Vec::new()
        };
        let provenance = match namespace {
            Namespace::Hns => EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [0x72; 32],
                height: 72,
            },
            Namespace::Icann => EvidenceProvenance::IcannDoh {
                chain_state: if tls_policy == TlsTrustPolicy::WebPkiInsecureDelegation {
                    IcannChainState::ProvenInsecure
                } else {
                    IcannChainState::Secure
                },
            },
        };
        let plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host.clone(),
            endpoints: vec!["203.0.113.72:443".parse().unwrap()],
            service: default_service_binding(&query, &host).unwrap(),
            tls_policy,
            tlsa_records,
            provenance,
            freshness,
        })
        .unwrap();
        match namespace {
            Namespace::Hns => {
                let icann_absence = ValidatedAbsence::new(
                    Namespace::Icann,
                    query.clone(),
                    AbsenceKind::DnssecAuthenticatedNxDomain,
                    EvidenceProvenance::IcannDoh {
                        chain_state: IcannChainState::Secure,
                    },
                    freshness,
                )
                .unwrap();
                decide_namespace(
                    &query,
                    RootLookup::Present(plan),
                    RootLookup::Absent(icann_absence),
                    SelectionPolicy::default(),
                    now,
                )
                .unwrap()
            }
            Namespace::Icann => {
                let hns_absence = ValidatedAbsence::new(
                    Namespace::Hns,
                    query.clone(),
                    AbsenceKind::HnsCurrentUrkelNonInclusion,
                    EvidenceProvenance::Hns {
                        network: HnsNetwork::Mainnet,
                        tree_root: [0x73; 32],
                        height: 73,
                    },
                    freshness,
                )
                .unwrap();
                decide_namespace(
                    &query,
                    RootLookup::Absent(hns_absence),
                    RootLookup::Present(plan),
                    SelectionPolicy::default(),
                    now,
                )
                .unwrap()
            }
        }
    }

    fn tls_origin_request_for_decision(decision: &NamespaceDecision) -> OriginRequest {
        let plan = decision.selected_plan().unwrap();
        let tls_policy = plan.tls_policy();
        let mut tls = TlsValidation {
            mode: match plan.namespace() {
                Namespace::Hns => hns_dane::DomainTrustMode::HnsStrict,
                Namespace::Icann => hns_dane::DomainTrustMode::IcannWebPki,
            },
            dnssec_secure: tls_policy != TlsTrustPolicy::WebPkiInsecureDelegation,
            namespace_fingerprint: Some(decision_fingerprint(decision).to_hex()),
            service_port: 443,
            service_transport: TlsaTransport::Tcp,
            ..Default::default()
        };
        match tls_policy {
            TlsTrustPolicy::Dane => {
                tls.tlsa_records = vec![TlsaRecord {
                    usage: TlsaUsage::DaneEe,
                    selector: TlsaSelector::SubjectPublicKeyInfo,
                    matching: TlsaMatching::Sha256,
                    association_data: vec![0x71; 32],
                }];
                tls.tlsa_source = Some(TlsaRecordSource::NativeTlsa);
                tls.browser_tls_decision = Some(BrowserTlsDecision::EnforceDane {
                    record_count: std::num::NonZeroUsize::new(1).unwrap(),
                });
            }
            TlsTrustPolicy::WebPkiAuthenticatedAbsence => {
                tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
            }
            TlsTrustPolicy::WebPkiInsecureDelegation => {
                tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiInsecureDelegation);
            }
            TlsTrustPolicy::Cleartext => panic!("HTTPS test plan cannot be cleartext"),
        }
        OriginRequest {
            method: "CONNECT".to_owned(),
            scheme: "https".to_owned(),
            host: decision.query().host().as_str().to_owned(),
            connect_host: Some("203.0.113.72".to_owned()),
            port: 443,
            path_and_query: "/".to_owned(),
            protocol: OriginProtocol::Http11,
            tls,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn force_same_generation_authority_aba(authority: &CanonicalAuthority) {
        let mut runtime = authority.runtime.lock().unwrap();
        runtime
            .transition(CanonicalAuthorityState::Degraded)
            .unwrap();
        advance_canonical_authority_to_active(&mut runtime).unwrap();
        runtime.admit_event().unwrap();
    }

    fn delayed_http_origin() -> (
        u16,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_seen_tx, request_seen_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_test_http_head(&mut stream).unwrap();
            request_seen_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });
        (port, request_seen_rx, release_tx, origin)
    }

    fn proxy_request(port: u16, scheme: &str) -> LoopbackProxyRequest {
        LoopbackProxyRequest {
            method: "GET".to_owned(),
            scheme: scheme.to_owned(),
            host: "welcome".to_owned(),
            port,
            path_and_query: "/socket".to_owned(),
            headers: vec![
                ProxyHeader::new("Host", format!("welcome:{port}")),
                ProxyHeader::new("X-Test", "yes"),
                ProxyHeader::new("X-HNS-Browser-Network", "mainnet"),
            ],
            body: ProxyRequestBody::Empty,
        }
    }

    fn read_test_http_head(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while head.len() < MAX_GATEWAY_HEADER_TEXT_BYTES {
            if stream.read(&mut byte)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "test HTTP head ended early",
                ));
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                return Ok(head);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "test HTTP head exceeded limit",
        ))
    }

    #[test]
    fn browser_proxy_status_observer_receives_typed_trusted_main_frame_metadata() {
        let (data_dir, runtime) =
            runtime_with_cached_loopback_name("runtime-proxy-status-observer");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = listener.local_addr().unwrap().port();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET / HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nX-HNS-Security-Path: spoofed\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                )
                .unwrap();
        });

        let (status_tx, status_rx) = std::sync::mpsc::channel();
        let observer = move |status: &BrowserProxyStatus| {
            let _result = status_tx.send(status.clone());
        };
        let generated_ca = LocalCertificateAuthority::generate().unwrap();
        let proxy = runtime
            .start_dane_browser_proxy_with_certificate_authority_and_observer(
                generated_ca.authority().clone(),
                Arc::new(observer),
            )
            .unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = format!(
            "GET http://welcome:{origin_port}/ HTTP/1.1\r\nHost: welcome:{origin_port}\r\nProxy-Authorization: {}\r\nSec-Fetch-Dest: document\r\nAccept: text/html\r\n\r\n",
            proxy.running.endpoint().authorization_header_value(),
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!response.to_ascii_lowercase().contains("x-hns-"));

        let status = status_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(status.generation, proxy.generation());
        assert_eq!(status.host, "welcome");
        assert_eq!(status.status_code, 200);
        assert!(status.likely_main_frame);
        assert_eq!(
            status.correlation_epoch,
            runtime.security_maintenance_epoch()
        );
        assert_eq!(status.tls_policy, None);
        assert_eq!(status.resolver_policy, None);
        assert_ne!(
            status.security_path,
            Some(BrowserProxySecurityPath::StatelessDane)
        );
        assert!(
            status
                .resolution_trace_json
                .as_deref()
                .is_some_and(|trace| trace.contains(r#""mode":"strict""#))
        );
        assert_eq!(status.canonical_status_unavailable_reason(), None);
        assert_eq!(
            status
                .canonical_status()
                .expect("proof-contained HNS success has canonical status")
                .actual_transport(),
            CanonicalResolutionTransport::LocalHnsProof
        );

        proxy.stop();
        origin.join().unwrap();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn runtime_proxy_backend_returns_typed_sanitized_gateway_response() {
        let (data_dir, runtime) = runtime_with_cached_loopback_name("runtime-proxy-http");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(!request.contains("X-HNS-"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: close, X-Origin-Hop\r\nX-Origin-Hop: secret\r\nX-HNS-TLS-Policy: spoofed\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                )
                .unwrap();
        });

        let response = runtime
            .proxy_backend()
            .execute(proxy_request(port, "http"), &ProxyCancellationToken::new())
            .unwrap();

        assert_eq!(response.head.status_code, 200);
        assert_eq!(response.head.reason_phrase, "OK");
        assert!(response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == "text/plain"
        }));
        assert!(response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(HNS_RESOLVER_MODE_HEADER) && header.value == "strict"
        }));
        assert!(response.head.headers.iter().any(|header| {
            header
                .name
                .eq_ignore_ascii_case(HNS_RESOLUTION_TRACE_HEADER)
                && header.value.contains(r#""dnssec":"secure""#)
        }));
        assert!(!response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("x-origin-hop")
                || header.name.eq_ignore_ascii_case("x-hns-tls-policy")
        }));
        match response.body {
            ProxyResponseBody::Bytes(body) => assert_eq!(body, b"ok"),
            ProxyResponseBody::Stream { .. } => panic!("runtime response must be bounded bytes"),
        }
        server.join().unwrap();
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn runtime_gateway_errors_remain_actionable_typed_http_responses() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("runtime-proxy-error-response");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let request = GatewayHttpRequest {
            method: "GET".to_owned(),
            scheme: "ws".to_owned(),
            host: "missing".to_owned(),
            port: 80,
            path_and_query: "/socket".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let failure = GatewayFailure::from(GatewayError::Resolver(ResolverError::NameNotFound));
        let maintenance = runtime.inner.coordination.maintenance.read().unwrap();
        let maintenance_epoch = runtime
            .inner
            .coordination
            .publication_epoch(&maintenance)
            .unwrap();
        let storage_identity = test_header_state_lease(&runtime.inner.coordination).identity;
        let response = proxy_error_response_from_gateway(
            &runtime,
            stamp,
            maintenance_epoch,
            storage_identity,
            &request,
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            &failure,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );
        drop(maintenance);

        assert_eq!(response.head.status_code, 404);
        assert_eq!(response.head.reason_phrase, "HNS Name Not Found");
        assert!(response.head.observation_id.is_some());
        assert!(response.head.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header.value == "text/plain; charset=utf-8"
        }));
        assert!(response.head.headers.iter().any(|header| {
            header
                .name
                .eq_ignore_ascii_case(HNS_RESOLUTION_TRACE_HEADER)
                && header
                    .value
                    .contains(r#""finalError":"resolver error: HNS name does not exist""#)
        }));
        match response.body {
            ProxyResponseBody::Bytes(body) => {
                let body = String::from_utf8(body).unwrap();
                assert!(body.contains("ws://missing/socket"));
                assert!(body.contains("404 HNS Name Not Found"));
            }
            ProxyResponseBody::Stream { .. } => panic!("error response must be bounded bytes"),
        }
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn runtime_interception_error_is_a_hardened_clickable_html_document() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("runtime-interception-error-response");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let request = GatewayHttpRequest {
            method: "GET".to_owned(),
            scheme: "https".to_owned(),
            host: "shakeshift".to_owned(),
            port: 443,
            path_and_query: "/".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let failure = GatewayFailure::from(GatewayError::Resolver(
            ResolverError::Port53InterceptionDetected,
        ));
        let dns_trace = trace_with_hns_nameserver("shakeshift", "a.namenode");
        let maintenance = runtime.inner.coordination.maintenance.read().unwrap();
        let maintenance_epoch = runtime
            .inner
            .coordination
            .publication_epoch(&maintenance)
            .unwrap();
        let storage_identity = test_header_state_lease(&runtime.inner.coordination).identity;
        let response = proxy_error_response_from_gateway(
            &runtime,
            stamp,
            maintenance_epoch,
            storage_identity,
            &request,
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            &failure,
            &FallbackMarker::default(),
            &dns_trace,
        );
        drop(maintenance);

        assert_eq!(response.head.status_code, 502);
        for (name, value) in [
            ("content-type", "text/html; charset=utf-8"),
            ("content-security-policy", INTERCEPTION_ERROR_CSP),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ] {
            assert!(
                response.head.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case(name) && header.value == value
                })
            );
        }
        match response.body {
            ProxyResponseBody::Bytes(body) => {
                let body = String::from_utf8(body).unwrap();
                assert!(body.contains(
                    "https://hns.denuoweb.com/dane-generator/?domain=shakeshift%2F&amp;domain_type=hns&amp;intent=authoritative_doh&amp;mode=delegated&amp;nameserver=a.namenode"
                ));
            }
            ProxyResponseBody::Stream { .. } => panic!("error response must be bounded bytes"),
        }
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn typed_upgrade_parser_requires_a_complete_websocket_handshake() {
        let parsed = parse_upgrade_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.status_code, 101);
        assert!(parsed.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("sec-websocket-accept") && value == "accepted"
        }));

        for invalid in [
            b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
                .as_slice(),
        ] {
            assert!(matches!(
                parse_upgrade_response_head(invalid),
                Err(ProxyBackendError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn post_admission_prepare_failure_returns_an_exactly_stamped_error_head() {
        let (data_dir, runtime, _anchor_height) =
            runtime_with_current_mainnet_authority("stamped-prepare-failure");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let mut request = proxy_request(80, "http");
        request
            .headers
            .push(ProxyHeader::new("Invalid Header Name", "value"));
        let response = runtime
            .proxy_backend()
            .execute(request, &ProxyCancellationToken::new())
            .unwrap();

        assert_eq!(response.head.status_code, 400);
        assert!(response.head.observation_id.is_some());
        runtime
            .set_policy(RuntimePolicy {
                resolution_mode: ResolutionMode::Strict,
                ..RuntimePolicy::compatibility()
            })
            .unwrap();
        let mut published = Vec::new();
        assert!(
            response
                .publication_permit
                .publish(|| published.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n"))
                .is_err()
        );
        assert!(published.is_empty());

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn fallible_response_sanitization_becomes_a_stamped_error_without_orphan_status() {
        let (data_dir, runtime) =
            runtime_with_cached_loopback_name("stamped-response-sanitization-failure");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_test_http_head(&mut stream).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: invalid token\r\nContent-Length: 2\r\n\r\nok",
                )
                .unwrap();
        });

        let response = runtime
            .proxy_backend()
            .execute(proxy_request(port, "http"), &ProxyCancellationToken::new())
            .unwrap();
        assert_eq!(response.head.status_code, 502);
        assert_eq!(response.head.reason_phrase, "Invalid Upstream Response");
        let observation_id = response.head.observation_id.unwrap();
        assert!(matches!(
            runtime
                .inner
                .canonical_statuses
                .take(observation_id, &runtime.inner.canonical_authority),
            Some(CanonicalStatusObservation {
                status: CanonicalStatusAvailability::Unavailable(
                    CanonicalStatusUnavailableReason::EvidenceUnavailable
                ),
                ..
            })
        ));
        let mut published = Vec::new();
        response
            .publication_permit
            .publish(|| published.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"))
            .unwrap();
        assert!(!published.is_empty());

        origin.join().unwrap();
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn fallible_upgrade_sanitization_becomes_a_stamped_error_head() {
        let (data_dir, runtime) =
            runtime_with_cached_loopback_name("stamped-upgrade-sanitization-failure");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.contains("Connection: Upgrade\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, invalid token\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\n\r\n",
                )
                .unwrap();
        });
        let request = LoopbackProxyRequest {
            method: "GET".to_owned(),
            scheme: "ws".to_owned(),
            host: "welcome".to_owned(),
            port,
            path_and_query: "/socket".to_owned(),
            headers: vec![
                ProxyHeader::new("Host", format!("welcome:{port}")),
                ProxyHeader::new("Connection", "Upgrade"),
                ProxyHeader::new("Upgrade", "websocket"),
                ProxyHeader::new("Sec-WebSocket-Key", "key"),
                ProxyHeader::new("Sec-WebSocket-Version", "13"),
            ],
            body: ProxyRequestBody::Empty,
        };

        let opened = runtime
            .proxy_backend()
            .open_tunnel(request, &ProxyCancellationToken::new())
            .unwrap();
        let ProxyTunnelOpen::Response(response) = opened else {
            panic!("invalid upgrade response metadata must fail before tunnel publication");
        };
        assert_eq!(response.head.status_code, 502);
        assert_eq!(response.head.reason_phrase, "Invalid Upstream Response");
        assert!(response.head.observation_id.is_some());
        let mut published = Vec::new();
        response
            .publication_permit
            .publish(|| published.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"))
            .unwrap();
        assert!(!published.is_empty());

        origin.join().unwrap();
        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn denied_response_and_tunnel_heads_cannot_commit_sticky_namespace_after_aba() {
        let exercise_response = || {
            let (data_dir, runtime) = runtime_with_cached_loopback_name("response-sticky-aba");
            let proxy = runtime.start_proxy("welcome").unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let origin = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let _request = read_test_http_head(&mut stream).unwrap();
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
            });
            let response = runtime
                .proxy_backend()
                .execute(proxy_request(port, "http"), &ProxyCancellationToken::new())
                .unwrap();
            origin.join().unwrap();
            let key = NamespaceOriginKey::new("http", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );

            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            let mut published = Vec::new();
            assert!(
                response
                    .publication_permit
                    .publish(|| published.write_all(b"HTTP/1.1 200 OK\r\n\r\n"))
                    .is_err()
            );
            assert!(published.is_empty());
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );

            proxy.stop();
            cleanup_dir(&data_dir);
        };

        let exercise_tunnel = || {
            let (data_dir, runtime) = runtime_with_cached_loopback_name("tunnel-sticky-aba");
            let proxy = runtime.start_proxy("welcome").unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let origin = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let _request = read_test_http_head(&mut stream).unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\n\r\n",
                    )
                    .unwrap();
            });
            let request = LoopbackProxyRequest {
                method: "GET".to_owned(),
                scheme: "ws".to_owned(),
                host: "welcome".to_owned(),
                port,
                path_and_query: "/socket".to_owned(),
                headers: vec![
                    ProxyHeader::new("Host", format!("welcome:{port}")),
                    ProxyHeader::new("Connection", "Upgrade"),
                    ProxyHeader::new("Upgrade", "websocket"),
                    ProxyHeader::new("Sec-WebSocket-Key", "key"),
                    ProxyHeader::new("Sec-WebSocket-Version", "13"),
                ],
                body: ProxyRequestBody::Empty,
            };
            let opened = runtime
                .proxy_backend()
                .open_tunnel(request, &ProxyCancellationToken::new())
                .unwrap();
            origin.join().unwrap();
            let ProxyTunnelOpen::Tunnel(tunnel) = opened else {
                panic!("valid origin upgrade must prepare a tunnel");
            };
            let key = NamespaceOriginKey::new("ws", "welcome", port).unwrap();
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );

            force_same_generation_authority_aba(&runtime.inner.canonical_authority);
            let mut published = Vec::new();
            assert!(
                tunnel
                    .publication_permit
                    .publish(|| published.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"))
                    .is_err()
            );
            assert!(published.is_empty());
            assert_eq!(
                runtime
                    .inner
                    .coordination
                    .namespace_bindings
                    .get(&key)
                    .unwrap(),
                None
            );

            proxy.stop();
            cleanup_dir(&data_dir);
        };

        exercise_response();
        exercise_tunnel();
    }

    #[test]
    fn rust_proxy_uses_runtime_gateway_for_websocket_upgrade() {
        let (data_dir, runtime) = runtime_with_cached_loopback_name("runtime-proxy-websocket");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = listener.local_addr().unwrap().port();
        let origin = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = String::from_utf8(read_test_http_head(&mut stream).unwrap()).unwrap();
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(request.contains("Connection: Upgrade\r\n"));
            assert!(request.contains("Upgrade: websocket\r\n"));
            assert!(request.contains("Sec-WebSocket-Key: key\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(!request.contains("Proxy-Authorization"));
            assert!(!request.contains("X-HNS-"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Origin-Hop\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\nX-Origin-Hop: secret\r\nX-HNS-TLS-Policy: spoofed\r\n\r\norigin",
                )
                .unwrap();
            stream.flush().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&payload).unwrap();
            stream.flush().unwrap();
        });
        let proxy = runtime.start_proxy("welcome").unwrap();
        let mut client = TcpStream::connect(proxy.running.endpoint().address()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = format!(
            "GET ws://welcome:{origin_port}/socket HTTP/1.1\r\nHost: welcome:{origin_port}\r\nProxy-Authorization: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\nX-Test: yes\r\nX-HNS-Client: spoofed\r\n\r\n",
            proxy.running.endpoint().authorization_header_value(),
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();

        let response = String::from_utf8(read_test_http_head(&mut client).unwrap()).unwrap();
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(response.contains("Connection: Upgrade\r\n"));
        assert!(response.contains("Upgrade: websocket\r\n"));
        assert!(response.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(!response.contains("X-Origin-Hop"));
        assert!(!response.contains("X-HNS-"));
        let mut initial = [0_u8; 6];
        client.read_exact(&mut initial).unwrap();
        assert_eq!(&initial, b"origin");
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        proxy.stop();
        origin.join().unwrap();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn proxy_stop_cancels_runtime_backend_waiting_for_maintenance() {
        let data_dir = temp_dir_path("runtime-proxy-maintenance-cancellation");
        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&data_dir, NetworkKind::Regtest))
                .unwrap();
        let maintenance = runtime.inner.coordination.maintenance.write().unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let observer = move |event: &hns_loopback_proxy::ProxyEvent| {
            if matches!(
                event,
                hns_loopback_proxy::ProxyEvent::Request {
                    phase: hns_loopback_proxy::RequestPhase::Accepted,
                    ..
                }
            ) {
                let _result = accepted_tx.send(());
            }
        };
        let proxy = RunningProxy::start(
            ProxyConfig::new(
                ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
                hns_loopback_proxy::HostScope::new("welcome").unwrap(),
            ),
            Arc::new(runtime.proxy_backend()),
            Arc::new(observer),
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\nProxy-Authorization: {}\r\n\r\n",
            proxy.endpoint().authorization_header_value(),
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
        let _result = client.shutdown(Shutdown::Both);
        drop(maintenance);
        cleanup_dir(&data_dir);
    }

    #[test]
    fn diagnostics_reports_fail_closed_security() {
        let diagnostics = diagnostics_json();

        assert!(diagnostics.contains(&format!(r#""version":"{}""#, env!("CARGO_PKG_VERSION"))));
        assert!(!diagnostics.contains("__VERSION__"));
        assert!(diagnostics.contains(r#""securityDefault":"fail-closed""#));
    }

    #[test]
    fn diagnostics_reports_resource_decoder() {
        assert!(diagnostics_json().contains(r#""hns-resource-decoder""#));
        assert!(diagnostics_json().contains(r#""hns-authoritative-doh-rfc8484""#));
    }

    #[test]
    fn diagnostics_reports_verified_resource_handoff() {
        assert!(diagnostics_json().contains(r#""header-canonical-height-index""#));
        assert!(diagnostics_json().contains(r#""header-mainnet-difficulty-retarget""#));
        assert!(diagnostics_json().contains(r#""urkel-proof-value-handoff""#));
        assert!(diagnostics_json().contains(r#""hns-resource-provider-adapter""#));
        assert!(diagnostics_json().contains(r#""hns-memory-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-sqlite-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-negative-cache""#));
        assert!(diagnostics_json().contains(r#""hns-ttl-cache-lru""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-stats""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-eviction""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-cap-enforcement""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-chain-anchors""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-reorg-invalidation""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-current-tip""#));
        assert!(diagnostics_json().contains(r#""hns-delegating-resolver-boundary""#));
        assert!(diagnostics_json().contains(r#""hns-name-state-resource-extraction""#));
        assert!(diagnostics_json().contains(r#""hns-proof-backed-ns-address-hydration""#));
        assert!(diagnostics_json().contains(r#""hns-authoritative-dnssec-delegated-resolver""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-referral-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-cname-address-routing""#));
        assert!(diagnostics_json().contains(r#""actionable-hns-errors""#));
        assert!(diagnostics_json().contains(r#""hns-name-not-found-error""#));
        assert!(diagnostics_json().contains(r#""gateway-hns-address-required""#));
        assert!(diagnostics_json().contains(r#""gateway-tlsa-service-scope""#));
    }

    #[test]
    fn diagnostics_reports_ed25519_dnssec() {
        assert!(diagnostics_json().contains(r#""dnssec-ed25519-verify""#));
    }

    #[test]
    fn diagnostics_reports_sha384_ds_digest() {
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha1""#));
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha384""#));
        assert!(diagnostics_json().contains(r#""dnssec-rsa-sha1-verify""#));
    }

    #[test]
    fn diagnostics_reports_tcp_peer_connection() {
        assert!(diagnostics_json().contains(r#""p2p-tcp-peer-connection""#));
        assert!(diagnostics_json().contains(r#""p2p-static-peer-source""#));
        assert!(diagnostics_json().contains(r#""p2p-dns-seed-source""#));
        assert!(diagnostics_json().contains(r#""p2p-getaddr-peer-discovery""#));
        assert!(diagnostics_json().contains(r#""p2p-discovery-rotation""#));
        assert!(diagnostics_json().contains(r#""p2p-peer-diversity""#));
        assert!(diagnostics_json().contains(r#""p2p-sqlite-peer-store""#));
    }

    #[test]
    fn static_relay_peer_endpoint_parser_is_bounded_and_canonical() {
        assert!(normalize_static_relay_peer_endpoint("Relay.Example:12038").is_err());
        assert_eq!(
            normalize_static_relay_peer_endpoint("001.002.003.004:12038"),
            Err("enter a valid IPv4 relay peer address".to_owned()),
        );
        assert_eq!(
            normalize_static_relay_peer_endpoint("[2001:0db8::1]:12038"),
            Ok("[2001:db8::1]:12038".to_owned()),
        );
        for invalid in [
            "",
            "relay.example",
            "https://relay.example:12038",
            "user@relay.example:12038",
            "relay_example:12038",
            "relay.example:0",
            "2001:db8::1:12038",
            "[fe80::1%2]:12038",
        ] {
            assert!(
                normalize_static_relay_peer_endpoint(invalid).is_err(),
                "{invalid}",
            );
        }

        assert!(
            resolve_static_relay_peer_endpoint("127.0.0.1:12038", &hns_core::network::mainnet(),)
                .is_err(),
        );
        assert_eq!(
            resolve_static_relay_peer_endpoint("1.1.1.1:12038", &hns_core::network::mainnet(),),
            Ok(vec!["1.1.1.1:12038".parse().unwrap()]),
        );
    }

    #[test]
    fn runtime_adds_only_a_live_relay_capable_static_peer() {
        let path = temp_dir_path("static-relay-peer");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let remote_height = Height(u32::MAX);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer = PeerConnection::new(stream, hns_core::network::regtest());
            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_)));
            peer.send_packet(&Packet::Version(VersionPacket {
                services: SERVICE_NETWORK | EXPERIMENTAL_DNS_RELAY_SERVICE,
                height: remote_height,
                ..VersionPacket::default()
            }))
            .unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();
        });

        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&path, NetworkKind::Regtest)).unwrap();
        let status = runtime.add_static_relay_peer(&address.to_string()).unwrap();

        assert_eq!(status.status, "peer_added");
        assert_eq!(status.peer_count, 1);
        assert_eq!(status.best_peer_height, None);
        let store = SqlitePeerStore::open(path.join("hns-regtest/peers.sqlite")).unwrap();
        assert_eq!(
            store.load_peer(address).unwrap().unwrap().last_height,
            Height(0),
        );
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn diagnostics_reports_sync_proof_scheduler() {
        assert!(diagnostics_json().contains(r#""header-mainnet-checkpoints""#));
        assert!(diagnostics_json().contains(r#""sync-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-multi-batch-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-parallel-peer-probing""#));
        assert!(diagnostics_json().contains(r#""sync-ranged-peer-rotation""#));
        assert!(diagnostics_json().contains(r#""sync-checkpoint-prefetch""#));
        assert!(diagnostics_json().contains(r#""sync-proof-scheduler""#));
        assert!(diagnostics_json().contains(r#""native-sync-once""#));
        assert!(diagnostics_json().contains(r#""sync-status""#));
        assert!(diagnostics_json().contains(r#""sync-outcome-status""#));
        assert!(diagnostics_json().contains(r#""sync-progress-heights""#));
        assert!(diagnostics_json().contains(r#""sync-high-batch-catchup""#));
        assert!(diagnostics_json().contains(r#""clear-resolver-cache""#));
        assert!(diagnostics_json().contains(r#""persistent-gateway-resolver""#));
        assert!(diagnostics_json().contains(r#""gateway-live-proof-fetch""#));
        assert!(diagnostics_json().contains(r#""gateway-header-forwarding""#));
        assert!(diagnostics_json().contains(r#""gateway-range-forwarding""#));
        assert!(diagnostics_json().contains(r#""gateway-body-forwarding""#));
        assert!(diagnostics_json().contains(r#""gateway-file-body-stream""#));
        assert!(diagnostics_json().contains(r#""chromium-browser-request-gateway""#));
        assert!(diagnostics_json().contains(r#""chromium-service-worker-gateway""#));
        assert!(diagnostics_json().contains(r#""chromium-redirect-gateway""#));
        assert!(diagnostics_json().contains(r#""user-configured-recursive-hns-doh""#));
        assert!(diagnostics_json().contains(r#""random-loopback-proxy-port""#));
    }

    #[test]
    fn diagnostics_reports_websocket_native_tunnel() {
        let diagnostics = diagnostics_json();

        assert!(diagnostics.contains(r#""hns-websocket-native-tunnel""#));
        assert!(diagnostics.contains(r#""http-origin-connection-pooling""#));
        assert!(diagnostics.contains(r#""https-tls-session-resumption""#));
        assert!(diagnostics.contains(r#""https-alt-svc-promotion""#));
    }

    #[test]
    fn diagnostics_reports_origin_transport_framing() {
        assert!(diagnostics_json().contains(r#""http-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http2-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http3-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http-origin-response-framing""#));
        assert!(diagnostics_json().contains(r#""https-rustls-transport""#));
        assert!(diagnostics_json().contains(r#""dane-certificate-chain-policy""#));
        assert!(diagnostics_json().contains(r#""x509-stateless-dane-evidence""#));
        assert!(diagnostics_json().contains(r#""dane-tls-policy""#));
    }

    #[test]
    fn diagnostics_reports_rust_loopback_connect_certificate_generation() {
        assert!(diagnostics_json().contains(r#""rust-loopback-local-hns-connect-certs""#));
    }

    #[test]
    fn diagnostics_reports_delegated_gateway_policy() {
        assert!(diagnostics_json().contains(r#""hns-dotted-root-label""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-nxdomain-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-delegated-origin-address-lookup""#));
        assert!(diagnostics_json().contains(r#""gateway-origin-address-query""#));
        assert!(diagnostics_json().contains(r#""gateway-https-service-query""#));
        assert!(diagnostics_json().contains(r#""gateway-svcb-alpn-policy""#));
        assert!(diagnostics_json().contains(r#""gateway-actionable-nameserver-errors""#));
    }

    #[test]
    fn sync_once_initializes_persistent_stores_without_seed_network() {
        let path = temp_dir_path("sync-once");

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.status, "idle");
        assert_eq!(status.attempted, 0);
        assert_eq!(status.successful, 0);
        assert_eq!(status.accepted, 0);
        assert_eq!(status.failed, 0);
        assert!(status.failures.is_empty());
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.peer_groups, 0);
        assert_eq!(status.best_height, Some(0));
        assert_eq!(status.best_peer_height, None);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);
        assert_eq!(status.resource_cache_evicted, 0);
        assert!(path.join("hns/headers.sqlite").exists());
        assert!(path.join("hns/peers.sqlite").exists());

        let json = sync_status(path.to_str().unwrap());
        assert!(json.contains(r#""status":"idle""#));
        assert!(json.contains(r#""failed":0"#));
        assert!(json.contains(r#""failures":[]"#));
        assert!(json.contains(r#""peerCount":0"#));
        assert!(json.contains(r#""peerGroups":0"#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(json.contains(r#""resourceCacheEntries":0"#));
        assert!(json.contains(r#""resourceCacheBytes":0"#));
        assert!(json.contains(r#""resourceCacheEvicted":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_status_initializes_persistent_stores_without_network() {
        let path = temp_dir_path("sync-status");

        let json = sync_status(path.to_str().unwrap());

        assert!(json.contains(r#""status":"idle""#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(json.contains(r#""peerCount":0"#));
        assert!(json.contains(r#""failures":[]"#));
        assert!(path.join("hns/headers.sqlite").exists());
        assert!(path.join("hns/peers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn testnet_sync_status_uses_isolated_storage_and_genesis() {
        let path = temp_dir_path("sync-status-testnet");

        let json = sync_status_for_network(path.to_str().unwrap(), NetworkKind::Testnet);

        assert!(json.contains(r#""network":"testnet""#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(path.join("hns-testnet/headers.sqlite").exists());
        assert!(path.join("hns-testnet/peers.sqlite").exists());
        assert!(!path.join("hns/headers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn regtest_sync_seeds_loopback_peers() {
        let path = temp_dir_path("sync-once-regtest");

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Regtest,
            true,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.network, NetworkKind::Regtest);
        assert_eq!(status.best_height, Some(0));
        assert!(status.peer_count >= 1);
        assert!(path.join("hns-regtest/headers.sqlite").exists());

        cleanup_dir(&path);
    }

    #[test]
    fn cached_sync_status_classifier_reports_up_to_date_without_network() {
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_590)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_590), Some(335_591)),
            "syncing",
        );
        assert_eq!(classify_cached_sync_status(Some(0), Some(0)), "idle");
        assert_eq!(classify_cached_sync_status(Some(10), None), "syncing");
    }

    #[test]
    fn local_chain_freshness_is_two_blocks_and_never_uses_schedule_estimate() {
        let current =
            LocalChainCurrentness::new(NetworkKind::Mainnet, Some(100), Some(102), Some(50_000));
        assert_eq!(current.target_height, Some(102));
        assert_eq!(current.lag_blocks, Some(2));
        assert_eq!(current.freshness, ChainFreshness::Current);
        assert_eq!(current.stale, Some(false));

        let stale =
            LocalChainCurrentness::new(NetworkKind::Mainnet, Some(100), Some(103), Some(100));
        assert_eq!(stale.lag_blocks, Some(3));
        assert_eq!(stale.freshness, ChainFreshness::Stale);
        assert_eq!(stale.stale, Some(true));

        let unknown =
            LocalChainCurrentness::new(NetworkKind::Mainnet, Some(100), None, Some(50_000));
        assert_eq!(unknown.target_height, None);
        assert_eq!(unknown.lag_blocks, None);
        assert_eq!(unknown.freshness, ChainFreshness::Unknown);
        assert_eq!(unknown.stale, None);
        assert_ne!(
            LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
            RESOURCE_PROOF_CACHE_CANONICAL_WINDOW
        );
    }

    #[test]
    fn name_tree_readiness_waits_only_for_the_target_authority_epoch() {
        let same_epoch = LocalChainCurrentness::new(NetworkKind::Mainnet, Some(1), Some(36), None);
        assert_eq!(same_epoch.authoritative_tree_root_height, Some(1));
        assert_eq!(same_epoch.local_tree_root_height, Some(1));
        assert_eq!(same_epoch.tree_root_ready, Some(true));
        assert_eq!(same_epoch.blocks_until_authoritative_tree_root, Some(0));

        let boundary = LocalChainCurrentness::new(NetworkKind::Mainnet, Some(36), Some(37), None);
        assert_eq!(boundary.authoritative_tree_root_height, Some(37));
        assert_eq!(boundary.local_tree_root_height, Some(1));
        assert_eq!(boundary.tree_root_ready, Some(false));
        assert_eq!(boundary.blocks_until_authoritative_tree_root, Some(1));

        let regtest = LocalChainCurrentness::new(NetworkKind::Regtest, Some(5), None, None);
        assert_eq!(regtest.authoritative_tree_root_height, Some(1));
        assert_eq!(regtest.tree_root_ready, Some(true));
    }

    #[test]
    fn peer_target_requires_recent_diverse_median_and_ignores_one_high_outlier() {
        let now = 10_000;
        let mut peers = PeerManager::default();
        peers.record_success("1.1.1.1:12038".parse().unwrap(), Height(100), now - 10);
        peers.record_success("8.8.8.8:12038".parse().unwrap(), Height(101), now - 9);
        peers.record_success("9.9.9.9:12038".parse().unwrap(), Height(u32::MAX), now - 8);

        let target = assess_peer_target(&peers, &hns_core::network::mainnet(), now);

        assert_eq!(target.height, Some(101));
        assert_eq!(target.peer_groups, 3);
        assert!(!target.evidence_expired);
        assert_eq!(target.evidence_valid_until_unix, Some(11_190));
    }

    #[test]
    fn peer_target_expiry_requires_loss_of_the_fresh_quorum() {
        let now = 10_000;
        let old = now - LOCAL_CHAIN_TARGET_OBSERVATION_MAX_AGE_SECONDS - 1;
        let mut peers = PeerManager::default();
        for (address, height) in [
            ("1.1.1.1:12038", 100),
            ("8.8.8.8:12038", 101),
            ("9.9.9.9:12038", 102),
        ] {
            peers.record_success(address.parse().unwrap(), Height(height), now - 10);
        }
        peers.record_success("208.67.222.222:12038".parse().unwrap(), Height(99), old);

        let mixed = assess_peer_target(&peers, &hns_core::network::mainnet(), now);
        assert_eq!(mixed.height, Some(101));
        assert_eq!(mixed.peer_groups, 3);
        assert!(!mixed.evidence_expired);
        assert_eq!(mixed.evidence_valid_until_unix, Some(11_190));

        for address in ["1.1.1.1:12038", "8.8.8.8:12038", "9.9.9.9:12038"] {
            let address = address.parse().unwrap();
            let height = peers.get(address).unwrap().last_height;
            peers.record_observed_height(address, height, old);
            // Newer proof/relay/transport activity must not refresh old header
            // evidence used to decide whether the local chain is current.
            peers.record_transport_success(address, now);
        }
        let expired = assess_peer_target(&peers, &hns_core::network::mainnet(), now);
        assert_eq!(expired.height, None);
        assert_eq!(expired.peer_groups, 0);
        assert!(expired.evidence_expired);
        assert_eq!(expired.evidence_valid_until_unix, None);
    }

    #[test]
    fn peer_target_deadline_is_when_the_fresh_quorum_will_be_lost() {
        let now = 10_000;
        let mut peers = PeerManager::default();
        for (address, height, observed_at) in [
            ("1.1.1.1:12038", 100, now - 100),
            ("8.8.8.8:12038", 101, now - 90),
            ("9.9.9.9:12038", 102, now - 80),
            ("208.67.222.222:12038", 103, now - 70),
        ] {
            peers.record_success(address.parse().unwrap(), Height(height), observed_at);
        }

        let target = assess_peer_target(&peers, &hns_core::network::mainnet(), now);
        let valid_until = now - 90 + LOCAL_CHAIN_TARGET_OBSERVATION_MAX_AGE_SECONDS;
        assert_eq!(target.peer_groups, 4);
        assert_eq!(target.evidence_valid_until_unix, Some(valid_until));

        let boundary = assess_peer_target(&peers, &hns_core::network::mainnet(), valid_until);
        assert!(boundary.height.is_some());
        assert_eq!(boundary.peer_groups, 3);
        assert_eq!(boundary.evidence_valid_until_unix, Some(valid_until));

        let expired = assess_peer_target(&peers, &hns_core::network::mainnet(), valid_until + 1);
        assert_eq!(expired.height, None);
        assert_eq!(expired.peer_groups, 2);
        assert!(expired.evidence_expired);
        assert_eq!(expired.evidence_valid_until_unix, None);
    }

    #[test]
    fn peer_target_ignores_legacy_height_without_header_observation_time() {
        let now = 10_000;
        let mut peers = PeerManager::default();
        for (address, height) in [
            ("1.1.1.1:12038", 100),
            ("8.8.8.8:12038", 101),
            ("9.9.9.9:12038", 102),
        ] {
            let peer = peers.upsert(address.parse().unwrap());
            peer.last_height = Height(height);
            peer.last_connected_at = Some(now);
            peer.successes = 1;
        }

        let target = assess_peer_target(&peers, &hns_core::network::mainnet(), now);

        assert_eq!(target.height, None);
        assert_eq!(target.peer_groups, 0);
        assert!(!target.evidence_expired);
        assert_eq!(target.evidence_valid_until_unix, None);
    }

    #[test]
    fn live_proof_peer_selection_ignores_zero_height_failed_peers() {
        let stale: SocketAddr = "1.1.1.2:12038".parse().unwrap();
        let current: SocketAddr = "1.1.1.3:12038".parse().unwrap();
        let private: SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        for _ in 0..32 {
            peers.record_transient_failure(stale);
        }
        peers.record_success(current, Height(336_034), 1_000);
        peers.record_success(private, Height(336_034), 1_000);
        let network = hns_core::network::mainnet();

        let selected = select_live_proof_peers(&peers, &network, 8, 1_100, Height(336_034));

        assert_eq!(selected, vec![current]);
    }

    #[test]
    fn sync_status_json_reports_peer_failures() {
        let status = NativeSyncStatus {
            network: NetworkKind::Mainnet,
            status: "peer_failed",
            attempted: 1,
            successful: 0,
            accepted: 0,
            failed: 1,
            peer_count: 1,
            peer_groups: 1,
            best_height: Some(0),
            best_peer_height: None,
            estimated_tip_height: Some(335_684),
            effective_target_height: None,
            lag_blocks: None,
            freshness: "unknown",
            freshness_threshold_blocks: LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG,
            tree_interval_blocks: 36,
            authoritative_tree_root_height: None,
            local_tree_root_height: None,
            tree_root_ready: None,
            blocks_until_authoritative_tree_root: None,
            target_source: "unknown",
            target_peer_groups: 0,
            target_evidence_expired: false,
            target_evidence_valid_until_unix: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some("all 1 attempted sync peers failed; see failures".to_owned()),
            failures: vec![NativePeerFailure {
                address: "127.0.0.1:12038".to_owned(),
                stage: "connect",
                error: "connection \"closed\"\n".to_owned(),
            }],
        };

        let json = status.to_json();

        assert!(json.contains(r#""status":"peer_failed""#));
        assert!(json.contains(r#""failed":1"#));
        assert!(json.contains(r#""estimatedTipHeight":335684"#));
        assert!(json.contains(r#""effectiveTargetHeight":null"#));
        assert!(json.contains(r#""lagBlocks":null"#));
        assert!(json.contains(r#""freshness":"unknown""#));
        assert!(json.contains(r#""freshnessThresholdBlocks":2"#));
        assert!(json.contains(r#""targetSource":"unknown""#));
        assert!(json.contains(r#""targetPeerGroups":0"#));
        assert!(json.contains(r#""targetEvidenceExpired":false"#));
        assert!(json.contains(r#""targetEvidenceValidUntilUnix":null"#));
        assert!(json.contains(r#""error":"all 1 attempted sync peers failed; see failures""#,));
        assert!(json.contains(
            r#""failures":[{"address":"127.0.0.1:12038","stage":"connect","error":"connection \"closed\"\n"}]"#,
        ));
    }

    #[test]
    fn sync_status_classifier_reports_up_to_date_and_peer_failed() {
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(335_591), Some(335_591)),
            "synced",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(45_000), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(92_000), None),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(93_344), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 4, false, Some(0), Some(335_684)),
            "peer_failed",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 2, false, Some(0), Some(335_684)),
            "attempted",
        );
        assert_eq!(
            classify_sync_status(0, 0, 0, 0, true, None, None),
            "seed_failed",
        );
        assert_eq!(classify_sync_status(0, 0, 0, 0, false, None, None), "idle");
    }

    #[test]
    fn sync_once_enforces_resource_cache_limit_and_clear_removes_cache() {
        let path = temp_dir_path("resource-cache-limit");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        let anchor_root = Hash::new([3; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    "alpha".to_owned(),
                    alpha_hash,
                    vec![1, 2, 3, 4, 5, 6],
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![7, 8])
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            2,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 2);

        let clear_json = clear_resolver_cache(path.to_str().unwrap());
        assert!(clear_json.contains(r#""status":"cleared""#));
        assert!(clear_json.contains(r#""resourceCacheEntries":0"#));
        assert!(clear_json.contains(r#""resourceCacheBytes":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_best_chain() {
        let path = temp_dir_path("resource-cache-reorg");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(hns_core::Hash::new([9; 32]), hns_core::Height(0)),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_keeps_resource_cache_entries_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-recent-canonical");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let older_root = Hash::new([3; 32]);
        let current_root = Hash::new([4; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[older_root, current_root]);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(older_root, heights[0]),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, heights[1]),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 0);
        assert_eq!(status.resource_cache_entries, 2);
        assert_eq!(status.resource_cache_bytes, 3);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-stale-tip");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let current_root = Hash::new([4; 32]);
        let current_height = store_best_header_with_tree_root(&base, current_root);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(BlockHeader::mainnet_genesis().tree_root, Height(0)),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, current_height),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            NetworkKind::Mainnet,
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 1);

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_cached_resource_anchor_and_records() {
        let path = temp_dir_path("proof-details-cached");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([8; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        store_peer_height(&base, anchor_height.0);
        let resource = owner_glue4_resource(&root_name, [127, 0, 0, 1]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(root_name.clone(), name_hash, resource.clone())
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let json = hns_proof_details(path.to_str().unwrap(), "www.welcome/");

        assert!(json.contains(r#""host":"www.welcome""#));
        assert!(json.contains(r#""name":"welcome""#));
        assert!(json.contains(&format!(r#""nameHash":"{}""#, name_hash.as_hash())));
        assert!(json.contains(r#""proofStatus":"verified""#));
        assert!(json.contains(r#""cacheStatus":"anchored_to_authoritative_tree_root""#));
        assert!(json.contains(&format!(r#""treeRoot":"{}""#, anchor_root)));
        assert!(json.contains(r#""blockHeight":1"#));
        assert!(json.contains(&format!(r#""resourceValueHex":"{}""#, hex_lower(&resource))));
        assert!(json.contains(r#""recordTypes":["A","NS"]"#));
        assert!(json.contains(r#""type":"NS""#));
        assert!(json.contains(r#""type":"A""#));
        assert!(json.contains(r#""currentTip":{"height":1"#));

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_missing_resource_cache() {
        let path = temp_dir_path("proof-details-missing-cache");

        let json = hns_proof_details(path.to_str().unwrap(), "missing");

        assert!(json.contains(r#""host":"missing""#));
        assert!(json.contains(r#""name":"missing""#));
        assert!(json.contains(r#""proofStatus":"unavailable""#));
        assert!(json.contains(r#""cacheStatus":"resource_cache_missing""#));
        assert!(json.contains(r#""resourceValueHex":null"#));
        assert!(json.contains(r#""error":"resource cache is not initialized""#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_status_json_escapes_errors() {
        let json = NativeSyncStatus::error("bad \"path\"\n".to_owned()).to_json();

        assert!(json.contains(r#""status":"error""#));
        assert!(json.contains(r#""error":"bad \"path\"\n""#));
    }

    #[test]
    fn sync_status_error_preserves_the_requested_network() {
        let json = NativeSyncStatus::error_for(NetworkKind::Testnet, "failed".to_owned()).to_json();

        assert!(json.contains(r#""network":"testnet""#));
        assert!(json.contains(r#""status":"error""#));
    }

    #[test]
    fn origin_response_suppresses_spoofed_hns_tls_policy_origin_headers() {
        let response = origin_response(OriginResponse {
            status: 200,
            headers: vec![("X-HNS-TLS-Policy".to_owned(), "origin".to_owned())],
            body: b"ok".to_vec(),
            dane_decision: DaneDecision::WebPkiFallback,
            tls_inspection: None,
        });
        let text = String::from_utf8(response).unwrap();

        assert!(!text.contains("X-HNS-TLS-Policy: origin\r\n"));
        assert!(text.contains("X-HNS-TLS-Policy: webpki-fallback\r\n"));
    }

    #[test]
    fn origin_response_suppresses_the_entire_reserved_hns_header_namespace() {
        let response = origin_response(OriginResponse {
            status: 200,
            headers: vec![(
                "x-hns-future-security-metadata".to_owned(),
                "origin-controlled".to_owned(),
            )],
            body: b"ok".to_vec(),
            dane_decision: DaneDecision::WebPkiFallback,
            tls_inspection: None,
        });
        let text = String::from_utf8(response).unwrap();

        assert!(
            !text
                .to_ascii_lowercase()
                .contains("x-hns-future-security-metadata")
        );
    }

    #[test]
    fn origin_response_suppresses_spoofed_security_path_and_emits_native_value() {
        let response = origin_response_with_resolver_policy_and_trace(
            OriginResponse {
                status: 200,
                headers: vec![(
                    HNS_SECURITY_PATH_HEADER.to_owned(),
                    "stateless-dane".to_owned(),
                )],
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::Matched(TlsaUsage::DaneEe),
                tls_inspection: None,
            },
            None,
            Some("dane-authoritative-doh"),
            "{}",
        );
        let text = String::from_utf8(response).unwrap();

        assert!(!text.contains("X-HNS-Security-Path: stateless-dane\r\n"));
        assert_eq!(
            text.matches("X-HNS-Security-Path: dane-authoritative-doh\r\n")
                .count(),
            1,
        );
    }

    #[test]
    fn upgrade_response_preserves_canonical_websocket_headers_only() {
        let response = upgrade_response_head_with_resolver_policy_and_trace(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: Upgrade, X-Hop\r\n\
              Upgrade: websocket\r\n\
              X-Hop: secret\r\n\
              X-HNS-Security-Path: spoofed\r\n\
              Sec-WebSocket-Accept: accepted\r\n\r\n",
            &DaneDecision::NoTlsa,
            None,
            "{}",
        );
        let text = String::from_utf8(response).unwrap();

        assert_eq!(text.matches("Connection: Upgrade\r\n").count(), 1);
        assert_eq!(text.matches("Upgrade: websocket\r\n").count(), 1);
        assert!(text.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(!text.contains("X-Hop:"));
        assert!(!text.contains("Connection: Upgrade, X-Hop"));
        assert!(!text.contains(HNS_SECURITY_PATH_HEADER));
    }

    #[test]
    fn origin_response_reports_hns_resolver_policy_after_tls_policy() {
        let response = origin_response_with_resolver_policy(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::Matched(hns_dane::TlsaUsage::DaneEe),
                tls_inspection: None,
            },
            Some("user-configured-recursive-hns-doh"),
        );
        let text = String::from_utf8(response).unwrap();

        assert!(
            text.contains("X-HNS-TLS-Policy: dane\r\nX-HNS-Resolver-Policy: user-configured-recursive-hns-doh\r\n",)
        );
    }

    #[test]
    fn gateway_headers_accept_only_the_validated_internal_recursive_hns_doh_url() {
        let configured = parse_gateway_headers(
            "X-HNS-Browser-DoH-Resolver: https://HNSDOH.COM:443/dns-query\r\n",
        )
        .unwrap();
        assert_eq!(
            configured
                .configured_hns_doh
                .map(|endpoint| endpoint.display()),
            Some("https://hnsdoh.com/dns-query".to_owned())
        );
        assert!(configured.headers.is_empty());

        let parsed = parse_gateway_headers(
            "Accept: text/html\r\n\
             X-HNS-Browser-Strict-Mode: 1\r\n\
             X-HNS-Browser-Stateless-DANE: 1\r\n\
             X-HNS-Security-Path: dane-authoritative-doh\r\n",
        )
        .unwrap();

        assert!(parsed.strict_hns_mode);
        assert!(parsed.stateless_dane_certificates);
        assert!(parsed.configured_hns_doh.is_none());
        assert_eq!(parsed.network, NetworkKind::Mainnet);
        assert_eq!(
            parsed.headers,
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
    }

    #[test]
    fn stateless_dane_roots_only_use_latest_forty_headers() {
        let base = temp_dir_path("stateless-dane-roots");
        std::fs::create_dir_all(&base).unwrap();
        let roots = (1u8..=41u8)
            .map(|byte| Hash::new([byte; 32]))
            .collect::<Vec<_>>();
        store_canonical_headers_with_tree_roots(&base, &roots);

        let recent = recent_stateless_dane_tree_roots(&base).unwrap();

        assert_eq!(recent.len(), MAX_STATELESS_DANE_ROOTS);
        assert!(!recent.contains(&roots[0].into_bytes()));
        assert!(recent.contains(&roots[1].into_bytes()));
        assert!(recent.contains(&roots[40].into_bytes()));
        cleanup_dir(&base);
    }

    #[test]
    fn authoritative_doh_uses_hns_proof_tlsa_without_webpki_fallback() {
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0x36; 32],
        };
        let endpoint = AuthoritativeDohEndpoint {
            ns: DnsName::from_ascii("ns1.denuoweb").unwrap(),
            host: "denuoweb".to_owned(),
            connect_addr: "35.212.156.128".parse().unwrap(),
            port: 8443,
            path_and_query: "/dns-query".to_owned(),
            tls_authentication: AuthoritativeDohTlsAuthentication::HnsProofTlsa(vec![
                record.clone(),
            ]),
        };

        let validation = authoritative_doh_tls_validation(&endpoint);

        assert_eq!(validation.mode, hns_dane::DomainTrustMode::HnsStrict);
        assert!(validation.dnssec_secure);
        assert_eq!(validation.tlsa_records, vec![record]);
        assert_eq!(validation.tlsa_source, Some(TlsaRecordSource::HnsProofTxt));
        assert_eq!(validation.service_port, 8443);
        assert_eq!(
            authoritative_doh_endpoint_display(&endpoint),
            "https://denuoweb:8443/dns-query via 35.212.156.128 [HNS-proof TLSA]"
        );
    }

    #[test]
    fn authoritative_doh_without_proof_tlsa_keeps_webpki_validation() {
        let endpoint = AuthoritativeDohEndpoint {
            ns: DnsName::from_ascii("ns1.welcome").unwrap(),
            host: "doh.example".to_owned(),
            connect_addr: "203.0.113.53".parse().unwrap(),
            port: 443,
            path_and_query: "/dns-query".to_owned(),
            tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
        };

        assert_eq!(
            authoritative_doh_tls_validation(&endpoint),
            TlsValidation::default()
        );
    }

    #[test]
    fn configured_recursive_hns_doh_url_rejects_unsafe_or_ambiguous_endpoints() {
        for value in [
            "http://hnsdoh.com/dns-query",
            "https://user@hnsdoh.com/dns-query",
            "https://hnsdoh.com/dns-query#fragment",
            "https://1.1.1.1/dns-query",
            "https://resolver.local/dns-query",
            "https://hnsdoh.com:53/dns-query",
        ] {
            assert!(
                parse_gateway_headers(&format!("X-HNS-Browser-DoH-Resolver: {value}\r\n")).is_err(),
                "{value}"
            );
        }
        assert!(
            normalize_configured_hns_doh_resolver(Some(&format!(
                "https://hnsdoh.com/{}",
                "a".repeat(MAX_CONFIGURED_HNS_DOH_URL_BYTES)
            )))
            .is_err()
        );
    }

    #[test]
    fn configured_recursive_hns_doh_request_requires_explicit_ip_and_keeps_webpki_hostname() {
        let endpoint = parse_configured_hns_doh_endpoint("https://hnsdoh.com/dns-query").unwrap();
        let request = configured_doh_origin_request(
            &endpoint,
            "203.0.113.53".parse().unwrap(),
            vec![0x12, 0x34],
        );

        assert_eq!(request.scheme, "https");
        assert_eq!(request.host, "hnsdoh.com");
        assert_eq!(request.connect_host.as_deref(), Some("203.0.113.53"));
        assert_eq!(request.port, 443);
        assert_eq!(request.path_and_query, "/dns-query");
        assert_eq!(request.tls, TlsValidation::default());
        assert_eq!(request.body, vec![0x12, 0x34]);
    }

    #[test]
    fn gateway_headers_parse_internal_network() {
        let parsed = parse_gateway_headers("X-HNS-Browser-Network: regtest\r\n").unwrap();

        assert_eq!(parsed.network, NetworkKind::Regtest);
        assert!(parsed.headers.is_empty());
    }

    #[test]
    fn gateway_headers_reject_invalid_network() {
        assert_eq!(
            parse_gateway_headers("X-HNS-Browser-Network: staging\r\n")
                .err()
                .as_deref(),
            Some("Handshake network is invalid")
        );
    }

    #[test]
    fn gateway_headers_reject_legacy_hns_doh_enablement() {
        assert_eq!(
            parse_gateway_headers("X-HNS-Browser-Legacy-HNS-DoH: 1\r\n")
                .err()
                .as_deref(),
            Some("legacy HNS DoH compatibility is prohibited")
        );
        assert!(parse_gateway_headers("X-HNS-Browser-Legacy-HNS-DoH: 0\r\n").is_ok());
    }

    #[test]
    fn origin_response_includes_resolution_trace_headers() {
        let response = origin_response_with_resolver_policy_and_trace(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            },
            None,
            None,
            r#"{"mode":"strict","fallback":{"used":false}}"#,
        );
        let text = String::from_utf8(response).unwrap();

        assert!(text.contains("X-HNS-Resolver-Mode: strict\r\n"));
        assert!(text.contains("X-HNS-DoH-Fallback: no\r\n"));
        assert!(text.contains(
            "X-HNS-Resolution-Trace: {\"mode\":\"strict\",\"fallback\":{\"used\":false}}\r\n",
        ));
    }

    #[test]
    fn resolution_trace_reports_authoritative_dns_attempts() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("nathan.woodburn".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "timeout".to_owned(),
            elapsed_ms: 901,
            error: Some("operation timed out".to_owned()),
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("nathan.woodburn".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "transport_error".to_owned(),
            elapsed_ms: 12,
            error: Some("connection refused".to_owned()),
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "detected".to_owned(),
            elapsed_ms: 7,
            error: Some(
                "received a matching DNS reply from a non-routable TEST-NET destination".to_owned(),
            ),
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnsTransport(
                "operation timed out".to_owned(),
            ))),
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"timeout","tcp53":"transport_error","doh":"not_attempted","p2pDnsRelay":"not_attempted"}"#
        ));
        assert!(trace.contains(r#""nameserverCandidates":["192.0.2.53:53"]"#));
        assert!(trace.contains(r#""port53Interception":"detected""#));
        assert!(trace.contains(r#""protocol":"udp53","server":"192.0.2.53:53""#));
        assert!(trace.contains(r#""protocol":"udp53","server":"192.0.2.53:53","root":"hns""#));
        assert!(trace.contains(r#""questionName":"nathan.woodburn","questionType":1"#));
        assert!(trace.contains(r#""status":"timeout""#));
        assert!(trace.contains(r#""elapsedMs":901"#));
    }

    #[test]
    fn security_path_uses_effective_svcb_port_and_last_successful_tlsa_transport() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "https",
            host: "denuoweb",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let tlsa_owner = "_8443._tcp.denuoweb";
        let events = vec![
            DnsTraceEvent {
                protocol: "authoritative_doh",
                server: "https://denuoweb:8443/dns-query".to_owned(),
                question_name: Some(tlsa_owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 10,
                error: None,
            },
            DnsTraceEvent {
                protocol: "user_configured_recursive_hns_doh",
                server: "https://resolver.example/dns-query".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::A.code()),
                status: "ok".to_owned(),
                elapsed_ms: 11,
                error: None,
            },
            DnsTraceEvent {
                protocol: "tcp53",
                server: "35.212.156.128:53".to_owned(),
                question_name: Some(tlsa_owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 12,
                error: None,
            },
        ];

        assert_eq!(
            security_path_name(
                &input,
                8443,
                TlsaTransport::Tcp,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                Some(Namespace::Hns),
                &events,
            ),
            Some("dane-authoritative-dns53"),
        );
    }

    #[test]
    fn security_path_uses_only_the_selected_roots_dns_events() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "https",
            host: "collision.example",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let owner = "_443._tcp.collision.example";
        let events = vec![
            DnsTraceEvent {
                protocol: "authoritative_doh",
                server: "https://ns.collision.example/dns-query".to_owned(),
                question_name: Some(owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 5,
                error: None,
            },
            DnsTraceEvent {
                protocol: "icann_doh",
                server: "https://cloudflare-dns.com/dns-query via 1.1.1.1".to_owned(),
                question_name: Some(owner.to_owned()),
                question_type: Some(RecordType::Tlsa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 7,
                error: None,
            },
        ];

        assert_eq!(
            security_path_name(
                &input,
                443,
                TlsaTransport::Tcp,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                Some(Namespace::Hns),
                &events,
            ),
            Some("dane-authoritative-doh"),
        );
        assert_eq!(
            security_path_name(
                &input,
                443,
                TlsaTransport::Tcp,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                Some(Namespace::Icann),
                &events,
            ),
            Some("dane-icann-doh"),
        );
    }

    #[test]
    fn resolution_trace_retains_both_roots_attempts_when_icann_is_selected() {
        let dns_trace = dns_trace_with_selected_namespace(Namespace::Icann);
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "203.0.113.53:53".to_owned(),
            question_name: Some("collision.dualroot".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 5,
            error: None,
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "icann_doh",
            server: "https://cloudflare-dns.com/dns-query via 1.1.1.1".to_owned(),
            question_name: Some("collision.dualroot".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 7,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "http",
                host: "collision.dualroot",
                port: 80,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("collision.dualroot").unwrap(),
                records: vec![address_record("collision.dualroot", [8, 8, 8, 8])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""protocol":"tcp53","server":"203.0.113.53:53","root":"hns""#,));
        assert!(trace.contains(
            r#""protocol":"icann_doh","server":"https://cloudflare-dns.com/dns-query via 1.1.1.1","root":"icann""#,
        ));
        assert!(trace.contains(r#""nameClass":"icann""#));
    }

    #[test]
    fn security_path_distinguishes_user_configured_doh_and_actual_stateless_dane() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "https",
            host: "denuoweb",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let events = vec![DnsTraceEvent {
            protocol: "user_configured_recursive_hns_doh",
            server: "https://resolver.example/dns-query".to_owned(),
            question_name: Some("_443._tcp.denuoweb".to_owned()),
            question_type: Some(RecordType::Tlsa.code()),
            status: "ok".to_owned(),
            elapsed_ms: 10,
            error: None,
        }];

        assert_eq!(
            security_path_name(
                &input,
                input.port,
                TlsaTransport::Tcp,
                &DaneDecision::Matched(TlsaUsage::DaneEe),
                Some(Namespace::Hns),
                &events,
            ),
            Some("dane-user-configured-recursive-hns-doh"),
        );
        assert_eq!(
            security_path_name(
                &input,
                input.port,
                TlsaTransport::Tcp,
                &DaneDecision::StatelessMatched(TlsaUsage::DaneEe),
                Some(Namespace::Hns),
                &events,
            ),
            Some("stateless-dane"),
        );
    }

    #[test]
    fn http_security_path_uses_later_aaaa_transport_after_empty_a_lookup() {
        let input = GatewayHttpRequestInput {
            data_dir: "/tmp",
            method: "GET",
            scheme: "http",
            host: "denuoweb",
            port: 80,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let events = vec![
            DnsTraceEvent {
                protocol: "authoritative_doh",
                server: "https://denuoweb:8443/dns-query".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::A.code()),
                status: "ok".to_owned(),
                elapsed_ms: 10,
                error: None,
            },
            DnsTraceEvent {
                protocol: "tcp53",
                server: "35.212.156.128:53".to_owned(),
                question_name: Some("denuoweb".to_owned()),
                question_type: Some(RecordType::Aaaa.code()),
                status: "ok".to_owned(),
                elapsed_ms: 12,
                error: None,
            },
        ];

        assert_eq!(
            security_path_name(
                &input,
                input.port,
                TlsaTransport::Tcp,
                &DaneDecision::NoTlsa,
                Some(Namespace::Hns),
                &events,
            ),
            Some("hns-authoritative-dns53"),
        );
    }

    fn dns_trace_with_selected_namespace(namespace: Namespace) -> DnsTraceRecorder {
        let trace = DnsTraceRecorder::default();
        let (outcome, selected, hns_state, icann_state) = match namespace {
            Namespace::Hns => ("hnsOnly", "hns", "present", "absent"),
            Namespace::Icann => ("icannOnly", "icann", "absent", "present"),
        };
        trace.record_namespace_resolution(
            format!(
                r#"{{"schemaVersion":2,"outcome":"{outcome}","selected":"{selected}","reason":"onlyAvailableRoot","fingerprint":"test-fixture","divergenceMask":null,"hnsState":"{hns_state}","icannState":"{icann_state}","hns":{{"state":"{hns_state}","rcode":null,"denial":null,"failure":null}},"icann":{{"state":"{icann_state}","rcode":null,"denial":null,"failure":null}}}}"#
            ),
            Some(namespace),
        );
        trace
    }

    #[test]
    fn resolution_trace_reports_hns_resource_source() {
        let dns_trace = dns_trace_with_selected_namespace(Namespace::Hns);
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [35, 212, 156, 128])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"hns_resource""#));
        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"not_attempted","tcp53":"not_attempted","doh":"not_attempted","p2pDnsRelay":"not_attempted"}"#
        ));
    }

    #[test]
    fn resolution_trace_reports_later_selected_aaaa_origin_address() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "http",
                host: "crewball",
                port: 80,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: Vec::new(),
                secure: true,
            }),
            TlsTraceInput {
                origin_address: Some("2001:db8::20"),
                ..TlsTraceInput::default()
            },
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""originAddress":"found""#));
    }

    #[test]
    fn resolution_trace_reports_authoritative_doh_source() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.record_namespace_resolution(
            dns_trace_with_selected_namespace(Namespace::Hns).namespace_resolution_json(),
            Some(Namespace::Hns),
        );
        dns_trace.push(DnsTraceEvent {
            protocol: "authoritative_doh",
            server: "https://ns1.crewball/dns-query via 203.0.113.53".to_owned(),
            question_name: Some("crewball".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [203, 0, 113, 20])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"authoritative_doh""#));
        assert!(trace.contains(
            r#""authoritativeDns":{"udp53":"not_attempted","tcp53":"not_attempted","doh":"ok","p2pDnsRelay":"not_attempted"}"#
        ));
    }

    #[test]
    fn resolution_trace_keeps_p2p_relay_distinct_from_third_party_doh() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.record_namespace_resolution(
            dns_trace_with_selected_namespace(Namespace::Hns).namespace_resolution_json(),
            Some(Namespace::Hns),
        );
        dns_trace.push(DnsTraceEvent {
            protocol: "p2p_dns_relay",
            server: "203.0.113.80:12038".to_owned(),
            question_name: Some("legacy.relaytest".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 31,
            error: None,
        });
        dns_trace.record_relay(DnsRelayTraceMetadata {
            peer: Some("203.0.113.80:12038".parse().unwrap()),
            retries: 1,
            service_advertised: Some(true),
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "http",
                host: "legacy.relaytest",
                port: 80,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("legacy.relaytest").unwrap(),
                records: vec![address_record("legacy.relaytest", [203, 0, 113, 44])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"p2p_dns_relay""#));
        assert!(trace.contains(
            r#""p2pDnsRelay":{"attempted":true,"peer":"203.0.113.80:12038","serviceAdvertised":true,"retryCount":1,"error":null}"#
        ));
        assert!(!trace.contains(r#""resolutionSource":"user_configured_recursive_hns_doh""#));
    }

    #[test]
    fn resolution_trace_source_uses_exact_address_question_not_other_doh_success() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.record_namespace_resolution(
            dns_trace_with_selected_namespace(Namespace::Hns).namespace_resolution_json(),
            Some(Namespace::Hns),
        );
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "203.0.113.53:53".to_owned(),
            question_name: Some("crewball".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "authoritative_doh",
            server: "https://crewball:8443/dns-query via 203.0.113.53".to_owned(),
            question_name: Some("_443._tcp.crewball".to_owned()),
            question_type: Some(RecordType::Tlsa.code()),
            status: "ok".to_owned(),
            elapsed_ms: 20,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "crewball",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("crewball").unwrap(),
                records: vec![address_record("crewball", [203, 0, 113, 20])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""resolutionSource":"authoritative_dns""#));
    }

    #[test]
    fn canonical_transport_requires_the_exact_selected_plan_question() {
        let now = now_unix_seconds();
        let host = CanonicalHost::parse("exacttransport").unwrap();
        let query = OriginQuery::new(
            host.clone(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Hns,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host.clone(),
            endpoints: vec!["203.0.113.44:80".parse().unwrap()],
            service: default_service_binding(&query, &host).unwrap(),
            tls_policy: TlsTrustPolicy::Cleartext,
            tlsa_records: Vec::new(),
            provenance: EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [61; 32],
                height: 10,
            },
            freshness: Freshness::new(now, now + 60).unwrap(),
        })
        .unwrap();
        let trace = DnsTraceRecorder::default();
        trace.push(DnsTraceEvent {
            protocol: "authoritative_doh",
            server: "https://unrelated/dns-query".to_owned(),
            question_name: Some("unrelated".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 1,
            error: None,
        });
        assert_eq!(
            canonical_hns_actual_transport_for_plan(&query, &plan, &trace),
            Err(CanonicalStatusUnavailableReason::EvidenceUnavailable)
        );

        assert_eq!(
            canonical_hns_actual_transport_for_plan(&query, &plan, &DnsTraceRecorder::default()),
            Ok(CanonicalResolutionTransport::LocalHnsProof)
        );

        trace.push(DnsTraceEvent {
            protocol: "p2p_dns_relay",
            server: "203.0.113.80:12038".to_owned(),
            question_name: Some(host.as_str().to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 2,
            error: None,
        });
        assert_eq!(
            canonical_hns_actual_transport_for_plan(&query, &plan, &trace),
            Ok(CanonicalResolutionTransport::HandshakeP2pDnsRelay)
        );

        let configured_trace = DnsTraceRecorder::default();
        configured_trace.push(DnsTraceEvent {
            protocol: "user_configured_recursive_hns_doh",
            server: "https://hnsdoh.com/dns-query via 203.0.113.53".to_owned(),
            question_name: Some(host.as_str().to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 3,
            error: None,
        });
        assert_eq!(
            canonical_hns_actual_transport_for_plan(&query, &plan, &configured_trace),
            Ok(CanonicalResolutionTransport::UserConfiguredRecursiveHnsDoh)
        );
    }

    #[test]
    fn canonical_failure_status_retains_root_and_post_selection_dane_evidence() {
        let (data_dir, runtime, _latest_height) =
            runtime_with_current_mainnet_authority("canonical-failure-status");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let now = now_unix_seconds();
        let host = CanonicalHost::parse("failure-status.example").unwrap();
        let query = OriginQuery::new(
            host.clone(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );

        let classification = ClassificationError::RootFailed {
            hns: RootResolutionState::Present,
            icann: RootResolutionState::Failed(RootFailure::new(
                Namespace::Icann,
                query.clone(),
                RootFailureKind::BogusDnssec,
                None,
            )),
        };
        let failure = GatewayFailure::from(GatewayError::Resolver(
            ResolverError::NamespaceClassification(classification),
        ));
        let CanonicalStatusAvailability::AvailableWithRootStates {
            status,
            root_states,
        } = canonical_status_for_gateway_failure(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            &failure,
            &DnsTraceRecorder::default(),
        )
        else {
            panic!("typed ICANN root failure must be representable");
        };
        assert_eq!(
            root_states,
            CanonicalRootResolutionStates::new(
                RootResolutionDisposition::Present,
                RootResolutionDisposition::Failed,
            )
        );
        assert_eq!(
            status.actual_transport(),
            CanonicalResolutionTransport::ValidatingIcannDoh
        );
        assert_eq!(
            status.icann_root_failure(),
            Some(RootFailureKind::BogusDnssec)
        );
        assert_eq!(
            status.icann_tls_action(),
            Some(CanonicalIcannTlsAction::FailClosed)
        );
        assert_eq!(
            status.icann_dnssec_status(),
            Some(CanonicalIcannDnssecStatus::Bogus)
        );
        assert_eq!(status.evidence().dnssec, CanonicalEvidenceState::Failed);
        assert!(!format!("{status:?}").contains(host.as_str()));

        let hns_failure = GatewayFailure::from(GatewayError::Resolver(
            ResolverError::NamespaceClassification(ClassificationError::RootFailed {
                hns: RootResolutionState::Failed(RootFailure::new(
                    Namespace::Hns,
                    query.clone(),
                    RootFailureKind::StaleHnsAnchor,
                    None,
                )),
                icann: RootResolutionState::Absent,
            }),
        ));
        let CanonicalStatusAvailability::AvailableWithRootStates {
            status,
            root_states,
        } = canonical_status_for_gateway_failure(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            &hns_failure,
            &DnsTraceRecorder::default(),
        )
        else {
            panic!("typed HNS root failure must be representable");
        };
        assert_eq!(
            root_states,
            CanonicalRootResolutionStates::new(
                RootResolutionDisposition::Failed,
                RootResolutionDisposition::Absent,
            )
        );
        assert_eq!(
            status.actual_transport(),
            CanonicalResolutionTransport::Unavailable
        );
        assert_eq!(
            status.hns_root_failure(),
            Some(RootFailureKind::StaleHnsAnchor)
        );

        let both_failed = GatewayFailure::from(GatewayError::Resolver(
            ResolverError::NamespaceClassification(ClassificationError::RootFailed {
                hns: RootResolutionState::Failed(RootFailure::new(
                    Namespace::Hns,
                    query.clone(),
                    RootFailureKind::Transport,
                    None,
                )),
                icann: RootResolutionState::Failed(RootFailure::new(
                    Namespace::Icann,
                    query.clone(),
                    RootFailureKind::BogusDnssec,
                    None,
                )),
            }),
        ));
        let CanonicalStatusAvailability::AvailableWithRootStates {
            status,
            root_states,
        } = canonical_status_for_gateway_failure(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            &both_failed,
            &DnsTraceRecorder::default(),
        )
        else {
            panic!("two typed root failures must be representable");
        };
        assert_eq!(
            root_states,
            CanonicalRootResolutionStates::new(
                RootResolutionDisposition::Failed,
                RootResolutionDisposition::Failed,
            )
        );
        assert_eq!(status.hns_root_failure(), Some(RootFailureKind::Transport));
        assert_eq!(
            status.icann_root_failure(),
            Some(RootFailureKind::BogusDnssec)
        );

        let freshness = Freshness::new(now, now + 60).unwrap();
        let hns_absence = ValidatedAbsence::new(
            Namespace::Hns,
            query.clone(),
            AbsenceKind::HnsCurrentUrkelNonInclusion,
            EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [65; 32],
                height: 65,
            },
            freshness,
        )
        .unwrap();
        let icann_plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host.clone(),
            endpoints: vec!["203.0.113.65:443".parse().unwrap()],
            service: default_service_binding(&query, &host).unwrap(),
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: vec![
                CanonicalTlsa::new({
                    let mut rdata = vec![3, 1, 1];
                    rdata.extend_from_slice(&[65; 32]);
                    rdata
                })
                .unwrap(),
            ],
            provenance: EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        })
        .unwrap();
        let decision = decide_namespace(
            &query,
            RootLookup::Absent(hns_absence),
            RootLookup::Present(icann_plan),
            SelectionPolicy::default(),
            now,
        )
        .unwrap();
        let expected_fingerprint = *decision_fingerprint(&decision).as_bytes();
        let failure = GatewayFailure::with_namespace_decision(
            GatewayError::Transport(TransportError::DaneFailed),
            decision.clone(),
        );
        let CanonicalStatusAvailability::Available(status) = canonical_status_for_gateway_failure(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            &failure,
            &DnsTraceRecorder::default(),
        ) else {
            panic!("post-selection DANE failure must be representable");
        };
        assert_eq!(status.namespace_outcome(), Some(OutcomeKind::IcannOnly));
        assert_eq!(status.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(status.decision_fingerprint(), Some(expected_fingerprint));
        assert_eq!(status.icann_root_failure(), None);
        assert_eq!(
            status.icann_tls_action(),
            Some(CanonicalIcannTlsAction::FailClosed)
        );
        assert_eq!(status.evidence().dane, CanonicalEvidenceState::Failed);
        assert_eq!(
            status.evidence().origin_sni,
            CanonicalEvidenceState::Unavailable
        );

        let generic_tls_failure = GatewayFailure::with_namespace_decision(
            GatewayError::Transport(TransportError::Tls(
                "generic TLS handshake failure".to_owned(),
            )),
            decision,
        );
        assert_eq!(
            canonical_status_for_gateway_failure(
                &runtime,
                stamp,
                NetworkKind::Mainnet,
                &generic_tls_failure,
                &DnsTraceRecorder::default(),
            ),
            CanonicalStatusAvailability::Unavailable(
                CanonicalStatusUnavailableReason::EvidenceUnavailable
            )
        );

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn production_ordinary_and_tunnel_failures_retain_request_local_neither() {
        let (data_dir, runtime) =
            runtime_with_cached_dual_root_absence("canonical-neither-error-status");
        let proxy = runtime.start_proxy("missing").unwrap();
        let backend = runtime.proxy_backend();
        let ordinary_request = LoopbackProxyRequest {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "missing".to_owned(),
            port: 80,
            path_and_query: "/".to_owned(),
            headers: vec![ProxyHeader::new("Host", "missing")],
            body: ProxyRequestBody::Empty,
        };
        let ordinary_response = backend
            .execute(ordinary_request, &ProxyCancellationToken::new())
            .unwrap();
        assert_eq!(ordinary_response.head.status_code, 404);
        assert_eq!(ordinary_response.head.reason_phrase, "Origin Not Found");

        let take_neither_fingerprint = |response: &ProxyResponse, boundary: &str| {
            let observation_id = response.head.observation_id.unwrap();
            let Some(CanonicalStatusObservation {
                tuple,
                status: CanonicalStatusAvailability::Available(status),
                ..
            }) = runtime
                .inner
                .canonical_statuses
                .take(observation_id, &runtime.inner.canonical_authority)
            else {
                panic!("{boundary} error must publish a typed Neither status");
            };
            assert_eq!(status.namespace_outcome(), Some(OutcomeKind::Neither));
            assert_eq!(status.selected_namespace(), None);
            assert_eq!(
                status.actual_transport(),
                CanonicalResolutionTransport::Unavailable
            );
            assert_eq!(status.hns_root_failure(), None);
            assert_eq!(status.icann_root_failure(), None);
            assert_eq!(tuple.event_sequence(), status.event_sequence());
            let fingerprint = status
                .decision_fingerprint()
                .expect("Neither status must retain its exact decision fingerprint");
            assert_ne!(fingerprint, [0; 32]);
            fingerprint
        };
        let ordinary_fingerprint = take_neither_fingerprint(&ordinary_response, "ordinary");

        let tunnel_request = LoopbackProxyRequest {
            method: "GET".to_owned(),
            scheme: "ws".to_owned(),
            host: "missing".to_owned(),
            port: 80,
            path_and_query: "/socket".to_owned(),
            headers: vec![
                ProxyHeader::new("Host", "missing"),
                ProxyHeader::new("Connection", "Upgrade"),
                ProxyHeader::new("Upgrade", "websocket"),
                ProxyHeader::new("Sec-WebSocket-Key", "key"),
                ProxyHeader::new("Sec-WebSocket-Version", "13"),
            ],
            body: ProxyRequestBody::Empty,
        };
        let opened = backend
            .open_tunnel(tunnel_request, &ProxyCancellationToken::new())
            .unwrap();
        let ProxyTunnelOpen::Response(tunnel_response) = opened else {
            panic!("a completed Neither decision must return a stamped tunnel error response");
        };
        assert_eq!(tunnel_response.head.status_code, 404);
        assert_eq!(tunnel_response.head.reason_phrase, "Origin Not Found");
        let tunnel_fingerprint = take_neither_fingerprint(&tunnel_response, "tunnel");
        assert_ne!(
            ordinary_fingerprint, tunnel_fingerprint,
            "the exact decision fingerprint must remain bound to each request scheme"
        );

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn browser_webpki_passthrough_status_has_no_rust_tls_validation_claim() {
        let (data_dir, runtime, _latest_height) =
            runtime_with_current_mainnet_authority("canonical-webpki-connect-status");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let decision = selected_tls_test_decision(
            Namespace::Icann,
            TlsTrustPolicy::WebPkiAuthenticatedAbsence,
        );
        let request = tls_origin_request_for_decision(&decision);

        let status = try_canonical_status_for_gateway_success(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            Some(&decision),
            true,
            &request,
            &DaneDecision::WebPkiFallback,
            OriginTlsObservation::BrowserWebPkiPassthrough,
            &DnsTraceRecorder::default(),
        )
        .unwrap();

        assert_eq!(status.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(
            status.icann_tls_action(),
            Some(CanonicalIcannTlsAction::WebPkiAuthenticatedAbsence)
        );
        assert_eq!(
            status.evidence().origin_sni,
            CanonicalEvidenceState::NotAttempted
        );
        assert_eq!(status.evidence().tlsa, CanonicalEvidenceState::Unavailable);
        assert_eq!(
            try_canonical_status_for_gateway_success(
                &runtime,
                stamp,
                NetworkKind::Mainnet,
                Some(&decision),
                true,
                &request,
                &DaneDecision::WebPkiFallback,
                OriginTlsObservation::RustValidated(false),
                &DnsTraceRecorder::default(),
            ),
            Err(CanonicalStatusUnavailableReason::EvidenceUnavailable)
        );
        let insertion_attempted = AtomicBool::new(false);
        assert!(matches!(
            publishable_webpki_connect_observation(
                CanonicalStatusAvailability::Unavailable(
                    CanonicalStatusUnavailableReason::EvidenceUnavailable,
                ),
                |_| {
                    insertion_attempted.store(true, Ordering::Release);
                    Some(1)
                },
            ),
            Err(ProxyConnectOpen::WebPkiUnavailable)
        ));
        assert!(!insertion_attempted.load(Ordering::Acquire));
        assert!(matches!(
            publishable_webpki_connect_observation(
                CanonicalStatusAvailability::Available(Box::new(status)),
                |_| None,
            ),
            Err(ProxyConnectOpen::WebPkiUnavailable)
        ));

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn selected_webpki_transport_failure_is_not_downgraded_to_local_tls() {
        let webpki = selected_tls_test_decision(
            Namespace::Icann,
            TlsTrustPolicy::WebPkiAuthenticatedAbsence,
        );
        let webpki_failure = GatewayFailure::with_namespace_decision(
            GatewayError::Transport(TransportError::Io(
                "selected origin socket refused".to_owned(),
            )),
            webpki,
        );
        assert!(gateway_failure_selected_browser_webpki(&webpki_failure));

        for namespace in [Namespace::Icann, Namespace::Hns] {
            let dane = selected_tls_test_decision(namespace, TlsTrustPolicy::Dane);
            let dane_failure = GatewayFailure::with_namespace_decision(
                GatewayError::Transport(TransportError::DaneFailed),
                dane,
            );
            assert!(!gateway_failure_selected_browser_webpki(&dane_failure));
        }
    }

    #[test]
    fn browser_tls_passthrough_cannot_attest_icann_dane_or_hns_dane() {
        let (data_dir, runtime, _latest_height) =
            runtime_with_current_mainnet_authority("canonical-dane-connect-intercept");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();

        for namespace in [Namespace::Icann, Namespace::Hns] {
            let decision = selected_tls_test_decision(namespace, TlsTrustPolicy::Dane);
            let request = tls_origin_request_for_decision(&decision);
            assert_eq!(
                try_canonical_status_for_gateway_success(
                    &runtime,
                    stamp,
                    NetworkKind::Mainnet,
                    Some(&decision),
                    true,
                    &request,
                    &DaneDecision::Matched(TlsaUsage::DaneEe),
                    OriginTlsObservation::BrowserWebPkiPassthrough,
                    &DnsTraceRecorder::default(),
                ),
                Err(CanonicalStatusUnavailableReason::EvidenceUnavailable),
                "{namespace:?} DANE must stay on the local Rust TLS intercept path"
            );
        }

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn canonical_status_uses_decision_fingerprint_and_selected_plan_anchor() {
        let (data_dir, runtime, _latest_height) =
            runtime_with_current_mainnet_authority("canonical-status-selected-plan");
        let proxy = runtime.start_proxy("welcome").unwrap();
        let stamp = runtime
            .inner
            .canonical_authority
            .admit(proxy.generation())
            .unwrap();
        let now = now_unix_seconds();
        let host = CanonicalHost::parse("selectedanchor").unwrap();
        let query = OriginQuery::new(
            host.clone(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let freshness = Freshness::new(now, now + 60).unwrap();
        let selected_tree_root = [63; 32];
        let selected_height = 777;
        let hns = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Hns,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host.clone(),
            endpoints: vec!["203.0.113.63:80".parse().unwrap()],
            service: default_service_binding(&query, &host).unwrap(),
            tls_policy: TlsTrustPolicy::Cleartext,
            tlsa_records: Vec::new(),
            provenance: EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: selected_tree_root,
                height: selected_height,
            },
            freshness,
        })
        .unwrap();
        let icann = ValidatedAbsence::new(
            Namespace::Icann,
            query.clone(),
            AbsenceKind::DnssecAuthenticatedNxDomain,
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        )
        .unwrap();
        let decision = decide_namespace(
            &query,
            RootLookup::Present(hns),
            RootLookup::Absent(icann),
            SelectionPolicy::default(),
            now,
        )
        .unwrap();
        let expected_fingerprint = *decision_fingerprint(&decision).as_bytes();
        let mut origin_request = OriginRequest {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: host.as_str().to_owned(),
            connect_host: Some("203.0.113.63".to_owned()),
            port: 80,
            path_and_query: "/".to_owned(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        origin_request.tls.namespace_fingerprint = Some(decision_fingerprint(&decision).to_hex());
        let trace = DnsTraceRecorder::default();
        trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "203.0.113.53:53".to_owned(),
            question_name: Some(host.as_str().to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 1,
            error: None,
        });

        let status = try_canonical_status_for_gateway_success(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            Some(&decision),
            true,
            &origin_request,
            &DaneDecision::NoTlsa,
            OriginTlsObservation::RustValidated(false),
            &trace,
        )
        .unwrap();
        assert_eq!(
            status.actual_transport(),
            CanonicalResolutionTransport::DirectAuthoritativeUdp
        );
        assert_eq!(status.decision_fingerprint(), Some(expected_fingerprint));
        assert_eq!(
            status.chain_anchor(),
            Some(CanonicalChainAnchor {
                height: selected_height,
                tree_root: selected_tree_root,
            })
        );

        let local_proof_status = try_canonical_status_for_gateway_success(
            &runtime,
            stamp,
            NetworkKind::Mainnet,
            Some(&decision),
            true,
            &origin_request,
            &DaneDecision::NoTlsa,
            OriginTlsObservation::RustValidated(false),
            &DnsTraceRecorder::default(),
        )
        .unwrap();
        assert_eq!(
            local_proof_status.actual_transport(),
            CanonicalResolutionTransport::LocalHnsProof
        );
        assert_eq!(
            local_proof_status.decision_fingerprint(),
            Some(expected_fingerprint)
        );

        proxy.stop();
        cleanup_dir(&data_dir);
    }

    #[test]
    fn resolution_trace_reports_icann_doh_source_without_hns_proof() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.record_namespace_resolution(
            dns_trace_with_selected_namespace(Namespace::Icann).namespace_resolution_json(),
            Some(Namespace::Icann),
        );
        dns_trace.push(DnsTraceEvent {
            protocol: "icann_doh",
            server: "https://cloudflare-dns.com/dns-query".to_owned(),
            question_name: Some("dane-test.denuoweb.com".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 42,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "dane-test.denuoweb.com",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("dane-test.denuoweb.com").unwrap(),
                records: vec![address_record(
                    "dane-test.denuoweb.com",
                    [35, 212, 156, 128],
                )],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""nameClass":"icann""#));
        assert!(trace.contains(r#""hnsProof":"not_applicable""#));
        assert!(trace.contains(r#""resolutionSource":"trusted_icann_doh""#));
        assert!(trace.contains(r#""protocol":"icann_doh""#));
        assert!(!trace.contains(r#""resolutionSource":"authoritative_doh""#));
    }

    #[test]
    fn resolution_trace_reports_cached_hns_proof_when_later_resolution_fails() {
        let path = temp_dir_path("trace-cached-proof-after-resolution-failure");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        resources
            .insert(VerifiedResourceValue::inclusion(
                root_name.clone(),
                name_hash,
                owner_glue4_resource(&root_name, [127, 0, 0, 1]),
            ))
            .unwrap();

        let dns_trace = dns_trace_with_selected_namespace(Namespace::Hns);
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "https",
                host: "www.welcome",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Strict,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnsTransport(
                "operation timed out".to_owned(),
            ))),
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""root":"welcome""#));
        assert!(trace.contains(r#""hnsProof":"verified""#));
        cleanup_dir(&path);
    }

    #[test]
    fn cached_non_inclusion_with_unknown_currentness_is_not_reported_as_not_found() {
        let path = temp_dir_path("trace-unknown-currentness-negative-proof");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let proof_root = Hash::new([41; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let root_name = "possibly-new".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .unwrap()
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();

        assert_eq!(
            hns_cached_proof_trace_status(path.to_str().unwrap(), NetworkKind::Mainnet, &root_name,),
            Some("currentness_unknown"),
        );
        cleanup_dir(&path);
    }

    #[test]
    fn resolution_trace_reports_stale_chain_fallback_reason_and_heights() {
        let path = temp_dir_path("trace-stale-chain-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let proof_root = Hash::new([12; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let target_height = 37;
        store_peer_height(&base, target_height);
        let marker = FallbackMarker::default();
        marker.mark("local_chain_not_current");

        let dns_trace = dns_trace_with_selected_namespace(Namespace::Hns);
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "https",
                host: "future",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::LocalChainNotCurrent)),
            &marker,
            &dns_trace,
        );

        assert!(trace.contains(r#""hnsProof":"stale""#));
        assert!(trace.contains(&format!(r#""localBestHeight":{}"#, proof_height.0)));
        assert!(trace.contains(&format!(r#""targetHeight":{}"#, target_height)));
        assert!(trace.contains(r#""estimatedTargetHeight":"#));
        assert!(trace.contains(r#""localChainStale":true"#));
        assert!(trace.contains(
            r#""fallback":{"used":true,"type":"USER_CONFIGURED_RECURSIVE_HNS_DOH","reason":"local_chain_not_current"}"#
        ));
        assert!(trace.contains(
            r#""finalError":"resolver error: local HNS chain is not current enough to determine current name state""#
        ));
        cleanup_dir(&path);
    }

    #[test]
    fn resolution_trace_marks_authoritative_dns_as_delegated() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            question_name: Some("denuoweb".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 19,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "denuoweb",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("denuoweb").unwrap(),
                records: vec![address_record("denuoweb", [35, 212, 156, 128])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""delegation":true"#));
        assert!(trace.contains(r#""resourceRecords":["A"]"#));
        assert!(trace.contains(r#""fallback":{"used":false"#));
    }

    #[test]
    fn resolution_trace_reports_tlsa_and_dane_details() {
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0xaa, 0xbb],
        };
        let mut tls = TlsValidation::hns_strict(true, vec![tlsa]);
        tls.service_port = 8443;
        let inspection = TlsCertificateInspection {
            end_entity_der: b"cert".to_vec(),
            end_entity_spki_der: b"spki".to_vec(),
            intermediate_der: vec![b"issuer".to_vec()],
            webpki_status: hns_dane::WebPkiStatus::Invalid,
        };
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput {
                validation: Some(&tls),
                decision: Some(&DaneDecision::Matched(TlsaUsage::DaneEe)),
                inspection: Some(&inspection),
                origin_address: None,
            },
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaOwner":"_8443._tcp.nathan.woodburn""#));
        assert!(trace.contains(r#""tlsaEvaluated":true"#));
        assert!(trace.contains(r#""tlsaStatus":"present""#));
        assert!(trace.contains(r#""tlsaBlockedBy":null"#));
        assert!(trace.contains(r#""tlsaFound":true"#));
        assert!(trace.contains(r#""dnssecSecure":true"#));
        assert!(trace.contains(
            r#""usage":"DANE-EE","selector":"SPKI","matching":"SHA-256","associationDataHex":"aabb""#
        ));
        assert!(trace.contains(r#""webPkiStatus":"invalid""#));
        assert!(trace.contains(&format!(r#""spkiSha256":"{}""#, sha256_hex(b"spki"))));
        assert!(trace.contains(r#""spkiDerHex":"73706b69""#));
        assert!(trace.contains(r#""intermediateCount":1"#));
        assert!(trace.contains(
            r#""dane":{"decision":"verified","matchedUsage":"DANE-EE","certificateMatch":"pass","webPkiFallback":false}"#
        ));
    }

    #[test]
    fn resolution_trace_marks_tlsa_not_evaluated_when_dnssec_fails_first() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "namecity",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnssecFailed)),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaOwner":"_443._tcp.namecity""#));
        assert!(trace.contains(r#""tlsaEvaluated":false"#));
        assert!(trace.contains(r#""tlsaStatus":"not_evaluated""#));
        assert!(trace.contains(r#""tlsaBlockedBy":"delegated_dnssec_validation_failed""#));
        assert!(trace.contains(r#""tlsaFound":false"#));
        assert!(trace.contains(r#""dane":{"decision":"not_evaluated""#));
    }

    #[test]
    fn resolution_trace_marks_expired_origin_certificate() {
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "mercenary",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            NetworkKind::Mainnet,
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Transport(TransportError::Io(
                "invalid peer certificate: certificate expired: verification time 1783324451, but certificate is not valid after 1680922072".to_owned(),
            ))),
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaStatus":"not_evaluated""#));
        assert!(trace.contains(r#""tlsaBlockedBy":"origin_certificate_expired""#));
        assert!(trace.contains(
            r#""finalError":"transport error: origin I/O error: invalid peer certificate: certificate expired:"#
        ));
    }

    #[test]
    fn configured_doh_fallback_uses_recursive_transport_on_earlier_transport_error() {
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("nathan.woodburn").unwrap(),
            records: vec![address_record("nathan.woodburn", [103, 152, 197, 116])],
            secure: true,
        };
        let marker = FallbackMarker::default();
        let resolver = FallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| ResolverError::DnsTransport("closed".to_owned())),
            TestDelegatedResolver::answer(answer.clone()),
            marker.clone(),
        );

        let resolved = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "nathan.woodburn".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &test_delegation("woodburn"),
            )
            .unwrap();

        assert_eq!(resolved, answer);
        assert_eq!(marker.reason(), Some("earlier_hns_transports_unavailable"));
    }

    #[test]
    fn configured_doh_fallback_skips_primary_after_root_fallback() {
        use std::sync::atomic::AtomicUsize;

        let primary_calls = Arc::new(AtomicUsize::new(0));
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("shakeshift").unwrap(),
            records: vec![address_record("shakeshift", [203, 0, 113, 10])],
            secure: true,
        };
        let resolver = FallbackDelegatedResolver::new(
            CountingErrorDelegatedResolver {
                calls: primary_calls.clone(),
                error: || ResolverError::DnsTransport("closed".to_owned()),
            },
            TestDelegatedResolver::answer(answer),
            FallbackMarker::default(),
        );

        resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "shakeshift".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &test_delegation("shakeshift"),
            )
            .unwrap();
        resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "_443._tcp.shakeshift".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
                &test_delegation("shakeshift"),
            )
            .unwrap();

        assert_eq!(primary_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn p2p_fallback_is_used_only_for_delegated_transport_failures() {
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("legacy.relaytest").unwrap(),
            records: vec![address_record("legacy.relaytest", [203, 0, 113, 44])],
            secure: true,
        };
        let relay = P2pFallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| {
                ResolverError::DnsTransport("authoritative UDP timed out".to_owned())
            }),
            TestDelegatedResolver::answer(answer.clone()),
        );
        let request = ResolutionRequest {
            qname: "legacy.relaytest".to_owned(),
            qtype: RecordType::A.code(),
        };

        assert_eq!(
            relay
                .resolve_delegated(&request, &test_delegation("relaytest"))
                .unwrap(),
            answer,
        );

        let gated = P2pFallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| ResolverError::ProofUnavailable),
            TestDelegatedResolver::answer(ResolutionAnswer {
                name: DnsName::from_ascii("legacy.relaytest").unwrap(),
                records: Vec::new(),
                secure: true,
            }),
        );
        assert_eq!(
            gated
                .resolve_delegated(&request, &test_delegation("relaytest"))
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn recursive_hns_doh_and_p2p_fallbacks_accept_only_typed_transport_unavailability() {
        assert_eq!(
            configured_doh_transport_fallback_reason(&ResolverError::DnsTransport(
                "closed".to_owned()
            )),
            Some("earlier_hns_transports_unavailable")
        );
        assert_eq!(
            configured_doh_transport_fallback_reason(&ResolverError::Port53InterceptionDetected),
            Some("port53_interception_detected")
        );

        for error in [
            ResolverError::DnsResponseCode(2),
            ResolverError::InvalidDnsResponse,
            ResolverError::DnssecFailed,
            ResolverError::RelayDnssecFailed,
            ResolverError::ProofUnavailable,
            ResolverError::LocalChainNotCurrent,
            ResolverError::ProofNameMismatch,
        ] {
            assert_eq!(configured_doh_transport_fallback_reason(&error), None);
            assert!(!delegated_p2p_fallback_allowed(&error));
        }
    }

    #[test]
    fn configured_recursive_hns_doh_never_masks_terminal_resolution_errors() {
        let request = ResolutionRequest {
            qname: "terminal.relaytest".to_owned(),
            qtype: RecordType::A.code(),
        };

        for terminal in [
            (|| ResolverError::DnsResponseCode(2)) as fn() -> ResolverError,
            || ResolverError::InvalidDnsResponse,
            || ResolverError::DnssecFailed,
            || ResolverError::RelayDnssecFailed,
            || ResolverError::ProofUnavailable,
            || ResolverError::LocalChainNotCurrent,
            || ResolverError::ProofNameMismatch,
        ] {
            let fallback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let marker = FallbackMarker::default();
            let resolver = ConfiguredDohFallbackDelegatedResolver::new(
                TestDelegatedResolver::error(terminal),
                CountingAnswerDelegatedResolver {
                    calls: Arc::clone(&fallback_calls),
                    answer: ResolutionAnswer {
                        name: DnsName::from_ascii("terminal.relaytest").unwrap(),
                        records: vec![address_record("terminal.relaytest", [203, 0, 113, 48])],
                        secure: true,
                    },
                },
                marker.clone(),
            );

            assert!(
                resolver
                    .resolve_delegated(&request, &test_delegation("relaytest"))
                    .is_err()
            );
            assert_eq!(fallback_calls.load(Ordering::Relaxed), 0);
            assert!(!marker.used());
        }
    }

    #[test]
    fn relay_live_query_key_ignores_dns_id_and_restores_each_callers_id() {
        let first = vec![0x12, 0x34, 0x01, 0x10, 0, 1];
        let second = vec![0xab, 0xcd, 0x01, 0x10, 0, 1];
        let (first_key, first_id) = dns_relay_coalescing_key(&first).unwrap();
        let (second_key, second_id) = dns_relay_coalescing_key(&second).unwrap();

        assert_eq!(first_key, second_key);
        assert_eq!(first_id, 0x1234);
        assert_eq!(second_id, 0xabcd);

        let relayed = vec![0x12, 0x34, 0x81, 0x80];
        assert_eq!(
            restore_dns_relay_response_id(relayed, second_id).unwrap(),
            vec![0xab, 0xcd, 0x81, 0x80]
        );
        assert!(matches!(
            dns_relay_coalescing_key(&[0]),
            Err(ResolverError::InvalidDnsResponse)
        ));
    }

    #[test]
    fn coalesced_relay_follower_inherits_peer_and_retry_metadata() {
        let peer: SocketAddr = "203.0.113.80:12038".parse().unwrap();
        let query = vec![0xab, 0xcd, 0x01, 0x10, 0, 1];
        let (key, _) = dns_relay_coalescing_key(&query).unwrap();
        let flight = Arc::new(DnsRelayFlight {
            result: Mutex::new(Some(Ok(DnsRelayFlightSuccess {
                response: vec![0x12, 0x34, 0x81, 0x80],
                metadata: DnsRelayTraceMetadata {
                    peer: Some(peer),
                    retries: 1,
                    service_advertised: Some(true),
                    error: None,
                },
            }))),
            completed: Condvar::new(),
        });
        let live_queries = Arc::new(Mutex::new(HashMap::from([(key, flight)])));
        let attempts = Arc::new(DnsRelayAttemptTracker::default());
        let trace = DnsTraceRecorder::default();
        let transport = HnsP2pDnsTransport {
            client: Arc::new(Mutex::new(None)),
            initialization_error: Some("leader-only client is unused by follower".to_owned()),
            peer_store_path: PathBuf::new(),
            network_kind: NetworkKind::Regtest,
            peer_state: None,
            proof_peer: Arc::new(Mutex::new(None)),
            trace: trace.clone(),
            endpoint_policy: DnsEndpointPolicy::for_network(NetworkKind::Regtest),
            live_queries,
            attempts: Arc::clone(&attempts),
        };

        attempts.begin(0);
        assert_eq!(
            transport.traced_exchange(&query).unwrap(),
            vec![0xab, 0xcd, 0x81, 0x80]
        );

        assert_eq!(attempts.finish(), vec![peer]);
        assert_eq!(
            trace.relay_snapshot(),
            Some(DnsRelayTraceMetadata {
                peer: Some(peer),
                retries: 1,
                service_advertised: Some(true),
                error: None,
            })
        );
        assert_eq!(trace.snapshot()[0].server, peer.to_string());
        assert!(p2p_dns_relay_trace_json(trace.relay_snapshot()).contains(
            r#""attempted":true,"peer":"203.0.113.80:12038","serviceAdvertised":true,"retryCount":1"#,
        ));
    }

    #[test]
    fn relay_dnssec_failure_penalizes_bad_peer_and_retries_complete_resolution_once() {
        let bad_peer: SocketAddr = "203.0.113.80:12038".parse().unwrap();
        let good_peer: SocketAddr = "203.0.113.81:12038".parse().unwrap();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("legacy.relaytest").unwrap(),
            records: vec![address_record("legacy.relaytest", [203, 0, 113, 47])],
            secure: true,
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let feedback =
            TestRelayDnssecFeedback::with_attempt_peers([vec![bad_peer], vec![good_peer]]);
        let resolver = RelayDnssecRetryDelegatedResolver::new(
            DnssecFailureThenAnswerDelegatedResolver {
                calls: Arc::clone(&calls),
                answer: answer.clone(),
            },
            feedback.clone(),
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "legacy.relaytest".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &test_delegation("relaytest"),
                )
                .unwrap(),
            answer,
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(feedback.retry_offsets(), vec![0, 1]);
        assert_eq!(feedback.reported_peers(), vec![vec![bad_peer]]);
    }

    #[test]
    fn configured_doh_follows_p2p_unavailability_and_keeps_distinct_marker() {
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("legacy.relaytest").unwrap(),
            records: vec![address_record("legacy.relaytest", [203, 0, 113, 45])],
            secure: true,
        };
        let p2p = P2pFallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| {
                ResolverError::DnsTransport("direct port 53 blocked".to_owned())
            }),
            TestDelegatedResolver::error(|| {
                ResolverError::DnsTransport("no capable relay peer".to_owned())
            }),
        );
        let marker = FallbackMarker::default();
        let resolver = FallbackDelegatedResolver::new(
            p2p,
            TestDelegatedResolver::answer(answer.clone()),
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "legacy.relaytest".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &test_delegation("relaytest"),
                )
                .unwrap(),
            answer,
        );
        assert_eq!(marker.reason(), Some("earlier_hns_transports_unavailable"));
    }

    #[test]
    fn relay_dnssec_failure_is_distinct_and_does_not_fall_through_to_configured_doh() {
        let first_peer: SocketAddr = "203.0.113.80:12038".parse().unwrap();
        let alternate_peer: SocketAddr = "203.0.113.81:12038".parse().unwrap();
        let relay_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let feedback =
            TestRelayDnssecFeedback::with_attempt_peers([vec![first_peer], vec![alternate_peer]]);
        let p2p = P2pFallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| {
                ResolverError::DnsTransport("direct port 53 blocked".to_owned())
            }),
            RelayDnssecRetryDelegatedResolver::new(
                CountingErrorDelegatedResolver {
                    calls: Arc::clone(&relay_calls),
                    error: || ResolverError::DnssecFailed,
                },
                feedback.clone(),
            ),
        );
        let marker = FallbackMarker::default();
        let resolver = FallbackDelegatedResolver::new(
            p2p,
            TestDelegatedResolver::answer(ResolutionAnswer {
                name: DnsName::from_ascii("legacy.relaytest").unwrap(),
                records: vec![address_record("legacy.relaytest", [203, 0, 113, 46])],
                secure: true,
            }),
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "legacy.relaytest".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &test_delegation("relaytest"),
                )
                .unwrap_err(),
            ResolverError::RelayDnssecFailed,
        );
        assert_eq!(relay_calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            feedback.reported_peers(),
            vec![vec![first_peer], vec![alternate_peer]]
        );
        assert!(!marker.used());
    }

    #[test]
    fn invalid_p2p_response_does_not_fall_through_to_configured_doh() {
        let p2p = P2pFallbackDelegatedResolver::new(
            TestDelegatedResolver::error(|| {
                ResolverError::DnsTransport("direct port 53 blocked".to_owned())
            }),
            TestDelegatedResolver::error(|| ResolverError::InvalidDnsResponse),
        );
        let fallback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let marker = FallbackMarker::default();
        let resolver = ConfiguredDohFallbackDelegatedResolver::new(
            p2p,
            CountingAnswerDelegatedResolver {
                calls: Arc::clone(&fallback_calls),
                answer: ResolutionAnswer {
                    name: DnsName::from_ascii("invalid.relaytest").unwrap(),
                    records: vec![address_record("invalid.relaytest", [203, 0, 113, 49])],
                    secure: true,
                },
            },
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "invalid.relaytest".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &test_delegation("relaytest"),
                )
                .unwrap_err(),
            ResolverError::InvalidDnsResponse,
        );
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 0);
        assert!(!marker.used());
    }

    #[test]
    fn relay_peer_persistence_merge_preserves_header_observation_atomically() {
        let address: SocketAddr = "203.0.113.80:12038".parse().unwrap();
        let mut stored = hns_p2p::PeerState::new(address);
        stored.score = 25;
        stored.last_height = Height(200);
        stored.last_height_observed_at = Some(290);
        stored.last_connected_at = Some(300);
        stored.banned_until = Some(600);
        stored.successes = 8;
        stored.failures = 4;

        let mut stale_relay = hns_p2p::PeerState::new(address);
        stale_relay.score = 5;
        stale_relay.last_height = Height(10_000);
        stale_relay.last_height_observed_at = Some(240);
        stale_relay.last_connected_at = Some(350);
        stale_relay.successes = 9;
        stale_relay.failures = 3;

        let merged = merge_dns_relay_peer_state(&stored, &stale_relay);
        assert_eq!(merged.score, 25);
        assert_eq!(merged.last_height, Height(200));
        assert_eq!(merged.last_height_observed_at, Some(290));
        assert_eq!(merged.last_connected_at, Some(350));
        assert_eq!(merged.banned_until, Some(600));
        assert_eq!(merged.successes, 9);
        assert_eq!(merged.failures, 4);
    }

    #[test]
    fn hns_proof_lineage_requires_one_exact_observation_per_root() {
        let lineage = HnsProofLineage::default();
        let observation = HnsProofObservation {
            anchor: ResourceValueAnchor {
                tree_root: Hash::new([41; 32]),
                height: Height(912),
            },
            exists: true,
            observed_at_unix: 1_000,
            expires_at_unix: 1_030,
        };

        assert_eq!(lineage.exact("denuoweb").unwrap(), None);
        lineage.record("denuoweb", observation).unwrap();
        lineage.record("denuoweb", observation).unwrap();
        assert_eq!(lineage.exact("denuoweb").unwrap(), Some(observation));
        assert_eq!(lineage.exact("other-root").unwrap(), None);
    }

    #[test]
    fn namespace_trace_vocabulary_matches_the_extension_schema() {
        assert_eq!(
            namespace_selection_reason_trace_name(
                OutcomeKind::HnsOnly,
                Some(SelectionReason::SingleRoot),
            ),
            "onlyAvailableRoot",
        );
        assert_eq!(
            icann_absence_state(AbsenceKind::IcannInsecureNoUsableEndpoint),
            "insecureAbsent",
        );
        assert_eq!(
            icann_absence_state(AbsenceKind::DnssecAuthenticatedNoUsableEndpoint),
            "authenticatedAbsent",
        );
    }

    #[test]
    fn indeterminate_namespace_trace_preserves_bounded_root_states() {
        let query = OriginQuery::new(
            CanonicalHost::parse("partial-state.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let failed_hns = ClassificationError::RootFailed {
            hns: RootResolutionState::Failed(RootFailure::new(
                Namespace::Hns,
                query.clone(),
                RootFailureKind::Transport,
                None,
            )),
            icann: RootResolutionState::Absent,
        };
        let trace = indeterminate_namespace_trace_json(&query, &failed_hns);
        assert!(trace.contains(r#""hnsState":"failed","icannState":"absent""#));
        assert!(trace.contains(
            r#""hns":{"state":"failed","rcode":null,"denial":null,"failure":"Transport"}"#
        ));
        assert!(
            trace.contains(
                r#""icann":{"state":"absent","rcode":null,"denial":null,"failure":null}"#
            )
        );
        assert!(!trace.contains("authenticatedAbsent"));
        assert!(!trace.contains("insecureAbsent"));

        let both_failed = ClassificationError::RootFailed {
            hns: RootResolutionState::Failed(RootFailure::new(
                Namespace::Hns,
                query.clone(),
                RootFailureKind::Transport,
                None,
            )),
            icann: RootResolutionState::Failed(RootFailure::new(
                Namespace::Icann,
                query.clone(),
                RootFailureKind::BogusDnssec,
                None,
            )),
        };
        let trace = indeterminate_namespace_trace_json(&query, &both_failed);
        assert!(trace.contains(r#""hnsState":"failed","icannState":"failed""#));
        assert!(trace.contains(r#""failure":"Transport""#));
        assert!(trace.contains(r#""failure":"BogusDnssec""#));
        assert!(!trace.contains(query.host().as_str()));
    }

    #[test]
    fn hns_proof_lineage_rejects_anchor_or_existence_drift() {
        let anchor_drift = HnsProofLineage::default();
        anchor_drift
            .record(
                "denuoweb",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([42; 32]),
                        height: Height(913),
                    },
                    exists: true,
                    observed_at_unix: 1_000,
                    expires_at_unix: 1_030,
                },
            )
            .unwrap();
        anchor_drift
            .record(
                "denuoweb",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([43; 32]),
                        height: Height(914),
                    },
                    exists: true,
                    observed_at_unix: 1_001,
                    expires_at_unix: 1_031,
                },
            )
            .unwrap();
        assert_eq!(
            anchor_drift.exact("denuoweb").unwrap_err(),
            ResolverError::ProofNameMismatch
        );

        let existence_drift = HnsProofLineage::default();
        let anchor = ResourceValueAnchor {
            tree_root: Hash::new([44; 32]),
            height: Height(915),
        };
        existence_drift
            .record(
                "denuoweb",
                HnsProofObservation {
                    anchor,
                    exists: true,
                    observed_at_unix: 1_000,
                    expires_at_unix: 1_030,
                },
            )
            .unwrap();
        existence_drift
            .record(
                "denuoweb",
                HnsProofObservation {
                    anchor,
                    exists: false,
                    observed_at_unix: 1_001,
                    expires_at_unix: 1_031,
                },
            )
            .unwrap();
        assert_eq!(
            existence_drift.exact("denuoweb").unwrap_err(),
            ResolverError::ProofNameMismatch
        );
    }

    #[test]
    fn delegated_hns_name_error_is_short_lived_and_unsigned_error_fails() {
        let now = now_unix_seconds();
        let query = OriginQuery::new(
            CanonicalHost::parse("missing.securechild").unwrap(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                "securechild",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([54; 32]),
                        height: Height(1_004),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();

        let secure_negative = build_root_resolution(
            Namespace::Hns,
            &query,
            &TestResolver::error(|| ResolverError::NameNotFound),
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Absent(absence) = secure_negative.lookup else {
            panic!("DS-secured delegated name error must be authenticated absence");
        };
        assert_eq!(
            absence.kind(),
            AbsenceKind::DnssecAuthenticatedNoUsableEndpoint,
        );
        assert!(
            absence
                .freshness()
                .expires_at_unix()
                .saturating_sub(absence.freshness().observed_at_unix())
                <= 1
        );

        let unsigned_negative = build_root_resolution(
            Namespace::Hns,
            &query,
            &TestResolver::error(|| ResolverError::DnssecFailed),
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Failed(failure) = unsigned_negative.lookup else {
            panic!("unsigned delegated name error must fail classification");
        };
        assert_eq!(failure.kind(), RootFailureKind::BogusDnssec);
    }

    #[test]
    fn delegated_hns_dns_bounds_the_complete_plan_freshness() {
        let now = now_unix_seconds();
        let host = "www.securechild";
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                "securechild",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([55; 32]),
                        height: Height(1_005),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, [8, 8, 8, 8])],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "203.0.113.53:53".to_owned(),
            question_name: Some(host.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "ok".to_owned(),
            elapsed_ms: 1,
            error: None,
        });

        let built = build_root_resolution(
            Namespace::Hns,
            &query,
            &resolver,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            Some(&dns_trace),
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("delegated HNS DNS answer must produce a complete plan");
        };
        assert!(
            plan.freshness()
                .expires_at_unix()
                .saturating_sub(plan.freshness().observed_at_unix())
                <= HNS_DELEGATED_DNS_EVIDENCE_TTL_SECONDS
        );
    }

    #[test]
    fn icann_doh_evidence_retains_absolute_overlap_and_rejects_state_drift() {
        let request = ResolutionRequest {
            qname: "dane-test.denuoweb.com".to_owned(),
            qtype: RecordType::Tlsa.code(),
        };
        let evidence = IcannDohEvidence::default();
        evidence
            .record(
                &request,
                IcannDohObservation {
                    kind: IcannDohAnswerKind::Present,
                    secure: true,
                    rcode: DNS_RCODE_NOERROR,
                    observed_at_unix: 2_000,
                    expires_at_unix: 2_120,
                },
            )
            .unwrap();
        evidence
            .record(
                &request,
                IcannDohObservation {
                    kind: IcannDohAnswerKind::Present,
                    secure: true,
                    rcode: DNS_RCODE_NOERROR,
                    observed_at_unix: 2_010,
                    expires_at_unix: 2_100,
                },
            )
            .unwrap();
        assert_eq!(
            evidence.exact(&request).unwrap(),
            Some(IcannDohObservation {
                kind: IcannDohAnswerKind::Present,
                secure: true,
                rcode: DNS_RCODE_NOERROR,
                observed_at_unix: 2_010,
                expires_at_unix: 2_100,
            })
        );

        evidence
            .record(
                &request,
                IcannDohObservation {
                    kind: IcannDohAnswerKind::NoData,
                    secure: true,
                    rcode: DNS_RCODE_NOERROR,
                    observed_at_unix: 2_011,
                    expires_at_unix: 2_101,
                },
            )
            .unwrap();
        assert_eq!(
            evidence.exact(&request).unwrap_err(),
            ResolverError::InvalidDnsResponse
        );
    }

    #[test]
    fn short_tlsa_denial_bounds_the_complete_icann_plan_freshness() {
        let now = now_unix_seconds();
        let host = "freshness.example";
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let tlsa_owner = format!("_443._tcp.{host}");
        let evidence = IcannDohEvidence::default();
        for (qname, qtype, kind, lifetime) in [
            (host, RecordType::Https, IcannDohAnswerKind::NoData, 600),
            (host, RecordType::A, IcannDohAnswerKind::Present, 600),
            (host, RecordType::Aaaa, IcannDohAnswerKind::NoData, 600),
            (
                tlsa_owner.as_str(),
                RecordType::Tlsa,
                IcannDohAnswerKind::NoData,
                7,
            ),
        ] {
            evidence
                .record(
                    &ResolutionRequest {
                        qname: qname.to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind,
                        secure: true,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: now,
                        expires_at_unix: now + lifetime,
                    },
                )
                .unwrap();
        }
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, [8, 8, 8, 8])],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: tlsa_owner,
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii("_443._tcp.freshness.example").unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let built = build_root_resolution(
            Namespace::Icann,
            &query,
            &resolver,
            None,
            Some(&evidence),
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("authenticated TLSA absence must retain an ICANN WebPKI plan");
        };

        assert_eq!(
            plan.tls_policy(),
            TlsTrustPolicy::WebPkiAuthenticatedAbsence,
        );
        assert_eq!(plan.freshness().expires_at_unix(), now + 7);
    }

    #[test]
    fn exact_insecure_icann_origin_rrset_skips_irrelevant_tlsa_lookup() {
        let now = now_unix_seconds();
        let host = "www.unsigned.example";
        let target = "edge.cdn.example";
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let evidence = IcannDohEvidence::default();
        for (qname, qtype, kind) in [
            (host, RecordType::Https, IcannDohAnswerKind::Present),
            (target, RecordType::Https, IcannDohAnswerKind::NoData),
            (target, RecordType::A, IcannDohAnswerKind::Present),
            (target, RecordType::Aaaa, IcannDohAnswerKind::NoData),
        ] {
            evidence
                .record(
                    &ResolutionRequest {
                        qname: qname.to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind,
                        secure: false,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: now,
                        expires_at_unix: now + 60,
                    },
                )
                .unwrap();
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        let built = build_root_resolution(
            Namespace::Icann,
            &query,
            &OriginMapResolver {
                responses: HashMap::from([
                    (
                        ResolutionRequest {
                            qname: host.to_owned(),
                            qtype: RecordType::Https.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(host).unwrap(),
                            records: vec![cname_record(host, target, 60)],
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::Https.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: Vec::new(),
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::A.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: vec![address_record(target, [8, 8, 8, 8])],
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::Aaaa.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: Vec::new(),
                            secure: false,
                        },
                    ),
                ]),
                requests: Arc::clone(&requests),
            },
            None,
            Some(&evidence),
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("an exact insecure origin RRset must allow the ICANN WebPKI plan");
        };
        assert_eq!(plan.tls_policy(), TlsTrustPolicy::WebPkiInsecureDelegation);
        assert!(matches!(
            plan.provenance(),
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::ProvenInsecure
            }
        ));
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.qtype == RecordType::Tlsa.code())
        );
    }

    #[test]
    fn signed_origin_cname_into_insecure_target_still_requires_tlsa_lookup() {
        let now = now_unix_seconds();
        let host = "www.signed.example";
        let target = "edge.unsigned.example";
        let tlsa_owner = format!("_443._tcp.{host}");
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let evidence = IcannDohEvidence::default();
        for (qname, qtype, kind) in [
            (host, RecordType::Https, IcannDohAnswerKind::Present),
            (target, RecordType::Https, IcannDohAnswerKind::NoData),
            (target, RecordType::A, IcannDohAnswerKind::Present),
            (target, RecordType::Aaaa, IcannDohAnswerKind::NoData),
        ] {
            evidence
                .record(
                    &ResolutionRequest {
                        qname: qname.to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind,
                        secure: false,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: now,
                        expires_at_unix: now + 60,
                    },
                )
                .unwrap();
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        let built = build_root_resolution(
            Namespace::Icann,
            &query,
            &OriginMapResolver {
                responses: HashMap::from([
                    (
                        ResolutionRequest {
                            qname: host.to_owned(),
                            qtype: RecordType::Https.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(host).unwrap(),
                            records: vec![
                                cname_record(host, target, 60),
                                rrsig_record(host, RecordType::Cname),
                            ],
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::Https.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: Vec::new(),
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::A.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: vec![address_record(target, [8, 8, 4, 4])],
                            secure: false,
                        },
                    ),
                    (
                        ResolutionRequest {
                            qname: target.to_owned(),
                            qtype: RecordType::Aaaa.code(),
                        },
                        ResolutionAnswer {
                            name: DnsName::from_ascii(target).unwrap(),
                            records: Vec::new(),
                            secure: false,
                        },
                    ),
                ]),
                requests: Arc::clone(&requests),
            },
            None,
            Some(&evidence),
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Failed(failure) = built.lookup else {
            panic!("a signed origin alias must not downgrade around TLSA discovery");
        };
        assert_eq!(failure.kind(), RootFailureKind::Unsupported);
        assert!(requests.lock().unwrap().iter().any(|request| {
            request.qname == tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
    }

    #[test]
    fn hns_https_uses_next_advertised_protocol_when_preferred_transport_lacks_tlsa() {
        let now = now_unix_seconds();
        let host = "denuoweb";
        let udp_tlsa_owner = format!("_443._udp.{host}");
        let tcp_tlsa_owner = format!("_443._tcp.{host}");
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                host,
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([59; 32]),
                        height: Height(1_009),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![https_alpn_record(
                            host,
                            &[b"h3".as_slice(), b"h2".as_slice()],
                        )],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, [35, 212, 156, 128])],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: udp_tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&udp_tlsa_owner).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: tcp_tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&tcp_tlsa_owner).unwrap(),
                        records: vec![tlsa_record(&tcp_tlsa_owner, 0x36)],
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::clone(&requests),
        };

        let built = build_root_resolution(
            Namespace::Hns,
            &query,
            &resolver,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("HNS must try another advertised protocol with a secure TLSA record");
        };
        assert_eq!(
            plan.service().selected_protocol(),
            ApplicationProtocol::Http2
        );
        assert_eq!(plan.service().transport(), ServiceTransport::Tcp);
        assert_eq!(plan.tls_policy(), TlsTrustPolicy::Dane);
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|request| {
            request.qname == udp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
        assert!(requests.iter().any(|request| {
            request.qname == tcp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
    }

    #[test]
    fn https_alpn_candidates_include_the_rfc9460_http11_default() {
        let capabilities = hns_namespace_resolution::ProtocolCapabilities::all();
        let advertised = vec![b"h3".to_vec(), b"h2".to_vec()];

        assert_eq!(
            application_protocol_candidates(capabilities, &advertised, false),
            vec![
                ApplicationProtocol::Http3,
                ApplicationProtocol::Http2,
                ApplicationProtocol::Http11,
            ]
        );
        assert_eq!(
            application_protocol_candidates(capabilities, &advertised, true),
            vec![ApplicationProtocol::Http3, ApplicationProtocol::Http2]
        );
        assert_eq!(
            application_protocol_candidates(capabilities, &[], false),
            vec![ApplicationProtocol::Http11]
        );
        assert!(
            application_protocol_candidates(capabilities, &[], true).is_empty(),
            "no-default-alpn without an explicit supported ALPN has no candidate"
        );
    }

    #[test]
    fn hns_https_keeps_http3_when_udp_tlsa_is_securely_present() {
        let now = now_unix_seconds();
        let host = "denuoweb";
        let udp_tlsa_owner = format!("_443._udp.{host}");
        let tcp_tlsa_owner = format!("_443._tcp.{host}");
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                host,
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([60; 32]),
                        height: Height(1_010),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![https_alpn_record(
                            host,
                            &[b"h3".as_slice(), b"h2".as_slice()],
                        )],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, [35, 212, 156, 128])],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: udp_tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&udp_tlsa_owner).unwrap(),
                        records: vec![tlsa_record(&udp_tlsa_owner, 0x36)],
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::clone(&requests),
        };

        let built = build_root_resolution(
            Namespace::Hns,
            &query,
            &resolver,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("secure UDP TLSA must retain the preferred HTTP/3 service");
        };
        assert_eq!(
            plan.service().selected_protocol(),
            ApplicationProtocol::Http3
        );
        assert_eq!(plan.service().transport(), ServiceTransport::Udp);
        assert_eq!(plan.tls_policy(), TlsTrustPolicy::Dane);
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|request| {
            request.qname == udp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
        assert!(!requests.iter().any(|request| {
            request.qname == tcp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
    }

    #[test]
    fn hns_https_does_not_downgrade_protocol_after_insecure_udp_tlsa_evidence() {
        let now = now_unix_seconds();
        let host = "denuoweb";
        let udp_tlsa_owner = format!("_443._udp.{host}");
        let tcp_tlsa_owner = format!("_443._tcp.{host}");
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                host,
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([61; 32]),
                        height: Height(1_011),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![https_alpn_record(
                            host,
                            &[b"h3".as_slice(), b"h2".as_slice()],
                        )],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, [35, 212, 156, 128])],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: udp_tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&udp_tlsa_owner).unwrap(),
                        records: Vec::new(),
                        secure: false,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: tcp_tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&tcp_tlsa_owner).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::clone(&requests),
        };

        let built = build_root_resolution(
            Namespace::Hns,
            &query,
            &resolver,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Failed(failure) = built.lookup else {
            panic!("insecure UDP TLSA evidence must fail closed");
        };
        assert_eq!(failure.kind(), RootFailureKind::BogusDnssec);
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|request| {
            request.qname == udp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
        assert!(!requests.iter().any(|request| {
            request.qname == tcp_tlsa_owner && request.qtype == RecordType::Tlsa.code()
        }));
    }

    #[test]
    fn hns_address_presence_without_required_tlsa_cannot_become_icann_only() {
        let now = now_unix_seconds();
        let host = "collision.dualroot";
        let tlsa_owner = format!("_443._tcp.{host}");
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let responses = |address| {
            HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![address_record(host, address)],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: tlsa_owner.clone(),
                        qtype: RecordType::Tlsa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(&tlsa_owner).unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
            ])
        };

        let hns_lineage = HnsProofLineage::default();
        hns_lineage
            .record(
                "dualroot",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([56; 32]),
                        height: Height(1_006),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let direct_hns_resolver = OriginMapResolver {
            responses: responses([1, 1, 1, 1]),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let mut direct_hns_session = RootResolutionSession::new(
            Namespace::Hns,
            &query,
            &direct_hns_resolver,
            Some(&hns_lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let direct_error = build_validated_origin_plan(&mut direct_hns_session).unwrap_err();
        assert!(
            matches!(direct_error, PlanBuildError::RequiredHnsTlsaMissing),
            "unexpected direct HNS plan error: {direct_error:?}",
        );
        let hns = build_root_resolution(
            Namespace::Hns,
            &query,
            &OriginMapResolver {
                responses: responses([1, 1, 1, 1]),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            Some(&hns_lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Failed(hns_failure) = &hns.lookup else {
            panic!("HNS address presence without required TLSA must fail classification");
        };
        assert_eq!(hns_failure.kind(), RootFailureKind::Unsupported);

        let icann_evidence = IcannDohEvidence::default();
        for (qname, qtype, kind) in [
            (host, RecordType::Https, IcannDohAnswerKind::NoData),
            (host, RecordType::A, IcannDohAnswerKind::Present),
            (host, RecordType::Aaaa, IcannDohAnswerKind::NoData),
            (
                tlsa_owner.as_str(),
                RecordType::Tlsa,
                IcannDohAnswerKind::NoData,
            ),
        ] {
            icann_evidence
                .record(
                    &ResolutionRequest {
                        qname: qname.to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind,
                        secure: true,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: now,
                        expires_at_unix: now + 60,
                    },
                )
                .unwrap();
        }
        let icann = build_root_resolution(
            Namespace::Icann,
            &query,
            &OriginMapResolver {
                responses: responses([8, 8, 8, 8]),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            None,
            Some(&icann_evidence),
            NetworkKind::Mainnet,
            None,
        );
        assert!(matches!(&icann.lookup, RootLookup::Present(_)));

        let error = decide_namespace(
            &query,
            hns.lookup,
            icann.lookup,
            SelectionPolicy::default(),
            now,
        )
        .unwrap_err();
        let hns_namespace_resolution::ClassificationError::RootFailed {
            hns: RootResolutionState::Failed(failure),
            icann: RootResolutionState::Present,
        } = error
        else {
            panic!("ICANN presence must not hide unresolved HNS TLS policy");
        };
        assert_eq!(failure.kind(), RootFailureKind::Unsupported);
    }

    #[test]
    fn root_session_deduplicates_cnames_and_rejects_cross_answer_target_drift() {
        let now = now_unix_seconds();
        let host = "www.cnamecheck";
        let alias_owner = "alias.cnamecheck";
        let alias_target = "edge.cnamecheck";
        let origin_host = CanonicalHost::parse(host).unwrap();
        let query = OriginQuery::new(
            origin_host.clone(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                "cnamecheck",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([57; 32]),
                        height: Height(1_007),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();

        let first = cname_record(alias_owner, alias_target, 30);
        let exact_duplicate = cname_record(alias_owner, alias_target, 20);
        assert_eq!(
            one_cname_target(&[&first, &exact_duplicate]).unwrap(),
            Some(DnsName::from_ascii(alias_target).unwrap()),
        );
        let distinct = cname_record(alias_owner, "other.cnamecheck", 20);
        assert!(matches!(
            one_cname_target(&[&first, &distinct]),
            Err(PlanBuildError::Malformed),
        ));

        let responses = |aaaa_target: &str| {
            HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![
                            address_record(host, [1, 1, 1, 1]),
                            cname_record(alias_owner, alias_target, 30),
                            cname_record(alias_owner, alias_target, 20),
                        ],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![cname_record(alias_owner, aaaa_target, 5)],
                        secure: true,
                    },
                ),
            ])
        };
        let consistent = build_root_resolution(
            Namespace::Hns,
            &query,
            &OriginMapResolver {
                responses: responses(alias_target),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        assert!(matches!(&consistent.lookup, RootLookup::Present(_)));
        let retained_cnames = consistent
            .answer
            .records
            .iter()
            .filter(|record| record.record_type == RecordType::Cname)
            .collect::<Vec<_>>();
        assert_eq!(retained_cnames.len(), 1);
        assert_eq!(retained_cnames[0].ttl, 5);

        let divergent = build_root_resolution(
            Namespace::Hns,
            &query,
            &OriginMapResolver {
                responses: responses("other.cnamecheck"),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Failed(failure) = divergent.lookup else {
            panic!("cross-answer CNAME target drift must fail classification");
        };
        assert_eq!(failure.kind(), RootFailureKind::MalformedResponse);

        let https_query = OriginQuery::new(
            origin_host.clone(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let https_then_address = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Https.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![cname_record(alias_owner, alias_target, 30)],
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii(host).unwrap(),
                        records: vec![
                            address_record(host, [1, 1, 1, 1]),
                            cname_record(alias_owner, "other.cnamecheck", 20),
                        ],
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let mut session = RootResolutionSession::new(
            Namespace::Hns,
            &https_query,
            &https_then_address,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        session.resolve(&origin_host, RecordType::Https).unwrap();
        assert!(matches!(
            session.resolve(&origin_host, RecordType::A),
            Err(PlanBuildError::Malformed),
        ));
    }

    #[test]
    fn full_host_root_plans_ignore_the_static_iana_suffix_class() {
        let query_for = |host: &str| {
            OriginQuery::new(
                CanonicalHost::parse(host).unwrap(),
                hns_namespace_resolution::OriginScheme::Http,
                NonZeroU16::new(80),
                hns_namespace_resolution::ProtocolCapabilities::all(),
            )
        };
        let answer_for = |host: &str, records: Vec<ResourceRecord>| ResolutionAnswer {
            name: DnsName::from_ascii(host).unwrap(),
            records,
            secure: true,
        };

        let hns_query = query_for("example.com");
        let hns_lineage = HnsProofLineage::default();
        hns_lineage
            .record(
                "com",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([51; 32]),
                        height: Height(1_001),
                    },
                    exists: true,
                    observed_at_unix: 1,
                    expires_at_unix: u64::MAX,
                },
            )
            .unwrap();
        let hns_requests = Arc::new(Mutex::new(Vec::new()));
        let hns_resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: "example.com".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    answer_for(
                        "example.com",
                        vec![address_record("example.com", [1, 1, 1, 1])],
                    ),
                ),
                (
                    ResolutionRequest {
                        qname: "example.com".to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    answer_for("example.com", Vec::new()),
                ),
            ]),
            requests: Arc::clone(&hns_requests),
        };
        let hns = build_root_resolution(
            Namespace::Hns,
            &hns_query,
            &hns_resolver,
            Some(&hns_lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(hns_plan) = hns.lookup else {
            panic!("HNS must be able to produce a complete .com plan");
        };
        assert_eq!(hns_plan.namespace(), Namespace::Hns);
        assert_eq!(hns_plan.endpoints(), &["1.1.1.1:80".parse().unwrap()]);
        assert_eq!(
            *hns_requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::Aaaa.code(),
                },
            ]
        );

        let icann_query = query_for("welcome");
        let icann_evidence = IcannDohEvidence::default();
        for (qtype, kind) in [
            (RecordType::A, IcannDohAnswerKind::Present),
            (RecordType::Aaaa, IcannDohAnswerKind::NoData),
        ] {
            icann_evidence
                .record(
                    &ResolutionRequest {
                        qname: "welcome".to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind,
                        secure: true,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: 1,
                        expires_at_unix: u64::MAX,
                    },
                )
                .unwrap();
        }
        let icann_requests = Arc::new(Mutex::new(Vec::new()));
        let icann_resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: "welcome".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    answer_for("welcome", vec![address_record("welcome", [8, 8, 8, 8])]),
                ),
                (
                    ResolutionRequest {
                        qname: "welcome".to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    answer_for("welcome", Vec::new()),
                ),
            ]),
            requests: Arc::clone(&icann_requests),
        };
        let icann = build_root_resolution(
            Namespace::Icann,
            &icann_query,
            &icann_resolver,
            None,
            Some(&icann_evidence),
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(icann_plan) = icann.lookup else {
            panic!("ICANN must be able to produce a complete non-IANA-suffix plan");
        };
        assert_eq!(icann_plan.namespace(), Namespace::Icann);
        assert_eq!(icann_plan.endpoints(), &["8.8.8.8:80".parse().unwrap()]);
        assert_eq!(
            *icann_requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::Aaaa.code(),
                },
            ]
        );
    }

    #[test]
    fn selected_endpoint_plan_queries_both_families_and_supports_ipv6_only() {
        let query = OriginQuery::new(
            CanonicalHost::parse("ipv6only").unwrap(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let lineage = HnsProofLineage::default();
        lineage
            .record(
                "ipv6only",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([52; 32]),
                        height: Height(1_002),
                    },
                    exists: true,
                    observed_at_unix: 1,
                    expires_at_unix: u64::MAX,
                },
            )
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = OriginMapResolver {
            responses: HashMap::from([
                (
                    ResolutionRequest {
                        qname: "ipv6only".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii("ipv6only").unwrap(),
                        records: Vec::new(),
                        secure: true,
                    },
                ),
                (
                    ResolutionRequest {
                        qname: "ipv6only".to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    ResolutionAnswer {
                        name: DnsName::from_ascii("ipv6only").unwrap(),
                        records: vec![ResourceRecord {
                            name: DnsName::from_ascii("ipv6only").unwrap(),
                            record_type: RecordType::Aaaa,
                            class: DNS_CLASS_IN,
                            ttl: 20,
                            rdata: Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)
                                .octets()
                                .to_vec(),
                        }],
                        secure: true,
                    },
                ),
            ]),
            requests: Arc::clone(&requests),
        };

        let built = build_root_resolution(
            Namespace::Hns,
            &query,
            &resolver,
            Some(&lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let RootLookup::Present(plan) = built.lookup else {
            panic!("IPv6-only origin must produce a plan");
        };
        assert_eq!(
            plan.endpoints(),
            &["[2001:4860:4860::8888]:80".parse().unwrap()]
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "ipv6only".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "ipv6only".to_owned(),
                    qtype: RecordType::Aaaa.code(),
                },
            ]
        );
    }

    #[test]
    fn same_a_but_different_aaaa_is_a_namespace_divergence() {
        let now = now_unix_seconds();
        let host = "www.dualroot";
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            hns_namespace_resolution::OriginScheme::Http,
            NonZeroU16::new(80),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let hns_lineage = HnsProofLineage::default();
        hns_lineage
            .record(
                "dualroot",
                HnsProofObservation {
                    anchor: ResourceValueAnchor {
                        tree_root: Hash::new([53; 32]),
                        height: Height(1_003),
                    },
                    exists: true,
                    observed_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let icann_evidence = IcannDohEvidence::default();
        for qtype in [RecordType::A, RecordType::Aaaa] {
            icann_evidence
                .record(
                    &ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: qtype.code(),
                    },
                    IcannDohObservation {
                        kind: IcannDohAnswerKind::Present,
                        secure: true,
                        rcode: DNS_RCODE_NOERROR,
                        observed_at_unix: now,
                        expires_at_unix: now + 60,
                    },
                )
                .unwrap();
        }
        let answer = |record_type, rdata| ResolutionAnswer {
            name: DnsName::from_ascii(host).unwrap(),
            records: vec![ResourceRecord {
                name: DnsName::from_ascii(host).unwrap(),
                record_type,
                class: DNS_CLASS_IN,
                ttl: 60,
                rdata,
            }],
            secure: true,
        };
        let responses = |last_ipv6_segment| {
            HashMap::from([
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    answer(RecordType::A, vec![8, 8, 8, 8]),
                ),
                (
                    ResolutionRequest {
                        qname: host.to_owned(),
                        qtype: RecordType::Aaaa.code(),
                    },
                    answer(
                        RecordType::Aaaa,
                        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, last_ipv6_segment)
                            .octets()
                            .to_vec(),
                    ),
                ),
            ])
        };
        let hns = build_root_resolution(
            Namespace::Hns,
            &query,
            &OriginMapResolver {
                responses: responses(0x8888),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            Some(&hns_lineage),
            None,
            NetworkKind::Mainnet,
            None,
        );
        let icann = build_root_resolution(
            Namespace::Icann,
            &query,
            &OriginMapResolver {
                responses: responses(0x8844),
                requests: Arc::new(Mutex::new(Vec::new())),
            },
            None,
            Some(&icann_evidence),
            NetworkKind::Mainnet,
            None,
        );
        let decision = decide_namespace(
            &query,
            hns.lookup,
            icann.lookup,
            SelectionPolicy::default(),
            now,
        )
        .unwrap();

        assert_eq!(decision.kind(), OutcomeKind::BothDivergent);
        assert_eq!(decision.selected_namespace(), Some(Namespace::Icann));
        assert_ne!(
            decision.divergence().unwrap().bits()
                & hns_namespace_resolution::DivergenceMask::ENDPOINTS.bits(),
            0,
        );
        let NamespaceOutcome::BothDivergent { hns, icann, .. } = decision.outcome() else {
            panic!("different AAAA endpoints must retain both divergent plans");
        };
        assert_eq!(hns.endpoints().len(), 2);
        assert_eq!(icann.endpoints().len(), 2);
    }

    #[test]
    fn relay_peer_refresh_merges_discovery_bans_and_local_penalties() {
        let path = temp_dir_path("relay-peer-refresh");
        std::fs::create_dir_all(&path).unwrap();
        let peer_store_path = path.join("peers.sqlite");
        let retained: SocketAddr = "1.1.1.1:12038".parse().unwrap();
        let discovered: SocketAddr = "8.8.8.8:12038".parse().unwrap();
        let removed: SocketAddr = "9.9.9.9:12038".parse().unwrap();
        let now = 1_000;

        let mut local = PeerManager::default();
        local.upsert(retained).score = 25;
        local.upsert(removed).score = 30;
        let mut client = DnsRelayClient::new(hns_core::network::mainnet(), local);

        let mut stored = PeerManager::default();
        let retained_store = stored.upsert(retained);
        retained_store.score = 5;
        retained_store.banned_until = Some(now + 600);
        stored.upsert(discovered).last_height = Height(300);
        SqlitePeerStore::open(&peer_store_path)
            .unwrap()
            .save_manager(&stored)
            .unwrap();

        assert!(
            refresh_dns_relay_peers(
                &peer_store_path,
                NetworkKind::Mainnet,
                &mut client,
                None,
                now,
            )
            .unwrap()
        );
        let peers = client.peer_manager();
        assert_eq!(peers.get(retained).unwrap().score, 25);
        assert!(peers.get(retained).unwrap().is_banned(now));
        assert_eq!(peers.get(discovered).unwrap().last_height, Height(300));
        assert!(peers.get(removed).is_none());
        cleanup_dir(&path);
    }

    #[test]
    fn fallback_resolver_uses_doh_on_proof_unavailable_in_compatibility_mode() {
        let marker = FallbackMarker::default();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("welcome").unwrap(),
            records: vec![address_record("welcome", [127, 0, 0, 1])],
            secure: true,
        };
        let resolver = FallbackResolver::with_marker(
            TestResolver::error(|| ResolverError::ProofUnavailable),
            TestResolver::answer(answer.clone()),
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap(),
            answer,
        );
        assert_eq!(marker.reason(), Some("local_hns_proof_unavailable"));
    }

    #[test]
    fn compatibility_fallback_uses_doh_on_stale_cached_non_inclusion() {
        let path = temp_dir_path("stale-negative-compat-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "future".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([9; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let target_height = 37;
        store_peer_height(&base, target_height);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let marker = FallbackMarker::default();
        let fallback_answer = ResolutionAnswer {
            name: DnsName::from_ascii(&root_name).unwrap(),
            records: vec![address_record(&root_name, [203, 0, 113, 8])],
            secure: true,
        };
        let primary = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );
        let resolver = FallbackResolver::with_marker(
            primary,
            TestResolver::answer(fallback_answer.clone()),
            marker.clone(),
        );

        let resolved = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(resolved, fallback_answer);
        assert_eq!(marker.reason(), Some("local_chain_not_current"));
        cleanup_dir(&path);
    }

    #[test]
    fn stale_cached_inclusion_stops_before_delegated_resolution() {
        let path = temp_dir_path("stale-inclusion-before-delegated-resolution");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "stale-included".to_owned();
        let request_name = format!("www.{root_name}");
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([12; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(&base, 37);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_ds_glue4_resource(&root_name, [203, 0, 113, 53]),
                )
                .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let delegated_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver = DelegatingResolver::new(
            GatewayProofProvider::new(base, resources, NetworkKind::Mainnet),
            CountingAnswerDelegatedResolver {
                calls: delegated_calls.clone(),
                answer: ResolutionAnswer {
                    name: DnsName::from_ascii(&request_name).unwrap(),
                    records: vec![address_record(&request_name, [203, 0, 113, 80])],
                    secure: true,
                },
            },
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: request_name,
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::LocalChainNotCurrent);
        assert_eq!(delegated_calls.load(Ordering::Relaxed), 0);
        cleanup_dir(&path);
    }

    #[test]
    fn current_cached_inclusion_continues_to_delegated_resolution() {
        let path = temp_dir_path("current-inclusion-delegated-resolution");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "current-included".to_owned();
        let request_name = format!("www.{root_name}");
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([13; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(&base, proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_ds_glue4_resource(&root_name, [203, 0, 113, 53]),
                )
                .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let delegated_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let expected = ResolutionAnswer {
            name: DnsName::from_ascii(&request_name).unwrap(),
            records: vec![address_record(&request_name, [203, 0, 113, 80])],
            secure: true,
        };
        let resolver = DelegatingResolver::new(
            GatewayProofProvider::new(base, resources, NetworkKind::Mainnet),
            CountingAnswerDelegatedResolver {
                calls: delegated_calls.clone(),
                answer: expected.clone(),
            },
        );

        let resolved = resolver
            .resolve(&ResolutionRequest {
                qname: request_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(resolved, expected);
        assert_eq!(delegated_calls.load(Ordering::Relaxed), 1);
        cleanup_dir(&path);
    }

    #[test]
    fn compatibility_fallback_keeps_current_non_inclusion_as_name_not_found() {
        let path = temp_dir_path("current-negative-no-fallback");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "missing".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([10; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(&base, proof_height.0 + LOCAL_CHAIN_CURRENTNESS_ALLOWED_LAG);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let marker = FallbackMarker::default();
        let fallback_answer = ResolutionAnswer {
            name: DnsName::from_ascii(&root_name).unwrap(),
            records: vec![address_record(&root_name, [203, 0, 113, 9])],
            secure: true,
        };
        let primary = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );
        let resolver = FallbackResolver::with_marker(
            primary,
            TestResolver::answer(fallback_answer),
            marker.clone(),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::NameNotFound);
        assert!(!marker.used());
        assert_eq!(marker.reason(), None);
        cleanup_dir(&path);
    }

    #[test]
    fn strict_resolver_reports_stale_cached_non_inclusion_without_fallback() {
        let path = temp_dir_path("stale-negative-strict");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "future-strict".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([11; 32]);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        store_peer_height(&base, 37);
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash)
                    .with_anchor(proof_root, proof_height),
            )
            .unwrap();
        let resolver = DelegatingResolver::new(
            GatewayProofProvider::new(base.clone(), resources, NetworkKind::Mainnet),
            TestResolver::error(|| ResolverError::ProofUnavailable),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::LocalChainNotCurrent);
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(error)),
            (
                503,
                "HNS Sync Incomplete",
                "The local HNS chain is not current enough to determine this name's current state.",
            ),
        );
        cleanup_dir(&path);
    }

    #[test]
    fn fallback_resolver_does_not_use_doh_on_name_not_found() {
        let marker = FallbackMarker::default();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("missing").unwrap(),
            records: vec![address_record("missing", [203, 0, 113, 10])],
            secure: true,
        };
        let resolver = FallbackResolver::with_marker(
            TestResolver::error(|| ResolverError::NameNotFound),
            TestResolver::answer(answer),
            marker.clone(),
        );

        let error = resolver
            .resolve(&ResolutionRequest {
                qname: "missing".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap_err();

        assert_eq!(error, ResolverError::NameNotFound);
        assert!(!marker.used());
    }

    #[test]
    fn strict_resolver_keeps_proof_errors_fail_closed() {
        let resolver = TestResolver::error(|| ResolverError::ProofUnavailable);

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn doh_response_parser_uses_ad_bit_for_secure_answers() {
        let qname = DnsName::from_ascii("nathan.woodburn").unwrap();
        let answer_record = address_record("nathan.woodburn", [103, 152, 197, 116]);
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a0),
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 2,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: vec![answer_record.clone()],
            authorities: Vec::new(),
            additionals: vec![
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
                    class: DEFAULT_DNS_UDP_PAYLOAD as u16,
                    ttl: DNSSEC_DO_FLAG,
                    rdata: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
                },
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(24),
                    class: 255,
                    ttl: 0,
                    rdata: vec![0, 253, 0, 0, 0, 0, 0, 0],
                },
            ],
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        let answer = doh_answer_from_body(0x1234, &qname, RecordType::A, &body).unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records, vec![answer_record]);
    }

    #[test]
    fn doh_response_parser_preserves_authenticated_nxdomain_expiry() {
        let qname = DnsName::from_ascii("_443._tcp.missing.example").unwrap();
        let zone = DnsName::from_ascii("example").unwrap();
        let mut soa_rdata = vec![0, 0];
        soa_rdata.extend(1_u32.to_be_bytes());
        soa_rdata.extend(2_u32.to_be_bytes());
        soa_rdata.extend(3_u32.to_be_bytes());
        soa_rdata.extend(4_u32.to_be_bytes());
        soa_rdata.extend(90_u32.to_be_bytes());
        let signature_expiration = u32::try_from(now_unix_seconds() + 600).unwrap();
        let rrsig = |owner: DnsName, covered_type: RecordType| {
            let mut rdata = vec![0; 12];
            rdata[..2].copy_from_slice(&covered_type.code().to_be_bytes());
            rdata[8..12].copy_from_slice(&signature_expiration.to_be_bytes());
            ResourceRecord {
                name: owner,
                record_type: RecordType::Rrsig,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata,
            }
        };
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a3),
                question_count: 1,
                answer_count: 0,
                authority_count: 4,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::Tlsa,
                class: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: vec![
                ResourceRecord {
                    name: zone.clone(),
                    record_type: RecordType::Soa,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: soa_rdata,
                },
                rrsig(zone, RecordType::Soa),
                ResourceRecord {
                    name: qname.clone(),
                    record_type: RecordType::Nsec,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: vec![0],
                },
                rrsig(qname.clone(), RecordType::Nsec),
            ],
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        let (answer, observation) =
            doh_answer_and_observation_from_body(0x1234, &qname, RecordType::Tlsa, &body).unwrap();

        assert!(answer.records.is_empty());
        assert!(answer.secure);
        assert_eq!(observation.kind, IcannDohAnswerKind::NxDomain);
        assert_eq!(observation.rcode, DNS_RCODE_NXDOMAIN);
        assert_eq!(
            observation.expires_at_unix - observation.observed_at_unix,
            90
        );
    }

    #[test]
    fn secure_negative_expiry_requires_and_caps_each_denial_rrset_signature() {
        let observed_at_unix = 1_800_000_000;
        let zone = DnsName::from_ascii("example").unwrap();
        let denied = DnsName::from_ascii("missing.example").unwrap();
        let mut soa_rdata = vec![0, 0];
        soa_rdata.extend(1_u32.to_be_bytes());
        soa_rdata.extend(2_u32.to_be_bytes());
        soa_rdata.extend(3_u32.to_be_bytes());
        soa_rdata.extend(4_u32.to_be_bytes());
        soa_rdata.extend(300_u32.to_be_bytes());
        let rrsig = |owner: DnsName, covered_type: RecordType, expiration: u32| -> ResourceRecord {
            let mut rdata = vec![0; 12];
            rdata[..2].copy_from_slice(&covered_type.code().to_be_bytes());
            rdata[8..12].copy_from_slice(&expiration.to_be_bytes());
            ResourceRecord {
                name: owner,
                record_type: RecordType::Rrsig,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata,
            }
        };
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a3),
                question_count: 1,
                answer_count: 0,
                authority_count: 4,
                additional_count: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: vec![
                ResourceRecord {
                    name: zone.clone(),
                    record_type: RecordType::Soa,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: soa_rdata,
                },
                rrsig(
                    zone,
                    RecordType::Soa,
                    u32::try_from(observed_at_unix + 40).unwrap(),
                ),
                ResourceRecord {
                    name: denied.clone(),
                    record_type: RecordType::Nsec,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: vec![0],
                },
                rrsig(
                    denied.clone(),
                    RecordType::Nsec,
                    u32::try_from(observed_at_unix + 15).unwrap(),
                ),
            ],
            additionals: Vec::new(),
        };

        assert_eq!(
            icann_doh_evidence_expiry(
                &message,
                IcannDohAnswerKind::NxDomain,
                true,
                observed_at_unix,
            ),
            Some(observed_at_unix + 15),
        );

        let mut missing_denial_signature = message;
        missing_denial_signature.authorities.pop();
        missing_denial_signature.authorities.push(rrsig(
            denied,
            RecordType::A,
            u32::try_from(observed_at_unix + 10).unwrap(),
        ));
        assert_eq!(
            icann_doh_evidence_expiry(
                &missing_denial_signature,
                IcannDohAnswerKind::NxDomain,
                true,
                observed_at_unix,
            ),
            None,
        );
    }

    #[test]
    fn doh_response_parser_rejects_negative_answer_without_soa_expiry() {
        let qname = DnsName::from_ascii("missing.example").unwrap();
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a3),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_and_observation_from_body(0x1234, &qname, RecordType::A, &body).unwrap_err(),
            ResolverError::InvalidDnsResponse
        );
    }

    #[test]
    fn doh_response_parser_rejects_truncated_authenticated_denial() {
        let qname = DnsName::from_ascii("_443._tcp.missing.example").unwrap();
        let mut soa_rdata = vec![0, 0];
        soa_rdata.extend(1_u32.to_be_bytes());
        soa_rdata.extend(2_u32.to_be_bytes());
        soa_rdata.extend(3_u32.to_be_bytes());
        soa_rdata.extend(4_u32.to_be_bytes());
        soa_rdata.extend(90_u32.to_be_bytes());
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x83a0),
                question_count: 1,
                answer_count: 0,
                authority_count: 1,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::Tlsa,
                class: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: vec![ResourceRecord {
                name: DnsName::from_ascii("example").unwrap(),
                record_type: RecordType::Soa,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata: soa_rdata,
            }],
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_and_observation_from_body(0x1234, &qname, RecordType::Tlsa, &body)
                .unwrap_err(),
            ResolverError::InvalidDnsResponse,
        );
    }

    #[test]
    fn doh_response_parser_rejects_nxdomain_with_positive_answer_data() {
        let qname = DnsName::from_ascii("contradictory.example").unwrap();
        let mut soa_rdata = vec![0, 0];
        soa_rdata.extend(1_u32.to_be_bytes());
        soa_rdata.extend(2_u32.to_be_bytes());
        soa_rdata.extend(3_u32.to_be_bytes());
        soa_rdata.extend(4_u32.to_be_bytes());
        soa_rdata.extend(90_u32.to_be_bytes());
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a3),
                question_count: 1,
                answer_count: 1,
                authority_count: 1,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: vec![address_record("contradictory.example", [8, 8, 8, 8])],
            authorities: vec![ResourceRecord {
                name: DnsName::from_ascii("example").unwrap(),
                record_type: RecordType::Soa,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata: soa_rdata,
            }],
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_and_observation_from_body(0x1234, &qname, RecordType::A, &body).unwrap_err(),
            ResolverError::InvalidDnsResponse,
        );
    }

    #[test]
    fn doh_response_parser_rejects_cname_nxdomain_instead_of_discarding_alias_ttl() {
        let qname = DnsName::from_ascii("alias.example").unwrap();
        let mut cname_rdata = Vec::new();
        DnsName::from_ascii("missing.example")
            .unwrap()
            .encode_wire(&mut cname_rdata)
            .unwrap();
        let mut soa_rdata = vec![0, 0];
        soa_rdata.extend(1_u32.to_be_bytes());
        soa_rdata.extend(2_u32.to_be_bytes());
        soa_rdata.extend(3_u32.to_be_bytes());
        soa_rdata.extend(4_u32.to_be_bytes());
        soa_rdata.extend(90_u32.to_be_bytes());
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a3),
                question_count: 1,
                answer_count: 1,
                authority_count: 1,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: vec![ResourceRecord {
                name: qname.clone(),
                record_type: RecordType::Cname,
                class: DNS_CLASS_IN,
                ttl: 5,
                rdata: cname_rdata,
            }],
            authorities: vec![ResourceRecord {
                name: DnsName::from_ascii("example").unwrap(),
                record_type: RecordType::Soa,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata: soa_rdata,
            }],
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_and_observation_from_body(0x1234, &qname, RecordType::A, &body).unwrap_err(),
            ResolverError::InvalidDnsResponse,
        );
    }

    #[test]
    fn secure_positive_icann_evidence_is_capped_by_rrsig_expiration() {
        let observed_at_unix = 1_800_000_000;
        let signature_expiration = observed_at_unix + 20;
        let mut rrsig_rdata = vec![0; 12];
        rrsig_rdata[8..12]
            .copy_from_slice(&u32::try_from(signature_expiration).unwrap().to_be_bytes());
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a0),
                question_count: 1,
                answer_count: 2,
                authority_count: 0,
                additional_count: 0,
            },
            questions: Vec::new(),
            answers: vec![
                ResourceRecord {
                    name: DnsName::from_ascii("signed.example").unwrap(),
                    record_type: RecordType::A,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: vec![8, 8, 8, 8],
                },
                ResourceRecord {
                    name: DnsName::from_ascii("signed.example").unwrap(),
                    record_type: RecordType::Rrsig,
                    class: DNS_CLASS_IN,
                    ttl: 300,
                    rdata: rrsig_rdata,
                },
            ],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        assert_eq!(
            icann_doh_evidence_expiry(
                &message,
                IcannDohAnswerKind::Present,
                true,
                observed_at_unix,
            ),
            Some(signature_expiration),
        );
    }

    #[test]
    fn doh_response_parser_returns_response_code_for_servfail() {
        let qname = DnsName::from_ascii("servfail.example").unwrap();
        let message = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8182),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        assert_eq!(
            doh_answer_from_body(DOH_DNS_ID, &qname, RecordType::A, &body).unwrap_err(),
            ResolverError::DnsResponseCode(2),
        );
    }

    #[test]
    fn doh_http_status_allows_any_successful_2xx() {
        assert!(!doh_http_status_success(199));
        assert!(doh_http_status_success(200));
        assert!(doh_http_status_success(204));
        assert!(doh_http_status_success(299));
        assert!(!doh_http_status_success(300));
    }

    #[test]
    fn doh_response_requires_dns_message_content_type() {
        let mut response = OriginResponse {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "Application/DNS-Message".to_owned(),
            )],
            body: Vec::new(),
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        };

        assert!(doh_response_has_dns_message_content_type(&response));

        response.headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        assert!(!doh_response_has_dns_message_content_type(&response));

        response.headers.clear();
        assert!(!doh_response_has_dns_message_content_type(&response));
    }

    #[test]
    fn doh_trace_requires_a_matching_dns_message_and_accepts_valid_2xx() {
        let qname = DnsName::from_ascii("denuoweb").unwrap();
        let query = build_doh_query(DOH_DNS_ID, &qname, RecordType::A).unwrap();
        let question = DnsMessage::parse(&query).unwrap().questions[0].clone();
        let body = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8180),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(&DnsEncodeConfig {
            max_message_len: 4096,
        })
        .unwrap();
        let response = OriginResponse {
            status: 201,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/dns-message".to_owned(),
            )],
            body,
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        };

        let valid = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(response.clone()),
        );
        assert_eq!(valid.status, "ok");

        let mut servfail_response = response.clone();
        servfail_response.body[3] = (servfail_response.body[3] & 0xf0) | 2;
        let servfail = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(servfail_response),
        );
        assert_eq!(servfail.status, "invalid_response");

        let invalid = doh_trace_event(
            "authoritative_doh",
            "https://denuoweb:8443/dns-query".to_owned(),
            &query,
            1,
            &Ok(OriginResponse {
                body: Vec::new(),
                ..response
            }),
        );
        assert_eq!(invalid.status, "invalid_response");
    }

    #[test]
    fn recursive_doh_query_uses_zero_dns_id_on_wire() {
        let qname = DnsName::from_ascii("dane-test.denuoweb.com").unwrap();
        let query = build_doh_query(0x1234, &qname, RecordType::A).unwrap();

        let (wire_query, original_id) = recursive_doh_query(&query).unwrap();
        let wire_message = DnsMessage::parse(&wire_query).unwrap();

        assert_eq!(original_id, 0x1234);
        assert_eq!(wire_message.header.id, DOH_DNS_ID);
        assert!(wire_message.header.flags.recursion_desired());

        let response = DnsMessage {
            header: DnsHeader {
                id: DOH_DNS_ID,
                flags: DnsFlags::new(0x8180),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: wire_message.questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(&DnsEncodeConfig {
            max_message_len: 4096,
        })
        .unwrap();

        let restored = restore_doh_response_id(&response, original_id).unwrap();
        let restored_message = DnsMessage::parse(&restored).unwrap();
        assert_eq!(restored_message.header.id, 0x1234);
    }

    #[test]
    fn doh_query_requests_authentic_data_and_dnssec_records() {
        let qname = DnsName::from_ascii("dane-test.denuoweb.com").unwrap();
        let query = build_doh_query(0x1234, &qname, RecordType::A).unwrap();
        let message = DnsMessage::parse(&query).unwrap();

        assert_eq!(message.header.id, 0x1234);
        assert!(message.header.flags.recursion_desired());
        assert_ne!(message.header.flags.bits() & DNS_AUTHENTIC_DATA_FLAG, 0);
        assert_eq!(message.questions[0].name, qname);
        assert_eq!(message.questions[0].record_type, RecordType::A);
        assert_eq!(message.additionals.len(), 1);
        assert_eq!(
            message.additionals[0].record_type,
            RecordType::Unknown(DNS_OPT_RECORD_TYPE)
        );
        assert_ne!(message.additionals[0].ttl & DNSSEC_DO_FLAG, 0);
    }

    #[test]
    fn gateway_response_fails_closed_without_resolver_backend() {
        let path = temp_dir_path("gateway-empty");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "X-HNS-Browser-Strict-Mode: 1\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 502 Origin Namespace Indeterminate\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_rejects_malformed_forwarded_headers() {
        let path = temp_dir_path("gateway-bad-headers");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "not-a-header\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(text.ends_with("http://welcome/\n400 Bad Request\nrequest header is malformed\n"));
        assert_eq!(
            parse_gateway_headers("X-Test: bad\0value\r\n")
                .err()
                .as_deref(),
            Some("request header is invalid")
        );
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_errors_are_mapped_to_actionable_hns_stages() {
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::ProofUnavailable)),
            (
                503,
                "HNS Proof Unavailable",
                "No current verified HNS proof is available for this name.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NameNotFound)),
            (
                404,
                "HNS Name Not Found",
                "A verified HNS non-inclusion proof says this name does not exist.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NoNameserverAddress)),
            (
                502,
                "HNS Nameserver Unavailable",
                "No verified nameserver address is available for this HNS delegation.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnsTransport(
                "timeout".to_owned(),
            ))),
            (
                502,
                "HNS Nameserver Unavailable",
                "Delegated HNS nameserver transport failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidDnsResponse)),
            (
                502,
                "HNS Nameserver Response Invalid",
                "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnssecFailed)),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Delegated HNS DNSSEC validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidResource(
                ResourceError::Malformed,
            ))),
            (
                502,
                "HNS Resource Invalid",
                "Verified HNS resource data is malformed or unsupported.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::InsecureResolution),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Secure HNS resolution was required but the resolver returned an insecure result.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::NoResolvedAddress),
            (
                502,
                "HNS Origin Address Missing",
                "Secure HNS resolution did not produce an origin A or AAAA address.",
            ),
        );
        assert_eq!(
            map_gateway_error_for_namespace(
                Some(Namespace::Icann),
                &GatewayError::NoResolvedAddress,
                &DnsTraceRecorder::default(),
            ),
            (
                502,
                "ICANN Origin Address Missing",
                "Secure ICANN DNS resolution did not produce an origin A or AAAA address.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::DaneFailed)),
            (
                502,
                "HNS DANE Validation Failed",
                "DANE/TLSA validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::UnsupportedSvcb),
            (
                502,
                "HNS HTTPS Service Unsupported",
                "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Io(
                "refused".to_owned(),
            ))),
            (
                502,
                "HNS Origin Transport Failed",
                "Origin connection failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Io(
                "invalid peer certificate: certificate expired: verification time 1783324451, but certificate is not valid after 1680922072".to_owned(),
            ))),
            (
                502,
                "HNS Origin Certificate Expired",
                "Origin HTTPS certificate is expired; renew the certificate and retry.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Http3(
                "frame error".to_owned(),
            ))),
            (
                502,
                "HNS HTTP/3 Transport Failed",
                "Origin HTTP/3 exchange failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Quic(
                "handshake failed".to_owned(),
            ))),
            (
                502,
                "HNS QUIC Transport Failed",
                "Origin QUIC connection failed closed.",
            ),
        );
    }

    #[test]
    fn classification_transport_failure_requires_positive_probe_for_interception_detail() {
        let query = OriginQuery::new(
            CanonicalHost::parse("intercepted.example").unwrap(),
            hns_namespace_resolution::OriginScheme::Https,
            NonZeroU16::new(443),
            hns_namespace_resolution::ProtocolCapabilities::all(),
        );
        let error = GatewayError::Resolver(ResolverError::NamespaceClassification(
            ClassificationError::RootFailed {
                hns: RootResolutionState::Failed(RootFailure::new(
                    Namespace::Hns,
                    query,
                    RootFailureKind::Transport,
                    None,
                )),
                icann: RootResolutionState::Absent,
            },
        ));
        let generic = map_gateway_error(&error);
        assert_eq!(
            map_gateway_error_for_namespace(None, &error, &DnsTraceRecorder::default()),
            generic
        );

        let inconclusive = DnsTraceRecorder::default();
        inconclusive.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "inconclusive".to_owned(),
            elapsed_ms: 1,
            error: Some("unrelated reply".to_owned()),
        });
        assert_eq!(
            map_gateway_error_for_namespace(None, &error, &inconclusive),
            generic
        );

        let detected = DnsTraceRecorder::default();
        detected.push(DnsTraceEvent {
            protocol: "dns_interception_probe",
            server: "192.0.2.1:53".to_owned(),
            question_name: Some(DNS_INTERCEPTION_PROBE_NAME.to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "detected".to_owned(),
            elapsed_ms: 1,
            error: Some(
                "received a matching DNS reply from a non-routable TEST-NET destination".to_owned(),
            ),
        });
        assert_eq!(
            map_gateway_error_for_namespace(None, &error, &detected),
            (
                502,
                HNS_PORT53_INTERCEPTION_REASON,
                "This network intercepted direct authoritative DNS and no authenticated alternate completed.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443 (an HNS hnsdns=1 declaration with proven glue plus a TLSA pin, or supported authenticated _dns.<NS> SVCB).\n\nUsers can enable the requester-only P2P DNS relay or configure an explicit recursive HNS DoH URL in extension settings; both retain local DNSSEC and DANE verification.",
            )
        );
    }

    #[test]
    fn interception_recovery_details_keep_action_groups_in_separate_paragraphs() {
        let p2p = DnsTraceRecorder::default();
        p2p.record_relay(DnsRelayTraceMetadata {
            peer: None,
            retries: 0,
            service_advertised: None,
            error: Some("exhausted".to_owned()),
        });
        let configured = DnsTraceRecorder::default();
        configured.push(DnsTraceEvent {
            protocol: "user_configured_recursive_hns_doh",
            server: "https://resolver.example/dns-query".to_owned(),
            question_name: Some("shakeshift".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "transport_error".to_owned(),
            elapsed_ms: 1,
            error: Some("exhausted".to_owned()),
        });
        let both = DnsTraceRecorder::default();
        both.record_relay(DnsRelayTraceMetadata {
            peer: None,
            retries: 0,
            service_advertised: None,
            error: Some("exhausted".to_owned()),
        });
        both.push(DnsTraceEvent {
            protocol: "user_configured_recursive_hns_doh",
            server: "https://resolver.example/dns-query".to_owned(),
            question_name: Some("shakeshift".to_owned()),
            question_type: Some(RecordType::A.code()),
            status: "transport_error".to_owned(),
            elapsed_ms: 1,
            error: Some("exhausted".to_owned()),
        });

        for trace in [DnsTraceRecorder::default(), p2p, configured] {
            let (_, _, detail) = interception_recovery_error(&trace);
            let paragraphs = detail.split("\n\n").collect::<Vec<_>>();
            assert_eq!(paragraphs.len(), 3, "{detail}");
            assert!(paragraphs[0].starts_with("This network intercepted"));
            assert!(paragraphs[1].starts_with("Site owners"));
            assert!(paragraphs[2].starts_with("Users"));
        }
        let (_, _, detail) = interception_recovery_error(&both);
        let paragraphs = detail.split("\n\n").collect::<Vec<_>>();
        assert_eq!(paragraphs.len(), 2, "{detail}");
        assert!(paragraphs[0].starts_with("This network intercepted"));
        assert!(paragraphs[1].starts_with("Site owners"));

        let (_, _, direct_detail) = map_gateway_error(&GatewayError::Resolver(
            ResolverError::Port53InterceptionDetected,
        ));
        assert_eq!(
            direct_detail,
            "This network intercepted direct authoritative DNS.\n\nSite owners can publish proof-anchored authoritative DoH on HTTPS 443.\n\nUsers can enable the requester-only P2P DNS relay or configure an explicit recursive HNS DoH URL in extension settings."
        );
    }

    #[test]
    fn interception_document_links_exact_hns_root_and_verified_nameserver() {
        let input = GatewayHttpRequestInput {
            data_dir: "",
            method: "GET",
            scheme: "https",
            host: "shakeshift",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let dns_trace = trace_with_hns_nameserver("shakeshift", "a.namenode");
        let (_, reason, detail) = interception_recovery_error(&dns_trace);
        let document = gateway_error_document(&input, 502, reason, detail, &dns_trace);
        let body = String::from_utf8(document.body).unwrap();

        assert_eq!(document.content_type, "text/html; charset=utf-8");
        assert!(body.contains(
            "href=\"https://hns.denuoweb.com/dane-generator/?domain=shakeshift%2F&amp;domain_type=hns&amp;intent=authoritative_doh&amp;mode=delegated&amp;nameserver=a.namenode\""
        ));
        assert!(body.contains("Open the DANE generator for shakeshift/"));
        assert!(body.contains(
            "</p><p>Site owners can publish proof-anchored authoritative DoH on HTTPS 443"
        ));
        assert!(body.contains("</p><p>Users can enable the requester-only P2P DNS relay"));
        for (name, value) in [
            ("Content-Security-Policy", INTERCEPTION_ERROR_CSP),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("Cache-Control", "no-store"),
        ] {
            assert!(
                document
                    .headers
                    .contains(&(name.to_owned(), value.to_owned()))
            );
        }
    }

    #[test]
    fn conflicting_hns_delegation_trace_permanently_omits_nameserver_guidance() {
        let trace = trace_with_hns_nameserver("shakeshift", "a.namenode");
        let owner = DnsName::from_ascii("shakeshift").unwrap();
        let target = DnsName::from_ascii("b.namenode").unwrap();
        let mut rdata = Vec::new();
        target.encode_wire(&mut rdata).unwrap();
        trace.record_hns_delegation(&HnsDelegation {
            root_name: "shakeshift".to_owned(),
            owner: owner.clone(),
            records: vec![ResourceRecord {
                name: owner,
                record_type: RecordType::Ns,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata,
            }],
        });

        assert_eq!(trace.hns_delegation_snapshot(), None);
        let (url, _) = interception_generator_handoff("shakeshift", &trace).unwrap();
        assert!(!url.contains("nameserver="));

        let owner = DnsName::from_ascii("shakeshift").unwrap();
        let target = DnsName::from_ascii("a.namenode").unwrap();
        let mut rdata = Vec::new();
        target.encode_wire(&mut rdata).unwrap();
        trace.record_hns_delegation(&HnsDelegation {
            root_name: "shakeshift".to_owned(),
            owner: owner.clone(),
            records: vec![ResourceRecord {
                name: owner,
                record_type: RecordType::Ns,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata,
            }],
        });
        assert_eq!(trace.hns_delegation_snapshot(), None);
    }

    #[test]
    fn interception_document_omits_unproven_nameserver_and_escapes_request_path() {
        let input = GatewayHttpRequestInput {
            data_dir: "",
            method: "GET",
            scheme: "https",
            host: "www.shakeshift",
            port: 443,
            path_and_query: "/<script>alert('x')</script>?a=\"&b=1",
            header_text: "",
            body: &[],
        };
        let dns_trace = DnsTraceRecorder::default();
        let (_, reason, detail) = interception_recovery_error(&dns_trace);
        let document = gateway_error_document(&input, 502, reason, detail, &dns_trace);
        let body = String::from_utf8(document.body).unwrap();
        let href = body
            .split_once("href=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(href, _)| href)
            .unwrap();

        assert_eq!(
            href,
            "https://hns.denuoweb.com/dane-generator/?domain=shakeshift%2F&amp;domain_type=hns&amp;intent=authoritative_doh&amp;mode=delegated"
        );
        assert!(!href.contains("nameserver="));
        assert!(!href.contains("script"));
        assert!(!body.contains("<script>"));
        assert!(body.contains(
            "https://www.shakeshift/&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;?a=&quot;&amp;b=1"
        ));

        let plain = gateway_error_document(
            &input,
            404,
            "HNS Name Not Found",
            "A verified non-inclusion proof says this name does not exist.",
            &dns_trace,
        );
        assert_eq!(plain.content_type, "text/plain; charset=utf-8");
        assert!(plain.headers.is_empty());
    }

    #[test]
    fn encoded_and_file_interception_responses_are_identical() {
        let directory = temp_dir_path("interception-response-parity");
        let body_path = directory.join("body.html");
        let input = GatewayHttpRequestInput {
            data_dir: "",
            method: "GET",
            scheme: "https",
            host: "shakeshift",
            port: 443,
            path_and_query: "/",
            header_text: "",
            body: &[],
        };
        let dns_trace = trace_with_hns_nameserver("shakeshift", "a.namenode");
        let (_, reason, detail) = interception_recovery_error(&dns_trace);
        let trace_json = r#"{"mode":"strict","fallback":{"used":false}}"#;
        let encoded = gateway_error_response_for_request_with_trace(
            &input, 502, reason, detail, trace_json, &dns_trace,
        );
        let encoded_head = gateway_error_response_to_file_for_request_with_trace(
            &input, 502, reason, detail, &body_path, trace_json, &dns_trace,
        )
        .unwrap();
        let file_body = fs::read(&body_path).unwrap();

        assert!(encoded.starts_with(&encoded_head));
        assert_eq!(&encoded[encoded_head.len()..], file_body);
        let head = String::from_utf8(encoded_head).unwrap();
        assert!(head.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(head.contains(&format!(
            "Content-Security-Policy: {INTERCEPTION_ERROR_CSP}\r\n"
        )));
        assert!(head.contains("Referrer-Policy: no-referrer\r\n"));
        assert!(head.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(head.contains("Cache-Control: no-store\r\n"));
        cleanup_dir(&directory);
    }

    #[test]
    fn gateway_response_fetches_hns_http_from_persistent_resource_cache() {
        let path = temp_dir_path("gateway-http");
        let base = path.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        store_peer_height(&base, anchor_height.0);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_dual_stack_resource(
                        &root_name,
                        [127, 0, 0, 1],
                        Ipv6Addr::LOCALHOST.octets(),
                    ),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\nhi") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /path HTTP/1.1\r\n"));
            assert!(request.contains("Content-Type: text/plain\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(request.contains("Content-Length: 2\r\n"));
            assert!(request.ends_with("\r\n\r\nhi"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "POST",
            scheme: "http",
            host: &root_name,
            port,
            path_and_query: "/path",
            header_text: "Content-Type: text/plain\r\nX-Test: yes\r\nX-HNS-Browser-Network: regtest\r\n",
            body: b"hi",
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\nok"));
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_rejects_non_tip_cached_resource_proof() {
        let path = temp_dir_path("gateway-http-recent-proof");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([5; 32]);
        let newer_root = Hash::new([6; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[proof_root, newer_root]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(proof_root, heights[0]),
            )
            .unwrap();

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port: 80,
            path_and_query: "/recent",
            header_text: "X-HNS-Browser-Strict-Mode: 1\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 502 Origin Namespace Indeterminate\r\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_streams_body_to_file_with_fixed_length_head() {
        let path = temp_dir_path("gateway-file-body");
        let base = path.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        store_peer_height(&base, anchor_height.0);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_dual_stack_resource(
                        &root_name,
                        [127, 0, 0, 1],
                        Ipv6Addr::LOCALHOST.octets(),
                    ),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\nlive\r\n0\r\n\r\n",
                )
                .unwrap();
        });

        let body_path = path.join("response.body");
        let head = gateway_http_response_body_to_file(
            GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "http",
                host: &root_name,
                port,
                path_and_query: "/stream",
                header_text: "X-HNS-Browser-Network: regtest\r\n",
                body: &[],
            },
            &body_path,
        )
        .unwrap();
        let text = String::from_utf8(head).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(!text.contains("Transfer-Encoding"));
        assert_eq!(std::fs::read(&body_path).unwrap(), b"live");
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn download_body_is_not_published_when_namespace_binding_persistence_fails() {
        let path = temp_dir_path("gateway-file-binding-failure");
        let base = path.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([58; 32]);
        let anchor_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, anchor_root);
        store_peer_height(&base, anchor_height.0);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_dual_stack_resource(
                        &root_name,
                        [127, 0, 0, 1],
                        Ipv6Addr::LOCALHOST.octets(),
                    ),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        drop(resources);

        let runtime =
            BrowserRuntime::open(RuntimeConfiguration::new(&path, NetworkKind::Regtest)).unwrap();
        let binding_path = base.join("namespace-bindings.sqlite");
        Connection::open(&binding_path)
            .unwrap()
            .execute_batch(
                "
                CREATE TRIGGER reject_namespace_binding
                BEFORE INSERT ON namespace_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'forced binding persistence failure');
                END;
                ",
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlive")
                .unwrap();
        });

        let body_path = path.join("response.body");
        fs::write(&body_path, b"sentinel").unwrap();
        let error = runtime
            .raw_gateway_request_body_to_file(
                RawGatewayHttpRequest {
                    method: "GET".to_owned(),
                    scheme: "http".to_owned(),
                    host: root_name,
                    port: i32::from(port),
                    path_and_query: "/download".to_owned(),
                    header_text: String::new(),
                    body: Vec::new(),
                },
                RuntimePolicy::compatibility(),
                &body_path,
            )
            .unwrap_err();

        assert!(
            matches!(
                error,
                RuntimeError::Operation(ref detail)
                    if detail.contains("persist namespace binding")
            ),
            "{error}",
        );
        assert_eq!(fs::read(&body_path).unwrap(), b"sentinel");
        assert!(
            fs::read_dir(&path).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".hns-pending-")
            }),
            "failed download must not leave a pending body file",
        );
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_fetches_live_proof_on_resource_cache_miss() {
        let path = temp_dir_path("gateway-live-proof");
        let base = path.join("hns-regtest");
        std::fs::create_dir_all(&base).unwrap();

        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let value =
            owner_dual_stack_resource(&root_name, [127, 0, 0, 1], Ipv6Addr::LOCALHOST.octets());
        let name_state_value = name_state_value(&root_name, &value);
        let proof_root = urkel_value_root(name_hash.as_hash(), &name_state_value);
        let proof_height =
            store_best_header_for_network_with_tree_root(&base, NetworkKind::Regtest, proof_root);
        let remote_height = Height(proof_height.0 + 10);

        let proof_payload = urkel_exists_payload(&name_state_value);
        let proof_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proof_address = proof_listener.local_addr().unwrap();
        let proof_server = thread::spawn(move || {
            let (stream, _) = proof_listener.accept().unwrap();
            let mut peer = PeerConnection::new(stream, hns_core::network::regtest());
            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_)));
            let version = VersionPacket {
                height: remote_height,
                ..VersionPacket::default()
            };
            peer.send_packet(&Packet::Version(version)).unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();
            match peer.receive_packet().unwrap() {
                Packet::GetProof(request) => {
                    assert_eq!(request.root, proof_root);
                    assert_eq!(request.key, name_hash.as_hash());
                    peer.send_packet(&Packet::Proof(ProofPacket {
                        root: request.root,
                        key: request.key,
                        proof: proof_payload,
                    }))
                    .unwrap();
                }
                other => panic!("unexpected proof peer packet: {other:?}"),
            }
        });

        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let mut peers = PeerManager::default();
        peers.seed([proof_address]);
        peers.record_observed_height(proof_address, proof_height, 1);
        peer_store.save_manager(&peers).unwrap();

        let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_server = thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 512];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /live HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlive")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port: origin_port,
            path_and_query: "/live",
            header_text: "X-HNS-Browser-Network: regtest\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nlive"));
        let cached = SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .unwrap()
            .prove_resource_value(&root_name, name_hash)
            .unwrap();
        assert_eq!(cached.value, Some(value));
        assert_eq!(
            cached.anchor,
            Some(ResourceValueAnchor {
                tree_root: proof_root,
                height: proof_height,
            }),
        );
        let peer = peer_store.load_peer(proof_address).unwrap().unwrap();
        assert_eq!(peer.last_height, proof_height);
        assert_eq!(peer.last_height_observed_at, Some(1));
        assert!(
            peer.last_connected_at
                .is_some_and(|connected_at| connected_at > 1)
        );
        assert_eq!(peer.successes, 1);
        proof_server.join().unwrap();
        origin_server.join().unwrap();
        cleanup_dir(&path);
    }

    struct TestResolver {
        outcome: TestResolverOutcome,
    }

    struct TestDelegatedResolver {
        outcome: TestResolverOutcome,
    }

    struct CountingErrorDelegatedResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        error: fn() -> ResolverError,
    }

    struct CountingAnswerDelegatedResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        answer: ResolutionAnswer,
    }

    struct DnssecFailureThenAnswerDelegatedResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        answer: ResolutionAnswer,
    }

    #[derive(Clone, Default)]
    struct TestRelayDnssecFeedback {
        attempt_peers: Arc<Mutex<std::collections::VecDeque<Vec<SocketAddr>>>>,
        retry_offsets: Arc<Mutex<Vec<usize>>>,
        reported_peers: Arc<Mutex<Vec<Vec<SocketAddr>>>>,
    }

    enum TestResolverOutcome {
        Answer(ResolutionAnswer),
        Error(fn() -> ResolverError),
    }

    impl TestResolver {
        fn answer(answer: ResolutionAnswer) -> Self {
            Self {
                outcome: TestResolverOutcome::Answer(answer),
            }
        }

        fn error(error: fn() -> ResolverError) -> Self {
            Self {
                outcome: TestResolverOutcome::Error(error),
            }
        }
    }

    impl TestDelegatedResolver {
        fn answer(answer: ResolutionAnswer) -> Self {
            Self {
                outcome: TestResolverOutcome::Answer(answer),
            }
        }

        fn error(error: fn() -> ResolverError) -> Self {
            Self {
                outcome: TestResolverOutcome::Error(error),
            }
        }
    }

    impl TestRelayDnssecFeedback {
        fn with_attempt_peers(attempt_peers: impl IntoIterator<Item = Vec<SocketAddr>>) -> Self {
            Self {
                attempt_peers: Arc::new(Mutex::new(attempt_peers.into_iter().collect())),
                ..Self::default()
            }
        }

        fn retry_offsets(&self) -> Vec<usize> {
            self.retry_offsets.lock().unwrap().clone()
        }

        fn reported_peers(&self) -> Vec<Vec<SocketAddr>> {
            self.reported_peers.lock().unwrap().clone()
        }
    }

    impl RelayDnssecAttemptFeedback for TestRelayDnssecFeedback {
        fn begin_attempt(&self, retry_offset: usize) {
            self.retry_offsets.lock().unwrap().push(retry_offset);
        }

        fn finish_attempt(&self) -> Vec<SocketAddr> {
            self.attempt_peers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default()
        }

        fn report_dnssec_failure(&self, peers: &[SocketAddr]) {
            self.reported_peers.lock().unwrap().push(peers.to_vec());
        }
    }

    impl Resolver for TestResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            match &self.outcome {
                TestResolverOutcome::Answer(answer) => Ok(answer.clone()),
                TestResolverOutcome::Error(error) => Err(error()),
            }
        }
    }

    impl DelegatedResolver for TestDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            match &self.outcome {
                TestResolverOutcome::Answer(answer) => Ok(answer.clone()),
                TestResolverOutcome::Error(error) => Err(error()),
            }
        }
    }

    impl DelegatedResolver for CountingErrorDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err((self.error)())
        }
    }

    impl DelegatedResolver for CountingAnswerDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.answer.clone())
        }
    }

    impl DelegatedResolver for DnssecFailureThenAnswerDelegatedResolver {
        fn resolve_delegated(
            &self,
            _request: &ResolutionRequest,
            _delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(ResolverError::DnssecFailed)
            } else {
                Ok(self.answer.clone())
            }
        }
    }

    fn test_delegation(root_name: &str) -> HnsDelegation {
        HnsDelegation {
            root_name: root_name.to_owned(),
            owner: DnsName::from_ascii(root_name).unwrap(),
            records: Vec::new(),
        }
    }

    fn address_record(owner: &str, address: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::A,
            class: DNS_CLASS_IN,
            ttl: 20,
            rdata: address.to_vec(),
        }
    }

    fn https_alpn_record(owner: &str, protocols: &[&[u8]]) -> ResourceRecord {
        let mut alpn = Vec::new();
        for protocol in protocols {
            alpn.push(u8::try_from(protocol.len()).unwrap());
            alpn.extend_from_slice(protocol);
        }
        let mut rdata = vec![0, 1, 0, 0, 1];
        rdata.extend(u16::try_from(alpn.len()).unwrap().to_be_bytes());
        rdata.extend(alpn);
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Https,
            class: DNS_CLASS_IN,
            ttl: 20,
            rdata,
        }
    }

    fn tlsa_record(owner: &str, digest: u8) -> ResourceRecord {
        let mut rdata = vec![3, 1, 1];
        rdata.extend([digest; 32]);
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Tlsa,
            class: DNS_CLASS_IN,
            ttl: 20,
            rdata,
        }
    }

    fn cname_record(owner: &str, target: &str, ttl: u32) -> ResourceRecord {
        let mut rdata = Vec::new();
        DnsName::from_ascii(target)
            .unwrap()
            .encode_wire(&mut rdata)
            .unwrap();
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Cname,
            class: DNS_CLASS_IN,
            ttl,
            rdata,
        }
    }

    fn rrsig_record(owner: &str, covered_type: RecordType) -> ResourceRecord {
        let mut rdata = vec![0; 18];
        rdata[..2].copy_from_slice(&covered_type.code().to_be_bytes());
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Rrsig,
            class: DNS_CLASS_IN,
            ttl: 60,
            rdata,
        }
    }

    fn store_best_header_with_tree_root(base: &std::path::Path, tree_root: Hash) -> Height {
        store_canonical_headers_with_tree_roots(base, &[tree_root])
            .last()
            .copied()
            .unwrap()
    }

    fn store_best_header_for_network_with_tree_root(
        base: &std::path::Path,
        network: NetworkKind,
        tree_root: Hash,
    ) -> Height {
        store_canonical_headers_for_network_with_tree_roots(base, network, &[tree_root])
            .last()
            .copied()
            .unwrap()
    }

    fn store_peer_height(base: &std::path::Path, height: u32) {
        let addresses = [
            "1.1.1.1:12038".parse().unwrap(),
            "8.8.8.8:12038".parse().unwrap(),
            "9.9.9.9:12038".parse().unwrap(),
        ];
        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let mut peers = PeerManager::default();
        for address in addresses {
            peers.record_success(address, Height(height), now_unix_seconds());
        }
        peer_store.save_manager(&peers).unwrap();
    }

    fn store_canonical_headers_with_tree_roots(
        base: &std::path::Path,
        tree_roots: &[Hash],
    ) -> Vec<Height> {
        store_canonical_headers_for_network_with_tree_roots(base, NetworkKind::Mainnet, tree_roots)
    }

    fn store_canonical_headers_for_network_with_tree_roots(
        base: &std::path::Path,
        network: NetworkKind,
        tree_roots: &[Hash],
    ) -> Vec<Height> {
        let genesis_header = BlockHeader::genesis_for_network(network);
        let genesis = StoredHeader {
            hash: genesis_header.hash(),
            chainwork: Chainwork::from_bits(genesis_header.bits).unwrap(),
            header: genesis_header,
            height: Height(0),
        };
        let mut headers = vec![genesis.clone()];
        let mut previous = genesis;
        let mut heights = Vec::new();
        for (index, tree_root) in tree_roots.iter().copied().enumerate() {
            let mut header = BlockHeader::genesis_for_network(network);
            header.prev_block = previous.hash;
            header.tree_root = tree_root;
            header.time = header.time.saturating_add((index as u64) + 1);
            header.extra_nonce[..4].copy_from_slice(&((index as u32) + 1).to_le_bytes());
            let header_work = Chainwork::from_bits(header.bits).unwrap();
            let stored = StoredHeader {
                hash: header.hash(),
                chainwork: previous.chainwork.checked_add(&header_work),
                header,
                height: Height(previous.height.0 + 1),
            };
            heights.push(stored.height);
            headers.push(stored.clone());
            previous = stored;
        }
        let mut store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        for header in &headers {
            if store.get_header(header.hash).is_none() {
                store.put_header(header.clone()).unwrap();
            }
        }
        store.replace_canonical_chain(&headers).unwrap();
        heights
    }

    fn urkel_exists_payload(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_le(&mut out, 3 << 14);
        write_u16_le(&mut out, 0);
        write_u16_le(&mut out, value.len() as u16);
        out.extend(value);
        out
    }

    fn urkel_value_root(key: Hash, value: &[u8]) -> Hash {
        let value_hash = blake2b_256(&[value]);
        blake2b_256(&[&[0x00], key.as_bytes(), value_hash.as_bytes()])
    }

    fn owner_glue4_resource(owner: &str, address: [u8; 4]) -> Vec<u8> {
        let mut value = vec![0, 2];
        DnsName::from_ascii(owner)
            .unwrap()
            .encode_wire(&mut value)
            .unwrap();
        value.extend(address);
        value
    }

    fn owner_dual_stack_resource(owner: &str, ipv4: [u8; 4], ipv6: [u8; 16]) -> Vec<u8> {
        let mut value = owner_glue4_resource(owner, ipv4);
        value.push(3);
        DnsName::from_ascii(owner)
            .unwrap()
            .encode_wire(&mut value)
            .unwrap();
        value.extend(ipv6);
        value
    }

    fn owner_ds_glue4_resource(owner: &str, address: [u8; 4]) -> Vec<u8> {
        let mut value = vec![0, 0];
        value.extend(1_u16.to_be_bytes());
        value.push(8);
        value.push(2);
        value.push(32);
        value.extend([7; 32]);
        value.push(2);
        DnsName::from_ascii(owner)
            .unwrap()
            .encode_wire(&mut value)
            .unwrap();
        value.extend(address);
        value
    }

    fn name_state_value(name: &str, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.push(name.len() as u8);
        value.extend(name.as_bytes());
        write_u16_le(&mut value, data.len() as u16);
        value.extend(data);
        value.extend(7_u32.to_le_bytes());
        value.extend(7_u32.to_le_bytes());
        value.extend(0_u16.to_le_bytes());
        value
    }

    fn write_u16_le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }

    fn trace_with_hns_nameserver(root_name: &str, nameserver: &str) -> DnsTraceRecorder {
        let owner = DnsName::from_ascii(root_name).unwrap();
        let target = DnsName::from_ascii(nameserver).unwrap();
        let mut rdata = Vec::new();
        target.encode_wire(&mut rdata).unwrap();
        let trace = DnsTraceRecorder::default();
        trace.record_hns_delegation(&HnsDelegation {
            root_name: root_name.to_owned(),
            owner: owner.clone(),
            records: vec![ResourceRecord {
                name: owner,
                record_type: RecordType::Ns,
                class: DNS_CLASS_IN,
                ttl: 300,
                rdata,
            }],
        });
        trace
    }

    fn temp_dir_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "chromium-runtime-{label}-{}-{now}",
            std::process::id()
        ))
    }

    fn cleanup_dir(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }
}
