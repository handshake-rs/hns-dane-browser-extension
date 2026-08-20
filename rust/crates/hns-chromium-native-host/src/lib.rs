//! Rust-owned Chromium native-messaging and proxy lifecycle boundary.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod wallet_abi;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use getrandom::fill as fill_random;
use hns_browser_observability::{
    BrowserStatus as CanonicalBrowserStatus, IcannDnssecStatus as CanonicalIcannDnssecStatus,
    IcannTlsAction as CanonicalIcannTlsAction, Namespace as CanonicalNamespace,
    OutcomeKind as CanonicalOutcomeKind, ReadinessState as CanonicalReadinessState,
    RootFailureKind as CanonicalRootFailureKind, SelectionReason as CanonicalSelectionReason,
};
use hns_chromium_platform_runtime::{
    BrowserProxy, BrowserProxyObservationKind, BrowserProxyStatus, BrowserProxyStatusObserver,
    BrowserRuntime, CanonicalBrowserObservationTuple, CanonicalRootResolutionStates,
    CanonicalStatusUnavailableReason, NetworkKind, ResolutionMode, RootResolutionDisposition,
    RuntimeConfiguration, RuntimePolicy, chromium_dane_pac_script, diagnostics_json,
    normalize_configured_hns_doh_resolver,
};
use hns_loopback_proxy::LocalCertificateAuthority;
use hns_meshmine_pool_stats::{
    HRM_AUTHORITY_ADAPTER_AVAILABLE as MESHMINE_HRM_AUTHORITY_ADAPTER_AVAILABLE,
    LEGACY_HSA1_ACCEPTED as MESHMINE_LEGACY_HSA1_ACCEPTED,
    VERIFIER_SCHEMA_VERSION as MESHMINE_POOL_STATS_VERIFIER_SCHEMA_VERSION,
};
use hns_resolution_policy::{
    DnsRelayRequesterPolicy, EvidenceState as CanonicalEvidenceState, HnsrPolicy,
    Network as CanonicalNetwork, ObliviousDnsPolicy, PolicyConfig, ProviderPolicy,
    ResolutionTransport, TransportPlan, WireProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use wallet_abi::{WALLET_ABI_VERSION, WalletAbiDiscovery};
use zeroize::{Zeroize, Zeroizing};

pub const NATIVE_MESSAGING_SCHEMA_VERSION: u32 = 1;
pub const CHROMIUM_SECURITY_RESULT_SCHEMA_VERSION: u32 = 3;
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
const MAX_RECENT_SECURITY_RESULTS: usize = 32;
const MAX_SECURITY_ERROR_BYTES: usize = 512;

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
    /// New opt-in key. Historical public-recursive settings intentionally use
    /// different tombstoned names and are never migrated into this field.
    #[serde(default)]
    pub recursive_hns_doh_url: String,
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
            recursive_hns_doh_url: String::new(),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ChromiumDnsTransport {
    DirectAuthoritativeUdp,
    DirectAuthoritativeTcp,
    AuthenticatedAuthoritativeDoh,
    UserConfiguredRecursiveHnsDoh,
    LocalHnsProof,
    IcannDoh,
    HandshakeP2pOdoh,
    HandshakeP2pDnsRelay,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum CanonicalSecurityStatus {
    Available,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ChromiumRegistryProfile {
    DenuoV1,
    Official,
    Auto,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityChainAnchor {
    local_best_height: Option<u64>,
    target_height: Option<u64>,
    estimated_target_height: Option<u64>,
    stale: Option<bool>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityTransportPolicy {
    direct_authoritative_first: bool,
    p2p_odoh: P2pOdohMode,
    p2p_dns_relay: bool,
    privacy_downgrade: PrivacyDowngradePolicy,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityProviderReadiness {
    dns_relay: &'static str,
    odoh_proxy: &'static str,
    odoh_target: &'static str,
    hnsr_endpoint: &'static str,
    hnsr_relay: &'static str,
    market_gossip: &'static str,
}

/// Sanitized, Rust-derived browser security result. The original resolution
/// trace can contain a complete URL and certificate material, so it never
/// crosses the native-messaging boundary.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChromiumSecurityResult {
    schema_version: u32,
    event_sequence: u64,
    runtime_session: String,
    runtime_generation: u64,
    policy_generation: u64,
    network: String,
    host: String,
    status_code: u16,
    main_frame: bool,
    canonical_status: CanonicalSecurityStatus,
    canonical_status_unavailable_reason: Option<&'static str>,
    namespace_outcome: String,
    selected_namespace: Option<String>,
    namespace_selection_reason: String,
    decision_fingerprint: Option<String>,
    hns_root_failure: Option<&'static str>,
    icann_root_failure: Option<&'static str>,
    hns_resolution_state: String,
    icann_resolution_state: String,
    chain_anchor: SecurityChainAnchor,
    transport_policy: Option<SecurityTransportPolicy>,
    actual_selected_transport: ChromiumDnsTransport,
    nameserver_authority: &'static str,
    local_hns_proof_state: String,
    local_dnssec_state: String,
    local_tlsa_state: String,
    local_dane_state: String,
    peer_identity: Option<String>,
    proxy_identity: Option<String>,
    target_identity: Option<String>,
    proxy_target_separation: &'static str,
    direct_relay_fallback: Option<bool>,
    authoritative_fallback_occurred: Option<bool>,
    provider_readiness: Option<SecurityProviderReadiness>,
    registry_profile: Option<ChromiumRegistryProfile>,
    registry_fingerprint: Option<String>,
    protocol_version: Option<u16>,
    diagnostic_final_error: Option<String>,
}

/// A host-scoped pre-TLS decision. It intentionally has no HTTP status or
/// main-frame claim; the extension correlates it with a completed browser
/// navigation.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChromiumConnectSecurityDecision {
    schema_version: u32,
    observation_kind: &'static str,
    http_status_observed: bool,
    observed_at_unix_ms: u64,
    maintenance_epoch: u64,
    event_sequence: u64,
    runtime_session: String,
    runtime_generation: u64,
    policy_generation: u64,
    network: String,
    host: String,
    port: u16,
    canonical_status: CanonicalSecurityStatus,
    namespace_outcome: String,
    selected_namespace: Option<String>,
    namespace_selection_reason: String,
    decision_fingerprint: Option<String>,
    hns_root_failure: Option<&'static str>,
    icann_root_failure: Option<&'static str>,
    hns_resolution_state: String,
    icann_resolution_state: String,
    icann_tls_action: Option<&'static str>,
    icann_dnssec_status: Option<&'static str>,
    chain_anchor: SecurityChainAnchor,
    transport_policy: Option<SecurityTransportPolicy>,
    actual_selected_transport: ChromiumDnsTransport,
    nameserver_authority: &'static str,
    local_hns_proof_state: String,
    local_dnssec_state: String,
    local_tlsa_state: String,
    local_dane_state: String,
    peer_identity: Option<String>,
    proxy_identity: Option<String>,
    target_identity: Option<String>,
    proxy_target_separation: &'static str,
    direct_relay_fallback: Option<bool>,
    provider_readiness: Option<SecurityProviderReadiness>,
    registry_profile: Option<ChromiumRegistryProfile>,
    registry_fingerprint: Option<String>,
    protocol_version: Option<u16>,
}

#[derive(Clone)]
struct ActiveSecurityContext {
    runtime_session: String,
    runtime_generation: u64,
    policy_generation: u64,
    proxy_generation: u64,
    network: String,
}

#[derive(Clone)]
struct MaintenanceBoundSecurityResult {
    maintenance_epoch: u64,
    result: ChromiumSecurityResult,
}

#[derive(Default)]
struct SecurityObservationState {
    active: Option<ActiveSecurityContext>,
    highest_maintenance_epoch: Option<u64>,
    latest_main_frame_maintenance_epoch: Option<u64>,
    latest_main_frame: Option<ChromiumSecurityResult>,
    latest_main_frame_unavailable_reason: Option<&'static str>,
    latest_main_frame_event_floor: Option<u64>,
    recent: VecDeque<MaintenanceBoundSecurityResult>,
    recent_connect_decisions: VecDeque<ChromiumConnectSecurityDecision>,
}

#[derive(Clone, Default)]
struct SecurityObservations {
    state: Arc<Mutex<SecurityObservationState>>,
}

impl SecurityObservations {
    fn activate(&self, context: ActiveSecurityContext, maintenance_epoch: Option<u64>) {
        if let Ok(mut state) = self.state.lock() {
            state.active = Some(context);
            state.highest_maintenance_epoch = maintenance_epoch.filter(|epoch| *epoch != 0);
            state.latest_main_frame_maintenance_epoch = None;
            state.latest_main_frame = None;
            state.latest_main_frame_unavailable_reason = None;
            state.latest_main_frame_event_floor = None;
            state.recent.clear();
            state.recent_connect_decisions.clear();
        }
    }

    fn deactivate(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = None;
            state.highest_maintenance_epoch = None;
            state.latest_main_frame_maintenance_epoch = None;
            state.latest_main_frame = None;
            state.latest_main_frame_unavailable_reason = None;
            state.latest_main_frame_event_floor = None;
            state.recent.clear();
            state.recent_connect_decisions.clear();
        }
    }

    fn retain_maintenance_epoch(&self, maintenance_epoch: Option<u64>) {
        if let Ok(mut state) = self.state.lock() {
            let maintenance_epoch = maintenance_epoch.filter(|epoch| *epoch != 0);
            state.highest_maintenance_epoch = maintenance_epoch;
            if state.latest_main_frame_maintenance_epoch != maintenance_epoch {
                clear_latest_main_frame_security(&mut state);
            }
            state
                .recent
                .retain(|entry| Some(entry.maintenance_epoch) == maintenance_epoch);
            state
                .recent_connect_decisions
                .retain(|entry| Some(entry.maintenance_epoch) == maintenance_epoch);
        }
    }

    fn observe(&self, status: &BrowserProxyStatus) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(context) = state.active.as_ref() else {
            return;
        };
        if status.generation() != context.proxy_generation {
            return;
        }
        let Some(maintenance_epoch) = status.correlation_epoch().filter(|epoch| *epoch != 0) else {
            return;
        };
        match status.observation_kind() {
            BrowserProxyObservationKind::OriginResponse => {
                let observation = chromium_security_result(context, status);
                retain_security_observation(
                    &mut state,
                    status.is_likely_main_frame(),
                    maintenance_epoch,
                    observation,
                );
            }
            BrowserProxyObservationKind::WebPkiConnectDecision => {
                let Some(decision) = chromium_connect_security_decision(context, status) else {
                    return;
                };
                retain_connect_security_decision(&mut state, decision);
            }
        }
    }

    fn latest_main_frame(&self, maintenance_epoch: Option<u64>) -> Option<ChromiumSecurityResult> {
        self.state.lock().ok().and_then(|state| {
            (state.latest_main_frame_maintenance_epoch == maintenance_epoch)
                .then(|| state.latest_main_frame.clone())
                .flatten()
        })
    }

    fn recent(&self, maintenance_epoch: Option<u64>) -> Vec<ChromiumSecurityResult> {
        self.state
            .lock()
            .map(|state| {
                state
                    .recent
                    .iter()
                    .filter(|entry| Some(entry.maintenance_epoch) == maintenance_epoch)
                    .map(|entry| entry.result.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn recent_connect_decisions(
        &self,
        maintenance_epoch: Option<u64>,
    ) -> Vec<ChromiumConnectSecurityDecision> {
        self.state
            .lock()
            .map(|state| {
                state
                    .recent_connect_decisions
                    .iter()
                    .filter(|entry| Some(entry.maintenance_epoch) == maintenance_epoch)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn latest_main_frame_unavailable_reason(
        &self,
        maintenance_epoch: Option<u64>,
    ) -> Option<&'static str> {
        self.state.lock().ok().and_then(|state| {
            (state.latest_main_frame_maintenance_epoch == maintenance_epoch)
                .then_some(state.latest_main_frame_unavailable_reason)
                .flatten()
        })
    }

    fn active_context(&self) -> Option<ActiveSecurityContext> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.active.clone())
    }
}

enum CanonicalSecurityObservation {
    Available {
        tuple: CanonicalBrowserObservationTuple,
        result: Box<ChromiumSecurityResult>,
    },
    Unavailable {
        tuple: CanonicalBrowserObservationTuple,
        reason: &'static str,
    },
    Unordered,
}

fn retain_security_observation(
    state: &mut SecurityObservationState,
    main_frame: bool,
    maintenance_epoch: u64,
    observation: CanonicalSecurityObservation,
) {
    let (tuple, result, unavailable_reason) = match observation {
        CanonicalSecurityObservation::Available { tuple, result }
            if security_result_matches_observation(&result, tuple) =>
        {
            (tuple, Some(*result), None)
        }
        CanonicalSecurityObservation::Available { .. } => return,
        CanonicalSecurityObservation::Unavailable { tuple, reason } => (tuple, None, Some(reason)),
        CanonicalSecurityObservation::Unordered => {
            return;
        }
    };
    if !admit_security_observation_epoch(state, maintenance_epoch) {
        return;
    }
    if main_frame
        && state
            .latest_main_frame_event_floor
            .is_none_or(|event| tuple.event_sequence() > event)
    {
        state.latest_main_frame_maintenance_epoch = Some(maintenance_epoch);
        state.latest_main_frame_event_floor = Some(tuple.event_sequence());
        state.latest_main_frame = result.clone();
        state.latest_main_frame_unavailable_reason = unavailable_reason;
    }
    let Some(result) = result else {
        return;
    };
    if state
        .recent
        .iter()
        .any(|current| current.result.event_sequence == result.event_sequence)
    {
        return;
    }
    let insertion = state
        .recent
        .iter()
        .position(|current| current.result.event_sequence > result.event_sequence)
        .unwrap_or(state.recent.len());
    state.recent.insert(
        insertion,
        MaintenanceBoundSecurityResult {
            maintenance_epoch,
            result,
        },
    );
    while state.recent.len() > MAX_RECENT_SECURITY_RESULTS {
        state.recent.pop_front();
    }
}

fn retain_connect_security_decision(
    state: &mut SecurityObservationState,
    decision: ChromiumConnectSecurityDecision,
) {
    if !admit_security_observation_epoch(state, decision.maintenance_epoch) {
        return;
    }
    if state
        .recent_connect_decisions
        .iter()
        .any(|current| current.event_sequence == decision.event_sequence)
    {
        return;
    }
    let insertion = state
        .recent_connect_decisions
        .iter()
        .position(|current| current.event_sequence > decision.event_sequence)
        .unwrap_or(state.recent_connect_decisions.len());
    state.recent_connect_decisions.insert(insertion, decision);
    while state.recent_connect_decisions.len() > MAX_RECENT_SECURITY_RESULTS {
        state.recent_connect_decisions.pop_front();
    }
}

fn admit_security_observation_epoch(
    state: &mut SecurityObservationState,
    maintenance_epoch: u64,
) -> bool {
    if maintenance_epoch == 0 {
        return false;
    }
    match state.highest_maintenance_epoch {
        Some(current) if maintenance_epoch < current => false,
        Some(current) if maintenance_epoch == current => true,
        _ => {
            state.highest_maintenance_epoch = Some(maintenance_epoch);
            clear_latest_main_frame_security(state);
            state.recent.clear();
            state.recent_connect_decisions.clear();
            true
        }
    }
}

fn clear_latest_main_frame_security(state: &mut SecurityObservationState) {
    state.latest_main_frame_maintenance_epoch = None;
    state.latest_main_frame = None;
    state.latest_main_frame_unavailable_reason = None;
    state.latest_main_frame_event_floor = None;
}

fn security_result_matches_observation(
    result: &ChromiumSecurityResult,
    tuple: CanonicalBrowserObservationTuple,
) -> bool {
    result.runtime_session == URL_SAFE_NO_PAD.encode(tuple.runtime_session())
        && result.runtime_generation == tuple.runtime_generation()
        && result.policy_generation == tuple.policy_generation()
        && result.event_sequence == tuple.event_sequence()
}

struct NativeSecurityObserver {
    observations: SecurityObservations,
}

impl BrowserProxyStatusObserver for NativeSecurityObserver {
    fn observe_status(&self, status: &BrowserProxyStatus) {
        self.observations.observe(status);
    }
}

fn chromium_security_result(
    context: &ActiveSecurityContext,
    status: &BrowserProxyStatus,
) -> CanonicalSecurityObservation {
    let Some(tuple) = status.canonical_observation_tuple() else {
        return CanonicalSecurityObservation::Unordered;
    };
    if !canonical_observation_matches_context(tuple, context, status.generation()) {
        return CanonicalSecurityObservation::Unordered;
    }
    let diagnostic_final_error = diagnostic_final_error(status);
    if let Some(canonical) = status.canonical_status() {
        if canonical_status_matches_observation(canonical, tuple, context) {
            return CanonicalSecurityObservation::Available {
                tuple,
                result: Box::new(chromium_security_result_from_canonical_with_root_states(
                    status.host(),
                    status.status_code(),
                    status.is_likely_main_frame(),
                    canonical,
                    status.canonical_root_resolution_states(),
                    diagnostic_final_error,
                )),
            };
        }
        return CanonicalSecurityObservation::Unavailable {
            tuple,
            reason: "authorityTupleMismatch",
        };
    }

    CanonicalSecurityObservation::Unavailable {
        tuple,
        reason: status
            .canonical_status_unavailable_reason()
            .map(canonical_unavailable_reason)
            .unwrap_or("pending"),
    }
}

fn chromium_connect_security_decision(
    context: &ActiveSecurityContext,
    status: &BrowserProxyStatus,
) -> Option<ChromiumConnectSecurityDecision> {
    if status.observation_kind() != BrowserProxyObservationKind::WebPkiConnectDecision {
        return None;
    }
    let port = status.port()?;
    let maintenance_epoch = status.correlation_epoch()?;
    if port == 0 || maintenance_epoch == 0 {
        return None;
    }
    let canonical = status.canonical_status()?;
    let observed_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()?;
    let observation = chromium_security_result(context, status);
    let CanonicalSecurityObservation::Available { result, .. } = observation else {
        return None;
    };
    chromium_connect_security_decision_from_canonical(
        canonical,
        *result,
        port,
        maintenance_epoch,
        observed_at_unix_ms,
    )
}

fn chromium_connect_security_decision_from_canonical(
    canonical: &CanonicalBrowserStatus,
    result: ChromiumSecurityResult,
    port: u16,
    maintenance_epoch: u64,
    observed_at_unix_ms: u64,
) -> Option<ChromiumConnectSecurityDecision> {
    if port == 0
        || maintenance_epoch == 0
        || canonical.selected_namespace() != Some(CanonicalNamespace::Icann)
        || !matches!(
            canonical.icann_tls_action(),
            Some(
                CanonicalIcannTlsAction::WebPkiAuthenticatedAbsence
                    | CanonicalIcannTlsAction::WebPkiInsecureDelegation
            )
        )
    {
        return None;
    }
    let ChromiumSecurityResult {
        event_sequence,
        runtime_session,
        runtime_generation,
        policy_generation,
        network,
        host,
        canonical_status,
        namespace_outcome,
        selected_namespace,
        namespace_selection_reason,
        decision_fingerprint,
        hns_root_failure,
        icann_root_failure,
        hns_resolution_state,
        icann_resolution_state,
        chain_anchor,
        transport_policy,
        actual_selected_transport,
        nameserver_authority,
        local_hns_proof_state,
        local_dnssec_state,
        local_tlsa_state,
        local_dane_state,
        peer_identity,
        proxy_identity,
        target_identity,
        proxy_target_separation,
        direct_relay_fallback,
        provider_readiness,
        registry_profile,
        registry_fingerprint,
        protocol_version,
        ..
    } = result;
    Some(ChromiumConnectSecurityDecision {
        schema_version: NATIVE_MESSAGING_SCHEMA_VERSION,
        observation_kind: "browserWebPkiPassthrough",
        http_status_observed: false,
        observed_at_unix_ms,
        maintenance_epoch,
        event_sequence,
        runtime_session,
        runtime_generation,
        policy_generation,
        network,
        host,
        port,
        canonical_status,
        namespace_outcome,
        selected_namespace,
        namespace_selection_reason,
        decision_fingerprint,
        hns_root_failure,
        icann_root_failure,
        hns_resolution_state,
        icann_resolution_state,
        icann_tls_action: canonical.icann_tls_action().map(canonical_icann_tls_action),
        icann_dnssec_status: canonical
            .icann_dnssec_status()
            .map(canonical_icann_dnssec_status),
        chain_anchor,
        transport_policy,
        actual_selected_transport,
        nameserver_authority,
        local_hns_proof_state,
        local_dnssec_state,
        local_tlsa_state,
        local_dane_state,
        peer_identity,
        proxy_identity,
        target_identity,
        proxy_target_separation,
        direct_relay_fallback,
        provider_readiness,
        registry_profile,
        registry_fingerprint,
        protocol_version,
    })
}

fn canonical_icann_tls_action(action: CanonicalIcannTlsAction) -> &'static str {
    match action {
        CanonicalIcannTlsAction::EnforceDane => "enforceDane",
        CanonicalIcannTlsAction::WebPkiAuthenticatedAbsence => "webPkiAuthenticatedAbsence",
        CanonicalIcannTlsAction::WebPkiInsecureDelegation => "webPkiInsecureDelegation",
        CanonicalIcannTlsAction::FailClosed => "failClosed",
    }
}

fn canonical_icann_dnssec_status(status: CanonicalIcannDnssecStatus) -> &'static str {
    match status {
        CanonicalIcannDnssecStatus::Secure => "secure",
        CanonicalIcannDnssecStatus::InsecureDelegation => "insecureDelegation",
        CanonicalIcannDnssecStatus::Bogus => "bogus",
        CanonicalIcannDnssecStatus::Indeterminate => "indeterminate",
    }
}

fn canonical_observation_matches_context(
    tuple: CanonicalBrowserObservationTuple,
    context: &ActiveSecurityContext,
    proxy_generation: u64,
) -> bool {
    URL_SAFE_NO_PAD.encode(tuple.runtime_session()) == context.runtime_session
        && tuple.runtime_generation() == context.runtime_generation
        && tuple.policy_generation() == context.policy_generation
        && proxy_generation == context.proxy_generation
}

fn canonical_status_matches_observation(
    canonical: &CanonicalBrowserStatus,
    tuple: CanonicalBrowserObservationTuple,
    context: &ActiveSecurityContext,
) -> bool {
    canonical.runtime_session() == tuple.runtime_session()
        && canonical.runtime_generation() == tuple.runtime_generation()
        && canonical.policy_generation() == tuple.policy_generation()
        && canonical.event_sequence() == tuple.event_sequence()
        && canonical_network_name(canonical.network()) == context.network
}

#[cfg(test)]
fn chromium_security_result_from_canonical(
    host: &str,
    status_code: u16,
    main_frame: bool,
    canonical: &CanonicalBrowserStatus,
    diagnostic_final_error: Option<String>,
) -> ChromiumSecurityResult {
    chromium_security_result_from_canonical_with_root_states(
        host,
        status_code,
        main_frame,
        canonical,
        None,
        diagnostic_final_error,
    )
}

fn chromium_security_result_from_canonical_with_root_states(
    host: &str,
    status_code: u16,
    main_frame: bool,
    canonical: &CanonicalBrowserStatus,
    partial_root_states: Option<CanonicalRootResolutionStates>,
    diagnostic_final_error: Option<String>,
) -> ChromiumSecurityResult {
    let actual_selected_transport = canonical_dns_transport(canonical.actual_transport());
    let (hns_resolution_state, icann_resolution_state) =
        canonical_root_states(canonical, partial_root_states);
    let evidence = canonical.evidence();
    let identities = canonical.identities();
    let chain_anchor = canonical.chain_anchor();
    let registry_fingerprint = canonical.registry_fingerprint();
    ChromiumSecurityResult {
        schema_version: CHROMIUM_SECURITY_RESULT_SCHEMA_VERSION,
        event_sequence: canonical.event_sequence(),
        runtime_session: URL_SAFE_NO_PAD.encode(canonical.runtime_session()),
        runtime_generation: canonical.runtime_generation(),
        policy_generation: canonical.policy_generation(),
        network: canonical_network_name(canonical.network()).to_owned(),
        host: host.to_owned(),
        status_code,
        main_frame,
        canonical_status: CanonicalSecurityStatus::Available,
        canonical_status_unavailable_reason: None,
        namespace_outcome: canonical_outcome_name(canonical.namespace_outcome()).to_owned(),
        selected_namespace: canonical
            .selected_namespace()
            .map(canonical_namespace_name)
            .map(str::to_owned),
        namespace_selection_reason: canonical_selection_reason_name(canonical.selection_reason())
            .to_owned(),
        decision_fingerprint: canonical.decision_fingerprint().map(hex_bytes),
        hns_root_failure: canonical
            .hns_root_failure()
            .map(canonical_root_failure_name),
        icann_root_failure: canonical
            .icann_root_failure()
            .map(canonical_root_failure_name),
        hns_resolution_state: hns_resolution_state.to_owned(),
        icann_resolution_state: icann_resolution_state.to_owned(),
        chain_anchor: SecurityChainAnchor {
            local_best_height: chain_anchor.map(|anchor| u64::from(anchor.height)),
            target_height: None,
            estimated_target_height: None,
            stale: canonical_chain_stale(evidence.chain_current),
        },
        transport_policy: Some(canonical_transport_policy(canonical)),
        actual_selected_transport,
        nameserver_authority: canonical_nameserver_authority(actual_selected_transport),
        local_hns_proof_state: canonical_evidence_state(evidence.hns_proof).to_owned(),
        local_dnssec_state: canonical_evidence_state(evidence.dnssec).to_owned(),
        local_tlsa_state: canonical_evidence_state(evidence.tlsa).to_owned(),
        local_dane_state: canonical_evidence_state(evidence.dane).to_owned(),
        peer_identity: identities.peer.clone(),
        proxy_identity: identities.proxy.clone(),
        target_identity: identities.target.clone(),
        proxy_target_separation: if actual_selected_transport
            == ChromiumDnsTransport::HandshakeP2pOdoh
        {
            "verified"
        } else {
            "notApplicable"
        },
        direct_relay_fallback: Some(identities.direct_relay_fallback),
        // Attempt history remains diagnostic and cannot be reconstructed from
        // the checked selected-transport status.
        authoritative_fallback_occurred: None,
        provider_readiness: Some(canonical_provider_readiness(canonical)),
        registry_profile: Some(canonical_registry_profile(canonical.registry_profile())),
        registry_fingerprint: (registry_fingerprint != [0; 32])
            .then(|| hex_bytes(registry_fingerprint)),
        protocol_version: (canonical.protocol_version() != 0).then(|| canonical.protocol_version()),
        diagnostic_final_error,
    }
}

fn canonical_dns_transport(transport: ResolutionTransport) -> ChromiumDnsTransport {
    match transport {
        ResolutionTransport::DirectAuthoritativeUdp => ChromiumDnsTransport::DirectAuthoritativeUdp,
        ResolutionTransport::DirectAuthoritativeTcp => ChromiumDnsTransport::DirectAuthoritativeTcp,
        ResolutionTransport::AuthenticatedAuthoritativeDoh => {
            ChromiumDnsTransport::AuthenticatedAuthoritativeDoh
        }
        ResolutionTransport::HandshakeP2pOdoh => ChromiumDnsTransport::HandshakeP2pOdoh,
        ResolutionTransport::HandshakeP2pDnsRelay => ChromiumDnsTransport::HandshakeP2pDnsRelay,
        ResolutionTransport::ValidatingIcannDoh => ChromiumDnsTransport::IcannDoh,
        ResolutionTransport::UserConfiguredRecursiveHnsDoh => {
            ChromiumDnsTransport::UserConfiguredRecursiveHnsDoh
        }
        ResolutionTransport::LocalHnsProof => ChromiumDnsTransport::LocalHnsProof,
        ResolutionTransport::Unavailable => ChromiumDnsTransport::Unavailable,
    }
}

fn canonical_nameserver_authority(transport: ChromiumDnsTransport) -> &'static str {
    match transport {
        ChromiumDnsTransport::Unavailable => "unavailable",
        ChromiumDnsTransport::IcannDoh => "validatingIcannResolver",
        ChromiumDnsTransport::UserConfiguredRecursiveHnsDoh => "userConfiguredRecursiveResolver",
        ChromiumDnsTransport::LocalHnsProof => "localHnsProof",
        ChromiumDnsTransport::DirectAuthoritativeUdp
        | ChromiumDnsTransport::DirectAuthoritativeTcp
        | ChromiumDnsTransport::AuthenticatedAuthoritativeDoh
        | ChromiumDnsTransport::HandshakeP2pOdoh
        | ChromiumDnsTransport::HandshakeP2pDnsRelay => "delegatedAuthoritativeNameserver",
    }
}

fn canonical_network_name(network: CanonicalNetwork) -> &'static str {
    match network {
        CanonicalNetwork::Mainnet => "mainnet",
        CanonicalNetwork::Testnet => "testnet",
        CanonicalNetwork::Regtest => "regtest",
        CanonicalNetwork::Simnet => "simnet",
    }
}

fn canonical_outcome_name(outcome: Option<CanonicalOutcomeKind>) -> &'static str {
    match outcome {
        Some(CanonicalOutcomeKind::HnsOnly) => "hnsOnly",
        Some(CanonicalOutcomeKind::IcannOnly) => "icannOnly",
        Some(CanonicalOutcomeKind::BothConvergent) => "bothConvergent",
        Some(CanonicalOutcomeKind::BothDivergent) => "bothDivergent",
        Some(CanonicalOutcomeKind::Neither) => "neither",
        None => "indeterminate",
    }
}

fn canonical_namespace_name(namespace: CanonicalNamespace) -> &'static str {
    match namespace {
        CanonicalNamespace::Hns => "hns",
        CanonicalNamespace::Icann => "icann",
    }
}

fn canonical_selection_reason_name(reason: Option<CanonicalSelectionReason>) -> &'static str {
    match reason {
        Some(CanonicalSelectionReason::SingleRoot) => "onlyAvailableRoot",
        Some(CanonicalSelectionReason::ExplicitPin) => "explicitPin",
        Some(CanonicalSelectionReason::StickyBinding) => "stickyBinding",
        Some(CanonicalSelectionReason::IcannDefault) => "icannDefault",
        None => "unavailable",
    }
}

fn canonical_root_states(
    canonical: &CanonicalBrowserStatus,
    partial_root_states: Option<CanonicalRootResolutionStates>,
) -> (&'static str, &'static str) {
    if let Some(root_states) = partial_root_states {
        return (
            partial_root_state_name(root_states.hns()),
            partial_root_state_name(root_states.icann()),
        );
    }
    match canonical.namespace_outcome() {
        Some(CanonicalOutcomeKind::HnsOnly) => ("securePresent", "absent"),
        Some(CanonicalOutcomeKind::IcannOnly) => ("authenticatedAbsent", "present"),
        Some(CanonicalOutcomeKind::BothConvergent | CanonicalOutcomeKind::BothDivergent) => {
            ("securePresent", "present")
        }
        Some(CanonicalOutcomeKind::Neither) => ("authenticatedAbsent", "absent"),
        None => (
            if canonical.hns_root_failure().is_some() {
                "failed"
            } else {
                "unknown"
            },
            if canonical.icann_root_failure().is_some() {
                "failed"
            } else {
                "unknown"
            },
        ),
    }
}

fn partial_root_state_name(state: RootResolutionDisposition) -> &'static str {
    match state {
        RootResolutionDisposition::Present => "present",
        RootResolutionDisposition::Absent => "absent",
        RootResolutionDisposition::Failed => "failed",
    }
}

fn canonical_root_failure_name(failure: CanonicalRootFailureKind) -> &'static str {
    match failure {
        CanonicalRootFailureKind::Timeout => "timeout",
        CanonicalRootFailureKind::Transport => "transport",
        CanonicalRootFailureKind::StaleHnsAnchor => "staleHnsAnchor",
        CanonicalRootFailureKind::BogusDnssec => "bogusDnssec",
        CanonicalRootFailureKind::IndeterminateDnssec => "indeterminateDnssec",
        CanonicalRootFailureKind::UnauthenticatedResolver => "unauthenticatedResolver",
        CanonicalRootFailureKind::MalformedResponse => "malformedResponse",
        CanonicalRootFailureKind::Unsupported => "unsupported",
        CanonicalRootFailureKind::Cancelled => "cancelled",
        CanonicalRootFailureKind::Internal => "internal",
        CanonicalRootFailureKind::StaleEvidence => "staleEvidence",
    }
}

fn canonical_evidence_state(state: CanonicalEvidenceState) -> &'static str {
    match state {
        CanonicalEvidenceState::Verified => "verified",
        CanonicalEvidenceState::Failed => "failed",
        CanonicalEvidenceState::Unavailable => "unavailable",
        CanonicalEvidenceState::Unsupported => "unsupported",
        CanonicalEvidenceState::NotAttempted => "notAttempted",
        CanonicalEvidenceState::Stale => "stale",
        CanonicalEvidenceState::Revoked => "revoked",
    }
}

fn canonical_chain_stale(state: CanonicalEvidenceState) -> Option<bool> {
    match state {
        CanonicalEvidenceState::Verified => Some(false),
        CanonicalEvidenceState::Failed | CanonicalEvidenceState::Stale => Some(true),
        CanonicalEvidenceState::Unavailable
        | CanonicalEvidenceState::Unsupported
        | CanonicalEvidenceState::NotAttempted
        | CanonicalEvidenceState::Revoked => None,
    }
}

fn canonical_transport_policy(canonical: &CanonicalBrowserStatus) -> SecurityTransportPolicy {
    let config = canonical.transport_policy().config();
    let plan = TransportPlan::for_policy(config);
    SecurityTransportPolicy {
        direct_authoritative_first: plan.as_slice().starts_with(&[
            ResolutionTransport::DirectAuthoritativeUdp,
            ResolutionTransport::DirectAuthoritativeTcp,
        ]),
        p2p_odoh: match config.oblivious_dns {
            ObliviousDnsPolicy::Disabled => P2pOdohMode::Off,
            ObliviousDnsPolicy::Preferred => P2pOdohMode::Preferred,
            ObliviousDnsPolicy::Required => P2pOdohMode::Required,
            ObliviousDnsPolicy::DirectRelayAllowed => P2pOdohMode::DirectAllowed,
        },
        p2p_dns_relay: plan.contains(ResolutionTransport::HandshakeP2pDnsRelay),
        privacy_downgrade: if config.oblivious_dns == ObliviousDnsPolicy::DirectRelayAllowed {
            PrivacyDowngradePolicy::AllowDirect
        } else {
            PrivacyDowngradePolicy::FailClosed
        },
    }
}

fn canonical_provider_readiness(canonical: &CanonicalBrowserStatus) -> SecurityProviderReadiness {
    let readiness = canonical.provider_readiness();
    SecurityProviderReadiness {
        dns_relay: canonical_readiness_state(readiness.dns_relay),
        odoh_proxy: canonical_readiness_state(readiness.odoh_proxy),
        odoh_target: canonical_readiness_state(readiness.odoh_target),
        hnsr_endpoint: canonical_readiness_state(readiness.hnsr_endpoint),
        hnsr_relay: canonical_readiness_state(readiness.hnsr_relay),
        market_gossip: canonical_readiness_state(readiness.market_gossip),
    }
}

fn canonical_readiness_state(state: CanonicalReadinessState) -> &'static str {
    match state {
        CanonicalReadinessState::Disabled => "disabled",
        CanonicalReadinessState::Starting => "starting",
        CanonicalReadinessState::Ready => "ready",
        CanonicalReadinessState::RateLimited => "rateLimited",
        CanonicalReadinessState::Degraded => "degraded",
        CanonicalReadinessState::Revoked => "revoked",
    }
}

fn canonical_registry_profile(profile: WireProfile) -> ChromiumRegistryProfile {
    match profile {
        WireProfile::DenuoV1 => ChromiumRegistryProfile::DenuoV1,
        WireProfile::Official => ChromiumRegistryProfile::Official,
        WireProfile::Auto => ChromiumRegistryProfile::Auto,
    }
}

fn canonical_unavailable_reason(reason: CanonicalStatusUnavailableReason) -> &'static str {
    match reason {
        CanonicalStatusUnavailableReason::P2pRegistryIdentityUnavailable => {
            "p2pRegistryIdentityUnavailable"
        }
        CanonicalStatusUnavailableReason::TransportNotRepresentable => "transportNotRepresentable",
        CanonicalStatusUnavailableReason::EvidenceUnavailable => "evidenceUnavailable",
        CanonicalStatusUnavailableReason::SchemaValidationRejected => "schemaValidationRejected",
        _ => "unknownCanonicalStatusReason",
    }
}

fn diagnostic_final_error(status: &BrowserProxyStatus) -> Option<String> {
    let trace = status
        .resolution_trace_json()
        .and_then(|trace| serde_json::from_str::<Value>(trace).ok())?;
    bounded_diagnostic_string(trace.get("finalError"), MAX_SECURITY_ERROR_BYTES)
}

fn bounded_diagnostic_string(value: Option<&Value>, maximum: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn hex_bytes(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
    Diagnostics {
        schema_version: u32,
        request_id: String,
    },
    WalletProviderCapabilities {
        schema_version: u32,
        request_id: String,
        provider_abi_version: u16,
        /// A lookup candidate from the trusted extension process. It is never
        /// accepted as authentication. The native host must replace it with a
        /// canonical opaque engine context before wallet dispatch is enabled.
        #[serde(default)]
        authority: Option<Value>,
    },
    WalletProviderRequest {
        schema_version: u32,
        request_id: String,
        provider_abi_version: u16,
        authority: Value,
        request: Value,
    },
    WalletProviderApprovalDecision {
        schema_version: u32,
        request_id: String,
        provider_abi_version: u16,
        approval_id: String,
        decision: String,
        #[serde(default)]
        authority: Option<Value>,
        #[serde(default)]
        request: Option<Value>,
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
            | Self::Diagnostics { schema_version, .. }
            | Self::WalletProviderCapabilities { schema_version, .. }
            | Self::WalletProviderRequest { schema_version, .. }
            | Self::WalletProviderApprovalDecision { schema_version, .. }
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
            | Self::Diagnostics { request_id, .. }
            | Self::WalletProviderCapabilities { request_id, .. }
            | Self::WalletProviderRequest { request_id, .. }
            | Self::WalletProviderApprovalDecision { request_id, .. }
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
        description: "Shakescape Rust native host",
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
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(local_ca_io)?;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(local_ca_io)
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
    wallet_abi: WalletAbiDiscovery,
    host_session: String,
    event_sequence: Arc<AtomicU64>,
    security_observations: SecurityObservations,
    policy: ExtensionPolicy,
}

impl NativeHostController {
    pub fn open(data_dir: &Path, network: NetworkKind) -> Result<Self, NativeHostError> {
        fs::create_dir_all(data_dir).map_err(local_ca_io)?;
        secure_directory(data_dir)?;
        let local_ca = LocalCaStore::open(data_dir)?;
        let runtime = BrowserRuntime::open(RuntimeConfiguration::new(data_dir, network))
            .map_err(|error| NativeHostError::Runtime(error.to_string()))?;
        let wallet_abi = WalletAbiDiscovery::discover(data_dir);
        Ok(Self {
            runtime,
            proxy: None,
            local_ca,
            wallet_abi,
            host_session: generate_host_session()?,
            event_sequence: Arc::new(AtomicU64::new(0)),
            security_observations: SecurityObservations::default(),
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
            NativeRequest::Hello { .. } => {
                self.wallet_abi.refresh();
                let wallet_abi = self.wallet_abi.status_json();
                (
                    self.success_response(
                        request_id,
                        json!({
                            "nativeHost": env!("CARGO_PKG_VERSION"),
                            "network": self.runtime.network().as_str(),
                            "walletAbi": wallet_abi,
                            "capabilities": {
                                "manifestV3": true,
                                "nativeMessaging": true,
                                "authenticatedLoopbackProxy": true,
                                "dnsNameDanePac": true,
                                "proxyAuthentication": true,
                                "perInstallLocalCa": true,
                                "chromiumSecurityResults": true,
                                "userConfiguredRecursiveHnsDoh": true,
                                "meshminePoolStatsVerifierCore": true,
                                "meshminePoolStatsVerifierSchemaVersion": MESHMINE_POOL_STATS_VERIFIER_SCHEMA_VERSION,
                                "meshmineHrmAuthorityAdapter": MESHMINE_HRM_AUTHORITY_ADAPTER_AVAILABLE,
                                "meshmineLegacyHsa1Accepted": MESHMINE_LEGACY_HSA1_ACCEPTED,
                                "meshmineVerifiedPoolStats": false,
                                "handshakeWalletProvider": false,
                                "p2pDnsRelay": true,
                                "p2pOdoh": false,
                                "hnsr": false
                            }
                        }),
                    ),
                    false,
                )
            }
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
                // A sync attempt may advance the maintenance epoch even when a
                // later peer/storage step returns an error. Retain observations
                // published under the resulting epoch while discarding only
                // stale-epoch results; a blanket clear here can erase a new
                // CONNECT decision published just after maintenance releases.
                self.security_observations
                    .retain_maintenance_epoch(self.runtime.security_maintenance_epoch());
                (self.response_from_result(request_id, result), false)
            }
            NativeRequest::Diagnostics { .. } => {
                let diagnostics = diagnostics_json();
                let core = serde_json::from_str(&diagnostics)
                    .unwrap_or_else(|_| Value::String(diagnostics.to_owned()));
                let runtime_status = self.status_result();
                let maintenance_epoch = runtime_status
                    .get("securityMaintenanceEpoch")
                    .and_then(Value::as_u64);
                let value = json!({
                    "core": core,
                    "runtime": runtime_status,
                    "recentSecurityResults": self
                        .security_observations
                        .recent(maintenance_epoch),
                    "recentConnectSecurityDecisions": self
                        .security_observations
                        .recent_connect_decisions(maintenance_epoch)
                });
                (self.success_response(request_id, value), false)
            }
            NativeRequest::WalletProviderCapabilities {
                provider_abi_version,
                ..
            }
            | NativeRequest::WalletProviderRequest {
                provider_abi_version,
                ..
            }
            | NativeRequest::WalletProviderApprovalDecision {
                provider_abi_version,
                ..
            } => (
                self.wallet_provider_unavailable(request_id, provider_abi_version),
                false,
            ),
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
        self.wallet_abi.refresh();
        let runtime_policy = runtime_policy(&policy)?;
        self.stop_proxy();
        self.runtime
            .set_policy(runtime_policy)
            .map_err(|error| ("runtimeError", error.to_string()))?;
        let observer = Arc::new(NativeSecurityObserver {
            observations: self.security_observations.clone(),
        });
        let proxy = self
            .runtime
            .start_dane_browser_proxy_with_certificate_authority_and_observer(
                self.local_ca.authority().clone(),
                observer,
            )
            .map_err(|error| ("proxyStartFailed", error.to_string()))?;
        let authority = self
            .runtime
            .canonical_authority_tuple()
            .map_err(|error| ("runtimeError", error.to_string()))?;
        let runtime_session = URL_SAFE_NO_PAD.encode(authority.runtime_session());
        if runtime_session != proxy.session_id() {
            return Err((
                "runtimeError",
                "canonical authority session does not match the active proxy session".to_owned(),
            ));
        }
        let runtime_generation = authority.runtime_generation();
        let policy_generation = authority.policy_generation();
        let proxy_generation = proxy.generation();
        let (header_sync, header_sync_unavailable_reason, maintenance_epoch) =
            self.header_sync_status_result();
        self.security_observations.activate(
            ActiveSecurityContext {
                runtime_session: runtime_session.clone(),
                runtime_generation,
                policy_generation,
                proxy_generation,
                network: self.runtime.network().as_str().to_owned(),
            },
            maintenance_epoch,
        );
        let pac_script = chromium_dane_pac_script(proxy.port())
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
            "runtimeSession": runtime_session,
            "runtimeGeneration": runtime_generation,
            "policyGeneration": policy_generation,
            "securityMaintenanceEpoch": maintenance_epoch,
            "policy": policy,
            "headerSync": header_sync,
            "headerSyncUnavailableReason": header_sync_unavailable_reason,
            "latestMainFrameSecurity": Value::Null,
            "latestMainFrameSecurityUnavailableReason": Value::Null,
            "recentConnectSecurityDecisions": [],
            "walletAbi": self.wallet_abi.status_json()
        });
        self.policy = policy;
        self.proxy = Some(proxy);
        Ok(result)
    }

    fn status_result(&self) -> Value {
        let proxy = self.proxy.as_ref();
        let context = self.security_observations.active_context();
        let (header_sync, header_sync_unavailable_reason, maintenance_epoch) =
            self.header_sync_status_result();
        json!({
            "state": if proxy.is_some_and(|proxy| !proxy.is_stop_requested()) {
                "active"
            } else {
                "stopped"
            },
            "runtimeSession": context.as_ref().map(|context| context.runtime_session.as_str()),
            "runtimeGeneration": context.as_ref().map(|context| context.runtime_generation),
            "policyGeneration": context
                .as_ref()
                .map_or_else(|| self.canonical_policy_generation(), |context| {
                    context.policy_generation
                }),
            "securityMaintenanceEpoch": maintenance_epoch,
            "policy": self.policy,
            "caReady": self.local_ca.is_marked_installed(),
            "ca": self.local_ca.status_json(),
            "headerSync": header_sync,
            "headerSyncUnavailableReason": header_sync_unavailable_reason,
            "latestMainFrameSecurity": self
                .security_observations
                .latest_main_frame(maintenance_epoch),
            "latestMainFrameSecurityUnavailableReason": self
                .security_observations
                .latest_main_frame_unavailable_reason(maintenance_epoch),
            "recentConnectSecurityDecisions": self
                .security_observations
                .recent_connect_decisions(maintenance_epoch),
            "walletAbi": self.wallet_abi.status_json()
        })
    }

    fn wallet_provider_unavailable(
        &mut self,
        request_id: String,
        provider_abi_version: u16,
    ) -> NativeResponse {
        if provider_abi_version != WALLET_ABI_VERSION {
            return self.error_response(
                request_id,
                "walletAbiVersionMismatch",
                format!(
                    "wallet ABI {provider_abi_version} is unsupported; expected {}",
                    WALLET_ABI_VERSION
                ),
            );
        }
        let code = self.wallet_abi.unavailable_code();
        let message = self.wallet_abi.unavailable_message().to_owned();
        self.error_response(request_id, code, message)
    }

    fn header_sync_status_result(&self) -> (Value, Value, Option<u64>) {
        match self.runtime.sync_status_with_security_epoch() {
            Ok((status, maintenance_epoch)) => {
                match serde_json::from_str::<Value>(&status.to_json()) {
                    Ok(value) => (value, Value::Null, maintenance_epoch),
                    Err(_) => (
                        Value::Null,
                        Value::String("headerSyncStatusInvalid".to_owned()),
                        None,
                    ),
                }
            }
            Err(_) => (
                Value::Null,
                Value::String("headerSyncStatusUnavailable".to_owned()),
                None,
            ),
        }
    }

    fn stop_proxy(&mut self) {
        self.security_observations.deactivate();
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
        NativeResponse {
            schema_version: NATIVE_MESSAGING_SCHEMA_VERSION,
            request_id,
            ok: true,
            runtime_session: self.current_runtime_session(),
            runtime_generation: self
                .security_observations
                .active_context()
                .map(|context| context.runtime_generation),
            policy_generation: self.canonical_policy_generation(),
            event_sequence: next_event_sequence(&self.event_sequence),
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
        NativeResponse {
            schema_version: NATIVE_MESSAGING_SCHEMA_VERSION,
            request_id,
            ok: false,
            runtime_session: self.current_runtime_session(),
            runtime_generation: self
                .security_observations
                .active_context()
                .map(|context| context.runtime_generation),
            policy_generation: self.canonical_policy_generation(),
            event_sequence: next_event_sequence(&self.event_sequence),
            result: None,
            error: Some(NativeProtocolError { code, message }),
        }
    }

    fn current_runtime_session(&self) -> String {
        self.security_observations
            .active_context()
            .map(|context| context.runtime_session)
            .unwrap_or_else(|| self.host_session.clone())
    }

    fn canonical_policy_generation(&self) -> u64 {
        self.runtime
            .canonical_authority_tuple()
            .map(|authority| authority.policy_generation())
            .unwrap_or_else(|_| self.runtime.policy_revision().saturating_add(1))
    }
}

impl Drop for NativeHostController {
    fn drop(&mut self) {
        self.stop_proxy();
    }
}

type ProtocolResult = Result<Value, (&'static str, String)>;

fn runtime_policy(policy: &ExtensionPolicy) -> Result<RuntimePolicy, (&'static str, String)> {
    let shared_policy = shared_resolution_policy(policy)?;
    let transport_plan = TransportPlan::for_policy(shared_policy);
    let configured_hns_doh = normalize_configured_hns_doh_resolver(Some(
        &policy.recursive_hns_doh_url,
    ))
    .map_err(|error| {
        (
            "invalidPolicy",
            format!("recursiveHnsDohUrl is invalid: {error}"),
        )
    })?;
    Ok(RuntimePolicy {
        resolution_mode: ResolutionMode::Strict,
        hns_doh_resolver: configured_hns_doh,
        experimental_p2p_dns_relay: transport_plan
            .contains(ResolutionTransport::HandshakeP2pDnsRelay),
        legacy_hns_doh_compatibility: false,
        stateless_dane_certificates: false,
    })
}

fn shared_resolution_policy(
    policy: &ExtensionPolicy,
) -> Result<PolicyConfig, (&'static str, String)> {
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
    let configured_hns_doh = normalize_configured_hns_doh_resolver(Some(
        &policy.recursive_hns_doh_url,
    ))
    .map_err(|error| {
        (
            "invalidPolicy",
            format!("recursiveHnsDohUrl is invalid: {error}"),
        )
    })?;
    let config = PolicyConfig {
        dns_relay_requester: if policy.p2p_dns_relay {
            DnsRelayRequesterPolicy::Auto
        } else {
            DnsRelayRequesterPolicy::Disabled
        },
        oblivious_dns: ObliviousDnsPolicy::Disabled,
        hnsr: HnsrPolicy::disabled(),
        authenticated_authoritative_doh: true,
        user_configured_recursive_hns_doh: configured_hns_doh.is_some(),
        providers: ProviderPolicy {
            dns_relay: false,
            odoh_proxy: false,
            odoh_target: false,
            market_gossip: false,
        },
        wire_profile: WireProfile::DenuoV1,
        allow_legacy_regtest_compatibility: false,
    };
    config.validate().map_err(|error| {
        (
            "unsupportedPolicy",
            format!("invalid shared resolution policy: {error}"),
        )
    })?;
    Ok(config)
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn generate_host_session() -> Result<String, NativeHostError> {
    let mut bytes = [0_u8; HOST_SESSION_RANDOM_BYTES];
    fill_random(&mut bytes).map_err(|_| NativeHostError::SessionGeneration)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn next_event_sequence(sequence: &AtomicU64) -> u64 {
    match sequence.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(1)
    }) {
        Ok(previous) => previous + 1,
        Err(_) => u64::MAX,
    }
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
    use hns_browser_observability::{
        IcannDnssecStatus, IcannTlsAction, ProviderReadiness, RateLimitState, StatusInput,
        TransportIdentities,
    };
    use hns_browser_runtime::{
        AuthorityState as CanonicalAuthorityState, BrowserRuntime as CanonicalRuntime,
        RuntimeSessionId as CanonicalRuntimeSessionId,
    };
    use hns_chain::{HeaderStore, SqliteHeaderStore, StoredHeader};
    use hns_core::{BlockHeader, Chainwork, Hash, Height, NameHash};
    use hns_resolution_policy::{ChainAnchor, PolicySnapshot, ValidationEvidence};
    use hns_resolver::{SqliteResourceValueProvider, VerifiedResourceValue};
    use std::io::Cursor;
    use std::net::{Ipv4Addr, TcpStream};
    use std::process::{Command, Stdio};

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
        assert_eq!(policy.recursive_hns_doh_url, "");
        assert!(policy.p2p_dns_relay);
        assert_eq!(policy.p2p_odoh, P2pOdohMode::Off);

        let request = serde_json::from_str::<NativeRequest>(
            r#"{"command":"start","schemaVersion":1,"requestId":"x","policy":{"recursiveHnsDohUrl":"https://hnsdoh.com/dns-query"}}"#,
        )
        .unwrap();
        let NativeRequest::Start { policy, .. } = request else {
            panic!("start request expected");
        };
        assert_eq!(policy.recursive_hns_doh_url, "https://hnsdoh.com/dns-query");

        let wallet = serde_json::from_str::<NativeRequest>(
            r#"{"command":"walletProviderRequest","schemaVersion":1,"requestId":"wallet-1","providerAbiVersion":2,"authority":{"origin":"https://example"},"request":{"schemaVersion":1,"kind":"request","requestId":"page-1","sequence":1,"method":"wallet_getStatus","params":null}}"#,
        )
        .unwrap();
        let NativeRequest::WalletProviderRequest {
            provider_abi_version,
            ..
        } = wallet
        else {
            panic!("wallet provider request expected");
        };
        assert_eq!(provider_abi_version, WALLET_ABI_VERSION);
        assert!(
            serde_json::from_str::<NativeRequest>(
                r#"{"command":"walletProviderCapabilities","schemaVersion":1,"requestId":"wallet-2","providerAbiVersion":2,"permissionGeneration":9}"#
            )
            .is_err()
        );
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
        policy.p2p_odoh = P2pOdohMode::Off;
        policy.privacy_downgrade = PrivacyDowngradePolicy::AllowDirect;
        assert_eq!(runtime_policy(&policy).unwrap_err().0, "unsupportedPolicy");
        policy.privacy_downgrade = PrivacyDowngradePolicy::FailClosed;
        policy.experimental_wire_profile = ExperimentalWireProfile::HipDrafts;
        assert_eq!(runtime_policy(&policy).unwrap_err().0, "unsupportedPolicy");
    }

    #[test]
    fn stable_extension_policy_maps_every_shared_control_without_hidden_roles() {
        let policy = ExtensionPolicy::default();
        let shared = shared_resolution_policy(&policy).unwrap();

        assert_eq!(
            shared.dns_relay_requester,
            DnsRelayRequesterPolicy::Disabled
        );
        assert_eq!(shared.oblivious_dns, ObliviousDnsPolicy::Disabled);
        assert_eq!(shared.hnsr, HnsrPolicy::disabled());
        assert!(shared.authenticated_authoritative_doh);
        assert_eq!(
            shared.providers,
            ProviderPolicy {
                dns_relay: false,
                odoh_proxy: false,
                odoh_target: false,
                market_gossip: false,
            }
        );
        assert_eq!(shared.wire_profile, WireProfile::DenuoV1);
        assert!(!shared.allow_legacy_regtest_compatibility);

        let plan = TransportPlan::for_policy(shared);
        assert_eq!(
            plan.as_slice(),
            &[
                ResolutionTransport::DirectAuthoritativeUdp,
                ResolutionTransport::DirectAuthoritativeTcp,
                ResolutionTransport::AuthenticatedAuthoritativeDoh,
            ]
        );
        assert!(!runtime_policy(&policy).unwrap().experimental_p2p_dns_relay);
    }

    #[test]
    fn opted_in_relay_is_auto_fallback_derived_from_shared_transport_plan() {
        let policy = ExtensionPolicy {
            p2p_dns_relay: true,
            ..ExtensionPolicy::default()
        };
        let shared = shared_resolution_policy(&policy).unwrap();

        assert_eq!(shared.dns_relay_requester, DnsRelayRequesterPolicy::Auto);
        assert_eq!(
            TransportPlan::for_policy(shared).as_slice(),
            &[
                ResolutionTransport::DirectAuthoritativeUdp,
                ResolutionTransport::DirectAuthoritativeTcp,
                ResolutionTransport::AuthenticatedAuthoritativeDoh,
                ResolutionTransport::HandshakeP2pDnsRelay,
            ]
        );
        assert!(runtime_policy(&policy).unwrap().experimental_p2p_dns_relay);
    }

    #[test]
    fn recursive_hns_doh_policy_is_blank_by_default_and_strictly_validated_by_rust() {
        let default_runtime = runtime_policy(&ExtensionPolicy::default()).unwrap();
        assert_eq!(default_runtime.hns_doh_resolver, None);

        let configured = ExtensionPolicy {
            recursive_hns_doh_url: " https://HNSDOH.COM:443/dns-query ".to_owned(),
            ..ExtensionPolicy::default()
        };
        assert_eq!(
            runtime_policy(&configured)
                .unwrap()
                .hns_doh_resolver
                .as_deref(),
            Some("https://hnsdoh.com/dns-query")
        );

        let invalid = ExtensionPolicy {
            recursive_hns_doh_url: "http://hnsdoh.com/dns-query".to_owned(),
            ..ExtensionPolicy::default()
        };
        let error = runtime_policy(&invalid).unwrap_err();
        assert_eq!(error.0, "invalidPolicy");
        assert!(error.1.contains("must use https"));
    }

    fn active_canonical_runtime(session_byte: u8) -> hns_browser_runtime::RuntimeSnapshot {
        let mut runtime =
            CanonicalRuntime::new(CanonicalRuntimeSessionId::new([session_byte; 16]).unwrap());
        for state in [
            CanonicalAuthorityState::LocalStateOpened,
            CanonicalAuthorityState::HeaderSyncing,
            CanonicalAuthorityState::HeaderCurrent,
            CanonicalAuthorityState::ProofReady,
            CanonicalAuthorityState::ResolutionTransportReady,
            CanonicalAuthorityState::DnssecVerified,
            CanonicalAuthorityState::DaneOriginVerified,
            CanonicalAuthorityState::BrowserBridgeReady,
            CanonicalAuthorityState::Active,
        ] {
            runtime.transition(state).unwrap();
        }
        runtime.admit_event().unwrap();
        runtime.snapshot()
    }

    fn canonical_policy(policy: &ExtensionPolicy) -> PolicySnapshot {
        PolicySnapshot::new(3, shared_resolution_policy(policy).unwrap()).unwrap()
    }

    fn hns_only_status_input(policy: PolicySnapshot) -> StatusInput {
        StatusInput {
            runtime: active_canonical_runtime(7),
            network: CanonicalNetwork::Regtest,
            policy,
            chain_anchor: Some(ChainAnchor {
                height: 42,
                tree_root: [4; 32],
            }),
            actual_transport: ResolutionTransport::DirectAuthoritativeTcp,
            identities: TransportIdentities::default(),
            registry_profile: policy.config().wire_profile,
            registry_fingerprint: [0; 32],
            protocol_version: 0,
            provider_readiness: ProviderReadiness::from_policy(policy),
            rate_limits: RateLimitState::default(),
            evidence: ValidationEvidence {
                hns_proof: CanonicalEvidenceState::Verified,
                dnssec: CanonicalEvidenceState::Verified,
                tlsa: CanonicalEvidenceState::Verified,
                dane: CanonicalEvidenceState::Verified,
                chain_current: CanonicalEvidenceState::Verified,
                origin_sni: CanonicalEvidenceState::Verified,
            },
            namespace_outcome: Some(CanonicalOutcomeKind::HnsOnly),
            hns_root_failure: None,
            icann_root_failure: None,
            selected_namespace: Some(CanonicalNamespace::Hns),
            selection_reason: Some(CanonicalSelectionReason::SingleRoot),
            decision_fingerprint: Some([12; 32]),
            icann_tls_action: None,
            icann_dnssec_status: None,
            degraded_reason: None,
            revocation_reason: None,
            unsupported_evidence: Vec::new(),
        }
    }

    fn icann_dane_status_input(
        outcome: CanonicalOutcomeKind,
        selection_reason: CanonicalSelectionReason,
    ) -> StatusInput {
        let policy = canonical_policy(&ExtensionPolicy::default());
        let mut input = hns_only_status_input(policy);
        input.chain_anchor = None;
        input.actual_transport = ResolutionTransport::ValidatingIcannDoh;
        input.evidence = ValidationEvidence {
            hns_proof: CanonicalEvidenceState::NotAttempted,
            dnssec: CanonicalEvidenceState::Verified,
            tlsa: CanonicalEvidenceState::Verified,
            dane: CanonicalEvidenceState::Verified,
            chain_current: CanonicalEvidenceState::NotAttempted,
            origin_sni: CanonicalEvidenceState::Verified,
        };
        input.namespace_outcome = Some(outcome);
        input.selected_namespace = Some(CanonicalNamespace::Icann);
        input.selection_reason = Some(selection_reason);
        input.decision_fingerprint = Some([13; 32]);
        input.icann_tls_action = Some(IcannTlsAction::EnforceDane);
        input.icann_dnssec_status = Some(IcannDnssecStatus::Secure);
        input
    }

    fn icann_webpki_status_input() -> StatusInput {
        let policy = canonical_policy(&ExtensionPolicy::default());
        let mut input = hns_only_status_input(policy);
        input.chain_anchor = None;
        input.actual_transport = ResolutionTransport::ValidatingIcannDoh;
        input.evidence = ValidationEvidence {
            hns_proof: CanonicalEvidenceState::NotAttempted,
            dnssec: CanonicalEvidenceState::Verified,
            tlsa: CanonicalEvidenceState::Unavailable,
            dane: CanonicalEvidenceState::NotAttempted,
            chain_current: CanonicalEvidenceState::NotAttempted,
            origin_sni: CanonicalEvidenceState::NotAttempted,
        };
        input.namespace_outcome = Some(CanonicalOutcomeKind::IcannOnly);
        input.selected_namespace = Some(CanonicalNamespace::Icann);
        input.selection_reason = Some(CanonicalSelectionReason::SingleRoot);
        input.decision_fingerprint = Some([15; 32]);
        input.icann_tls_action = Some(IcannTlsAction::WebPkiAuthenticatedAbsence);
        input.icann_dnssec_status = Some(IcannDnssecStatus::Secure);
        input
    }

    fn test_connect_security_decision(
        canonical: &CanonicalBrowserStatus,
        event_sequence: u64,
    ) -> ChromiumConnectSecurityDecision {
        test_connect_security_decision_at_epoch(canonical, event_sequence, 7)
    }

    fn test_connect_security_decision_at_epoch(
        canonical: &CanonicalBrowserStatus,
        event_sequence: u64,
        maintenance_epoch: u64,
    ) -> ChromiumConnectSecurityDecision {
        let mut result =
            chromium_security_result_from_canonical("www.example", 599, false, canonical, None);
        result.event_sequence = event_sequence;
        chromium_connect_security_decision_from_canonical(
            canonical,
            result,
            443,
            maintenance_epoch,
            123_456,
        )
        .unwrap()
    }

    fn observation_tuple(
        canonical: &CanonicalBrowserStatus,
        event_sequence: u64,
    ) -> CanonicalBrowserObservationTuple {
        CanonicalBrowserObservationTuple::new(
            canonical.runtime_session(),
            canonical.runtime_generation(),
            event_sequence,
            canonical.policy_generation(),
        )
        .unwrap()
    }

    #[test]
    fn security_result_uses_only_checked_canonical_status_fields() {
        let canonical = CanonicalBrowserStatus::new(hns_only_status_input(canonical_policy(
            &ExtensionPolicy::default(),
        )))
        .unwrap();
        let result =
            chromium_security_result_from_canonical("welcome", 200, true, &canonical, None);
        let encoded = serde_json::to_value(result).unwrap();

        assert_eq!(encoded["schemaVersion"], 3);
        assert_eq!(encoded["canonicalStatus"], "available");
        assert_eq!(encoded["eventSequence"], canonical.event_sequence());
        assert_eq!(
            encoded["runtimeSession"],
            URL_SAFE_NO_PAD.encode(canonical.runtime_session())
        );
        assert_eq!(encoded["runtimeGeneration"], canonical.runtime_generation());
        assert_eq!(encoded["policyGeneration"], canonical.policy_generation());
        assert_eq!(encoded["namespaceOutcome"], "hnsOnly");
        assert_eq!(encoded["selectedNamespace"], "hns");
        assert_eq!(encoded["namespaceSelectionReason"], "onlyAvailableRoot");
        assert_eq!(encoded["decisionFingerprint"], "0c".repeat(32));
        assert_eq!(encoded["hnsResolutionState"], "securePresent");
        assert_eq!(encoded["icannResolutionState"], "absent");
        assert_eq!(encoded["actualSelectedTransport"], "directAuthoritativeTcp");
        assert_eq!(encoded["localHnsProofState"], "verified");
        assert_eq!(encoded["localDnssecState"], "verified");
        assert_eq!(encoded["localTlsaState"], "verified");
        assert_eq!(encoded["localDaneState"], "verified");
        assert_eq!(encoded["peerIdentity"], Value::Null);
        assert_eq!(encoded["chainAnchor"]["localBestHeight"], 42);
        assert_eq!(encoded["registryProfile"], "denuoV1");
    }

    #[test]
    fn security_result_preserves_proof_contained_hns_success() {
        let policy = canonical_policy(&ExtensionPolicy::default());
        let mut input = hns_only_status_input(policy);
        input.actual_transport = ResolutionTransport::LocalHnsProof;
        let canonical = CanonicalBrowserStatus::new(input).unwrap();

        let result =
            chromium_security_result_from_canonical("shakeshift", 200, true, &canonical, None);
        let encoded = serde_json::to_value(result).unwrap();

        assert_eq!(encoded["host"], "shakeshift");
        assert_eq!(encoded["actualSelectedTransport"], "localHnsProof");
        assert_eq!(encoded["nameserverAuthority"], "localHnsProof");
        assert_eq!(encoded["localHnsProofState"], "verified");
        assert_eq!(encoded["canonicalStatus"], "available");
    }

    #[test]
    fn indeterminate_result_uses_typed_partial_root_states_without_subtype_claims() {
        let policy = canonical_policy(&ExtensionPolicy::default());
        let mut input = hns_only_status_input(policy);
        input.chain_anchor = None;
        input.actual_transport = ResolutionTransport::Unavailable;
        input.evidence = ValidationEvidence::not_attempted();
        input.namespace_outcome = None;
        input.hns_root_failure = Some(CanonicalRootFailureKind::Transport);
        input.icann_root_failure = None;
        input.selected_namespace = None;
        input.selection_reason = None;
        input.decision_fingerprint = None;
        let canonical = CanonicalBrowserStatus::new(input).unwrap();

        let encoded =
            serde_json::to_value(chromium_security_result_from_canonical_with_root_states(
                "intercepted.example",
                502,
                true,
                &canonical,
                Some(CanonicalRootResolutionStates::new(
                    RootResolutionDisposition::Failed,
                    RootResolutionDisposition::Absent,
                )),
                None,
            ))
            .unwrap();

        assert_eq!(encoded["namespaceOutcome"], "indeterminate");
        assert_eq!(encoded["hnsResolutionState"], "failed");
        assert_eq!(encoded["icannResolutionState"], "absent");
        assert_eq!(encoded["hnsRootFailure"], "transport");
        assert_eq!(encoded["icannRootFailure"], Value::Null);
        assert_ne!(encoded["icannResolutionState"], "authenticatedAbsent");
        assert_ne!(encoded["icannResolutionState"], "insecureAbsent");
    }

    #[test]
    fn relay_result_uses_only_canonical_intermediary_and_registry_identity() {
        let extension_policy = ExtensionPolicy {
            p2p_dns_relay: true,
            ..ExtensionPolicy::default()
        };
        let policy = canonical_policy(&extension_policy);
        let mut input = hns_only_status_input(policy);
        input.actual_transport = ResolutionTransport::HandshakeP2pDnsRelay;
        input.identities = TransportIdentities {
            peer: Some("198.51.100.7:12038".to_owned()),
            ..TransportIdentities::default()
        };
        input.registry_fingerprint = [8; 32];
        input.protocol_version = 1;
        let canonical = CanonicalBrowserStatus::new(input).unwrap();
        let encoded = serde_json::to_value(chromium_security_result_from_canonical(
            "welcome", 200, true, &canonical, None,
        ))
        .unwrap();

        assert_eq!(encoded["actualSelectedTransport"], "handshakeP2pDnsRelay");
        assert_eq!(
            encoded["nameserverAuthority"],
            "delegatedAuthoritativeNameserver"
        );
        assert_eq!(encoded["peerIdentity"], "198.51.100.7:12038");
        assert_eq!(encoded["proxyIdentity"], Value::Null);
        assert_eq!(encoded["targetIdentity"], Value::Null);
        assert_eq!(encoded["registryFingerprint"], "08".repeat(32));
        assert_eq!(encoded["protocolVersion"], 1);
        assert_eq!(encoded["authoritativeFallbackOccurred"], Value::Null);
    }

    #[test]
    fn icann_dane_result_uses_typed_validating_doh_without_trace_identity() {
        let canonical = CanonicalBrowserStatus::new(icann_dane_status_input(
            CanonicalOutcomeKind::IcannOnly,
            CanonicalSelectionReason::SingleRoot,
        ))
        .unwrap();
        let encoded = serde_json::to_value(chromium_security_result_from_canonical(
            "dane.example",
            200,
            true,
            &canonical,
            None,
        ))
        .unwrap();

        assert_eq!(encoded["actualSelectedTransport"], "icannDoh");
        assert_eq!(encoded["namespaceOutcome"], "icannOnly");
        assert_eq!(encoded["selectedNamespace"], "icann");
        assert_eq!(encoded["icannResolutionState"], "present");
        assert_eq!(encoded["nameserverAuthority"], "validatingIcannResolver");
        assert_eq!(encoded["peerIdentity"], Value::Null);
    }

    #[test]
    fn connect_decision_schema_is_explicit_host_scoped_and_not_an_http_result() {
        let canonical = CanonicalBrowserStatus::new(icann_webpki_status_input()).unwrap();
        let decision = test_connect_security_decision(&canonical, canonical.event_sequence());
        let encoded = serde_json::to_value(decision).unwrap();
        let object = encoded.as_object().unwrap();

        assert_eq!(encoded["schemaVersion"], 1);
        assert_eq!(encoded["observationKind"], "browserWebPkiPassthrough");
        assert_eq!(encoded["httpStatusObserved"], false);
        assert_eq!(encoded["observedAtUnixMs"], 123_456);
        assert_eq!(encoded["maintenanceEpoch"], 7);
        assert_eq!(encoded["host"], "www.example");
        assert_eq!(encoded["port"], 443);
        assert!(!object.contains_key("mainFrame"));
        assert!(!object.contains_key("statusCode"));
        assert_eq!(encoded["selectedNamespace"], "icann");
        assert_eq!(encoded["icannTlsAction"], "webPkiAuthenticatedAbsence");
        assert_eq!(encoded["icannDnssecStatus"], "secure");
        assert_eq!(encoded["actualSelectedTransport"], "icannDoh");
        assert_eq!(encoded["nameserverAuthority"], "validatingIcannResolver");
        assert_eq!(encoded["localHnsProofState"], "notAttempted");
        assert_eq!(encoded["localDnssecState"], "verified");
        assert_eq!(encoded["localTlsaState"], "unavailable");
        assert_eq!(encoded["localDaneState"], "notAttempted");
        assert_eq!(encoded["chainAnchor"]["localBestHeight"], Value::Null);
        assert_eq!(encoded["chainAnchor"]["targetHeight"], Value::Null);
        assert_eq!(encoded["chainAnchor"]["estimatedTargetHeight"], Value::Null);
    }

    #[test]
    fn connect_decision_requires_selected_icann_webpki_and_nonzero_correlation() {
        let webpki = CanonicalBrowserStatus::new(icann_webpki_status_input()).unwrap();
        let webpki_result =
            chromium_security_result_from_canonical("www.example", 200, false, &webpki, None);
        assert!(
            chromium_connect_security_decision_from_canonical(
                &webpki,
                webpki_result.clone(),
                0,
                7,
                1,
            )
            .is_none()
        );
        assert!(
            chromium_connect_security_decision_from_canonical(&webpki, webpki_result, 443, 0, 1,)
                .is_none()
        );

        let icann_dane = CanonicalBrowserStatus::new(icann_dane_status_input(
            CanonicalOutcomeKind::IcannOnly,
            CanonicalSelectionReason::SingleRoot,
        ))
        .unwrap();
        let icann_dane_result =
            chromium_security_result_from_canonical("dane.example", 200, false, &icann_dane, None);
        assert!(
            chromium_connect_security_decision_from_canonical(
                &icann_dane,
                icann_dane_result,
                443,
                7,
                1,
            )
            .is_none()
        );

        let hns = CanonicalBrowserStatus::new(hns_only_status_input(canonical_policy(
            &ExtensionPolicy::default(),
        )))
        .unwrap();
        let hns_result = chromium_security_result_from_canonical("welcome", 200, false, &hns, None);
        assert!(
            chromium_connect_security_decision_from_canonical(&hns, hns_result, 443, 7, 1,)
                .is_none()
        );
    }

    #[test]
    fn connect_decisions_are_bounded_ordered_and_deduplicated() {
        let canonical = CanonicalBrowserStatus::new(icann_webpki_status_input()).unwrap();
        let mut state = SecurityObservationState::default();
        for event_sequence in 1..=u64::try_from(MAX_RECENT_SECURITY_RESULTS + 5).unwrap() {
            retain_connect_security_decision(
                &mut state,
                test_connect_security_decision(&canonical, event_sequence),
            );
        }
        retain_connect_security_decision(
            &mut state,
            test_connect_security_decision(&canonical, 10),
        );

        assert_eq!(
            state.recent_connect_decisions.len(),
            MAX_RECENT_SECURITY_RESULTS
        );
        assert_eq!(
            state
                .recent_connect_decisions
                .front()
                .map(|decision| decision.event_sequence),
            Some(6)
        );
        assert_eq!(
            state
                .recent_connect_decisions
                .back()
                .map(|decision| decision.event_sequence),
            Some(u64::try_from(MAX_RECENT_SECURITY_RESULTS + 5).unwrap())
        );
    }

    #[test]
    fn convergent_default_keeps_canonical_icann_default_reason() {
        let canonical = CanonicalBrowserStatus::new(icann_dane_status_input(
            CanonicalOutcomeKind::BothConvergent,
            CanonicalSelectionReason::IcannDefault,
        ))
        .unwrap();
        let encoded = serde_json::to_value(chromium_security_result_from_canonical(
            "convergent.example",
            200,
            true,
            &canonical,
            None,
        ))
        .unwrap();

        assert_eq!(encoded["namespaceOutcome"], "bothConvergent");
        assert_eq!(encoded["namespaceSelectionReason"], "icannDefault");
        assert_eq!(encoded["hnsResolutionState"], "securePresent");
        assert_eq!(encoded["icannResolutionState"], "present");
    }

    #[test]
    fn neither_result_reaches_final_native_schema_with_exact_fingerprint() {
        let policy = canonical_policy(&ExtensionPolicy::default());
        let mut input = hns_only_status_input(policy);
        input.chain_anchor = None;
        input.actual_transport = ResolutionTransport::Unavailable;
        input.evidence = ValidationEvidence::not_attempted();
        input.namespace_outcome = Some(CanonicalOutcomeKind::Neither);
        input.selected_namespace = None;
        input.selection_reason = None;
        input.decision_fingerprint = Some([14; 32]);
        let canonical = CanonicalBrowserStatus::new(input).unwrap();
        let encoded = serde_json::to_value(chromium_security_result_from_canonical(
            "missing", 404, true, &canonical, None,
        ))
        .unwrap();

        assert_eq!(encoded["namespaceOutcome"], "neither");
        assert_eq!(encoded["selectedNamespace"], Value::Null);
        assert_eq!(encoded["namespaceSelectionReason"], "unavailable");
        assert_eq!(encoded["decisionFingerprint"], "0e".repeat(32));
        assert_eq!(encoded["hnsResolutionState"], "authenticatedAbsent");
        assert_eq!(encoded["icannResolutionState"], "absent");
        assert_eq!(encoded["actualSelectedTransport"], "unavailable");
    }

    #[test]
    fn unavailable_main_frame_clears_prior_canonical_result_without_fabricating_tuple() {
        let canonical = CanonicalBrowserStatus::new(hns_only_status_input(canonical_policy(
            &ExtensionPolicy::default(),
        )))
        .unwrap();
        let result = chromium_security_result_from_canonical("first", 200, true, &canonical, None);
        let mut state = SecurityObservationState::default();
        retain_security_observation(
            &mut state,
            true,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, canonical.event_sequence()),
                result: Box::new(result),
            },
        );
        assert_eq!(
            state
                .latest_main_frame
                .as_ref()
                .map(|result| result.host.as_str()),
            Some("first")
        );

        let unavailable_event = canonical.event_sequence() + 1;
        retain_security_observation(
            &mut state,
            true,
            7,
            CanonicalSecurityObservation::Unavailable {
                tuple: observation_tuple(&canonical, unavailable_event),
                reason: "p2pRegistryIdentityUnavailable",
            },
        );
        assert!(state.latest_main_frame.is_none());
        assert_eq!(
            state.latest_main_frame_unavailable_reason,
            Some("p2pRegistryIdentityUnavailable")
        );

        let newer_event = unavailable_event + 2;
        let mut newer =
            chromium_security_result_from_canonical("newer", 200, true, &canonical, None);
        newer.event_sequence = newer_event;
        retain_security_observation(
            &mut state,
            true,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, newer_event),
                result: Box::new(newer),
            },
        );
        retain_security_observation(
            &mut state,
            true,
            7,
            CanonicalSecurityObservation::Unavailable {
                tuple: observation_tuple(&canonical, unavailable_event + 1),
                reason: "staleUnavailable",
            },
        );
        assert_eq!(
            state
                .latest_main_frame
                .as_ref()
                .map(|result| result.host.as_str()),
            Some("newer")
        );
        assert_eq!(state.latest_main_frame_unavailable_reason, None);
    }

    #[test]
    fn header_maintenance_retains_new_epoch_and_rejects_late_old_epoch_results() {
        let canonical = CanonicalBrowserStatus::new(hns_only_status_input(canonical_policy(
            &ExtensionPolicy::default(),
        )))
        .unwrap();
        let webpki = CanonicalBrowserStatus::new(icann_webpki_status_input()).unwrap();
        let old_result =
            chromium_security_result_from_canonical("page.example", 200, true, &canonical, None);
        let observations = SecurityObservations::default();
        observations.activate(
            ActiveSecurityContext {
                runtime_session: old_result.runtime_session.clone(),
                runtime_generation: old_result.runtime_generation,
                policy_generation: old_result.policy_generation,
                proxy_generation: 9,
                network: old_result.network.clone(),
            },
            Some(7),
        );
        {
            let mut state = observations.state.lock().unwrap();
            retain_security_observation(
                &mut state,
                true,
                7,
                CanonicalSecurityObservation::Available {
                    tuple: observation_tuple(&canonical, old_result.event_sequence),
                    result: Box::new(old_result.clone()),
                },
            );
            retain_connect_security_decision(
                &mut state,
                test_connect_security_decision_at_epoch(&webpki, webpki.event_sequence(), 7),
            );
            assert!(state.latest_main_frame.is_some());
            assert_eq!(state.recent.len(), 1);
            assert_eq!(state.recent_connect_decisions.len(), 1);

            let new_event = old_result.event_sequence + 2;
            let mut new_result = old_result.clone();
            new_result.host = "new-epoch.example".to_owned();
            new_result.event_sequence = new_event;
            retain_security_observation(
                &mut state,
                true,
                8,
                CanonicalSecurityObservation::Available {
                    tuple: observation_tuple(&canonical, new_event),
                    result: Box::new(new_result),
                },
            );
            retain_connect_security_decision(
                &mut state,
                test_connect_security_decision_at_epoch(&webpki, new_event + 1, 8),
            );
        }

        // Model a CONNECT/HTTP callback that publishes under the new epoch
        // after maintenance releases but before sync_once returns.
        observations.retain_maintenance_epoch(Some(8));
        {
            let mut state = observations.state.lock().unwrap();
            retain_security_observation(
                &mut state,
                true,
                7,
                CanonicalSecurityObservation::Available {
                    tuple: observation_tuple(&canonical, old_result.event_sequence + 1),
                    result: Box::new(old_result),
                },
            );
            retain_connect_security_decision(
                &mut state,
                test_connect_security_decision_at_epoch(&webpki, webpki.event_sequence() + 1, 7),
            );
        }

        let state = observations.state.lock().unwrap();
        assert!(state.active.is_some());
        assert_eq!(state.highest_maintenance_epoch, Some(8));
        assert_eq!(state.latest_main_frame_maintenance_epoch, Some(8));
        assert_eq!(
            state
                .latest_main_frame
                .as_ref()
                .map(|result| result.host.as_str()),
            Some("new-epoch.example")
        );
        assert!(state.latest_main_frame_unavailable_reason.is_none());
        assert_eq!(state.recent.len(), 1);
        assert_eq!(state.recent_connect_decisions.len(), 1);
        drop(state);
        assert_eq!(
            observations
                .latest_main_frame(Some(8))
                .map(|result| result.host),
            Some("new-epoch.example".to_owned())
        );
        assert_eq!(observations.recent(Some(8)).len(), 1);
        assert_eq!(observations.recent_connect_decisions(Some(8)).len(), 1);
        assert!(observations.latest_main_frame(Some(7)).is_none());
        assert!(observations.recent(Some(7)).is_empty());
        assert!(observations.recent_connect_decisions(Some(7)).is_empty());
    }

    #[test]
    fn subresource_result_is_recent_without_replacing_latest_main_frame() {
        let canonical = CanonicalBrowserStatus::new(hns_only_status_input(canonical_policy(
            &ExtensionPolicy::default(),
        )))
        .unwrap();
        let main_frame =
            chromium_security_result_from_canonical("page.example", 200, true, &canonical, None);
        let subresource =
            chromium_security_result_from_canonical("asset.example", 200, false, &canonical, None);
        let main_event = canonical.event_sequence();
        let subresource_event = main_event + 1;
        let mut subresource = subresource;
        subresource.event_sequence = subresource_event;
        let mut state = SecurityObservationState::default();

        retain_security_observation(
            &mut state,
            true,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, main_event),
                result: Box::new(main_frame),
            },
        );
        retain_security_observation(
            &mut state,
            false,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, subresource_event),
                result: Box::new(subresource),
            },
        );
        let older_event = main_event - 1;
        let mut older =
            chromium_security_result_from_canonical("older.example", 200, false, &canonical, None);
        older.event_sequence = older_event;
        retain_security_observation(
            &mut state,
            false,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, older_event),
                result: Box::new(older),
            },
        );
        let mut duplicate = chromium_security_result_from_canonical(
            "duplicate.example",
            200,
            false,
            &canonical,
            None,
        );
        duplicate.event_sequence = main_event;
        retain_security_observation(
            &mut state,
            false,
            7,
            CanonicalSecurityObservation::Available {
                tuple: observation_tuple(&canonical, main_event),
                result: Box::new(duplicate),
            },
        );

        assert_eq!(
            state
                .latest_main_frame
                .as_ref()
                .map(|result| result.host.as_str()),
            Some("page.example")
        );
        assert_eq!(
            state
                .recent
                .iter()
                .map(|entry| entry.result.host.as_str())
                .collect::<Vec<_>>(),
            vec!["older.example", "page.example", "asset.example"]
        );
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

    #[cfg(unix)]
    #[test]
    fn controller_rejects_a_symlink_data_root_before_mutation() {
        use std::os::unix::fs::symlink;

        let nonce = generate_host_session().unwrap();
        let target = std::env::temp_dir().join(format!("hns-native-host-target-{nonce}"));
        let link = std::env::temp_dir().join(format!("hns-native-host-link-{nonce}"));
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert!(NativeHostController::open(&link, NetworkKind::Regtest).is_err());
        assert!(fs::read_dir(&target).unwrap().next().is_none());

        fs::remove_file(link).unwrap();
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn hello_distinguishes_pool_verifier_core_from_product_availability() {
        let path = std::env::temp_dir().join(format!(
            "hns-chromium-native-pool-capability-test-{}",
            generate_host_session().unwrap()
        ));
        let mut controller = NativeHostController::open(&path, NetworkKind::Regtest).unwrap();
        let (response, shutdown) = controller
            .handle_json(br#"{"command":"hello","schemaVersion":1,"requestId":"hello-pool"}"#);

        assert!(!shutdown);
        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(
            result["capabilities"]["meshminePoolStatsVerifierCore"],
            true
        );
        assert_eq!(
            result["capabilities"]["meshminePoolStatsVerifierSchemaVersion"],
            MESHMINE_POOL_STATS_VERIFIER_SCHEMA_VERSION
        );
        assert_eq!(result["capabilities"]["meshmineHrmAuthorityAdapter"], false);
        assert_eq!(result["capabilities"]["meshmineLegacyHsa1Accepted"], false);
        assert_eq!(result["capabilities"]["meshmineVerifiedPoolStats"], false);
        assert_eq!(result["capabilities"]["hnsr"], false);

        drop(controller);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn controller_lifecycle_returns_pac_credentials_and_monotonic_observability() {
        let path = std::env::temp_dir().join(format!(
            "hns-chromium-native-host-test-{}",
            generate_host_session().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        }
        let mut controller = NativeHostController::open(&path, NetworkKind::Regtest).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        }
        let start = br#"{"command":"start","schemaVersion":1,"requestId":"start-1","policy":{}}"#;
        let (response, shutdown) = controller.handle_json(start);

        assert!(!shutdown);
        assert!(response.ok);
        assert_eq!(response.event_sequence, 1);
        assert_eq!(response.runtime_generation, Some(2));
        let result = response.result.unwrap();
        let maintenance_epoch = controller.runtime.security_maintenance_epoch().unwrap();
        assert_ne!(maintenance_epoch, 0);
        assert_eq!(result["state"], "active");
        assert_eq!(result["securityMaintenanceEpoch"], maintenance_epoch);
        assert_eq!(result["ca"]["state"], "needsInstallation");
        assert_eq!(result["headerSync"]["network"], "regtest");
        assert_eq!(result["headerSync"]["bestHeight"], 0);
        assert_eq!(result["headerSyncUnavailableReason"], Value::Null);
        assert_eq!(result["latestMainFrameSecurity"], Value::Null);
        assert_eq!(result["walletAbi"]["available"], false);
        assert_eq!(
            result["walletAbi"]["reason"],
            if cfg!(unix) {
                "walletArtifactMissing"
            } else {
                "walletArtifactPlatformUnsupported"
            }
        );
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
        assert_eq!(
            controller.status_result()["securityMaintenanceEpoch"],
            maintenance_epoch
        );

        let wallet_request = br#"{"command":"walletProviderCapabilities","schemaVersion":1,"requestId":"wallet-1","providerAbiVersion":2}"#;
        let (response, shutdown) = controller.handle_json(wallet_request);
        assert!(!shutdown);
        assert!(!response.ok);
        assert_eq!(response.event_sequence, 2);
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(if cfg!(unix) {
                "walletArtifactMissing"
            } else {
                "walletArtifactPlatformUnsupported"
            })
        );

        let shutdown_request =
            br#"{"command":"shutdown","schemaVersion":1,"requestId":"shutdown-1"}"#;
        let (response, shutdown) = controller.handle_json(shutdown_request);
        assert!(shutdown);
        assert!(response.ok);
        assert_eq!(response.event_sequence, 3);
        assert_eq!(response.runtime_generation, None);
        assert_eq!(response.result.unwrap()["state"], "stopped");

        drop(controller);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn production_neither_crosses_proxy_observer_native_schema_and_js_validation() {
        let path = std::env::temp_dir().join(format!(
            "hns-chromium-native-neither-test-{}",
            generate_host_session().unwrap()
        ));
        install_cached_regtest_non_inclusion(&path, "missing");
        let mut controller = NativeHostController::open(&path, NetworkKind::Regtest).unwrap();
        let start =
            br#"{"command":"start","schemaVersion":1,"requestId":"start-neither","policy":{}}"#;
        let (response, shutdown) = controller.handle_json(start);
        assert!(!shutdown);
        assert!(response.ok);
        let proxy = controller.proxy.as_ref().unwrap();
        let credentials = STANDARD.encode(format!(
            "{}:{}",
            proxy.authorization_username(),
            proxy.authorization_password()
        ));
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
        client
            // The full workspace suite can saturate slower CI runners while
            // this production proxy path performs its cryptographic checks.
            // Keep the test bounded without making ordinary parallel load a
            // false protocol failure.
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .write_all(
                format!(
                    "GET http://missing/ HTTP/1.1\r\nHost: missing\r\nProxy-Authorization: Basic {credentials}\r\nSec-Fetch-Dest: document\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        client.flush().unwrap();
        let mut response_bytes = Vec::new();
        client.read_to_end(&mut response_bytes).unwrap();
        assert!(response_bytes.starts_with(b"HTTP/1.1 404 Origin Not Found\r\n"));

        let status = controller.status_result();
        let result = status["latestMainFrameSecurity"].clone();
        assert_eq!(result["schemaVersion"], 3);
        assert_eq!(result["canonicalStatus"], "available");
        assert_eq!(result["namespaceOutcome"], "neither");
        assert_eq!(result["selectedNamespace"], Value::Null);
        assert_eq!(result["namespaceSelectionReason"], "unavailable");
        assert!(
            result["decisionFingerprint"]
                .as_str()
                .is_some_and(|fingerprint| fingerprint != "0".repeat(64))
        );
        let runtime = json!({
            "runtimeSession": status["runtimeSession"],
            "runtimeGeneration": status["runtimeGeneration"],
            "policyGeneration": status["policyGeneration"]
        });
        assert_security_result_passes_extension_validator(&result, &runtime);

        controller.stop_proxy();
        drop(controller);
        std::fs::remove_dir_all(path).unwrap();
    }

    fn install_cached_regtest_non_inclusion(path: &Path, root_name: &str) {
        let base = path.join("hns-regtest");
        fs::create_dir_all(&base).unwrap();
        let tree_root = Hash::new([34; 32]);
        let genesis_header = BlockHeader::genesis_for_network(NetworkKind::Regtest);
        let genesis = StoredHeader {
            hash: genesis_header.hash(),
            chainwork: Chainwork::from_bits(genesis_header.bits).unwrap(),
            header: genesis_header,
            height: Height(0),
        };
        let mut child_header = BlockHeader::genesis_for_network(NetworkKind::Regtest);
        child_header.prev_block = genesis.hash;
        child_header.tree_root = tree_root;
        child_header.time = child_header.time.saturating_add(1);
        child_header.extra_nonce[..4].copy_from_slice(&1_u32.to_le_bytes());
        let child_work = Chainwork::from_bits(child_header.bits).unwrap();
        let child = StoredHeader {
            hash: child_header.hash(),
            chainwork: genesis.chainwork.checked_add(&child_work),
            header: child_header,
            height: Height(1),
        };
        let mut headers = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        headers.put_header(genesis.clone()).unwrap();
        headers.put_header(child.clone()).unwrap();
        headers
            .replace_canonical_chain(&[genesis, child.clone()])
            .unwrap();
        drop(headers);

        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        resources
            .insert(
                VerifiedResourceValue::non_inclusion(
                    root_name.to_owned(),
                    NameHash::from_name(root_name).unwrap(),
                )
                .with_anchor(tree_root, child.height),
            )
            .unwrap();
    }

    fn assert_security_result_passes_extension_validator(result: &Value, runtime: &Value) {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .unwrap();
        let validator = repository.join("extension/src/security-result.js");
        let script = r#"
            import fs from "node:fs";
            import { pathToFileURL } from "node:url";
            const { currentSecurityResult } =
              await import(pathToFileURL(process.argv[1]).href);
            const payload = JSON.parse(fs.readFileSync(0, "utf8"));
            if (currentSecurityResult(payload.result, payload.runtime) === null) {
              throw new Error("extension rejected the production native security result");
            }
        "#;
        let mut child = Command::new("node")
            .args(["--input-type=module", "--eval", script])
            .arg(&validator)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        serde_json::to_writer(
            child.stdin.as_mut().unwrap(),
            &json!({"result": result, "runtime": runtime}),
        )
        .unwrap();
        drop(child.stdin.take());
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "extension validator failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
