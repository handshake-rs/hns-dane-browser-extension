//! Native, profile-specific verification for MeshMine public pool statistics.
//!
//! The HTTP endpoint is deliberately absent from this API. A caller supplies an
//! independently selected Handshake name and network plus a non-forgeable
//! [`VerifiedHnsResource`]. The verifier then binds the canonical `hsa1`
//! authority, HNSA service authorization, endpoint delegation, and signed
//! `pool-stats` snapshot before returning a minimized value.
//!
//! A verified value is returned only after the caller-provided commit function
//! durably accepts the complete replacement state. The state checksum detects
//! corruption; the embedding platform must provide atomic, authenticated,
//! rollback-resistant storage and serialize admission per HNS name/network.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "the public API keeps the experimental profile and persistence boundary explicit"
)]

use std::error::Error;
use std::fmt;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_light_chain::{HnsResourceRecord, VerifiedHnsResource};
use hns_service_authority::{
    AuthorityError, AuthorityRecord, EndpointDelegationV1, ServiceAuthorizationV1, ServiceIdentity,
    select_authority_record,
};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;

/// Version of this verifier/state contract, independent of native messaging.
pub const VERIFIER_SCHEMA_VERSION: u32 = 1;
/// Private experimental profile pending a standards assignment.
pub const EXPERIMENTAL_PROFILE_ID: u16 = 0xff00;
/// Exact HNSA service selected independently of operator input.
pub const SERVICE_NAME: &str = "pool-stats";
/// The sole capability admitted by this read-only profile.
pub const READ_STATS_CAPABILITY: u32 = 1;
/// Maximum lifetime of an endpoint-signed statistics snapshot.
pub const MAX_SNAPSHOT_LIFETIME_SECONDS: u64 = 120;
/// Maximum canonical signed snapshot size.
pub const MAX_SNAPSHOT_BYTES: usize = 512;
/// Maximum decoded size of either opaque HNSA document object.
pub const MAX_HNSA_OBJECT_BYTES: usize = 1_024;
/// Maximum bounded JSON document size accepted by the native verifier.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1_024;
/// Maximum endpoint-key histories retained under one HNS authority scope.
pub const MAX_ENDPOINT_HISTORIES: usize = 16;
/// Maximum global operator histories retained under one HNS authority scope.
pub const MAX_OPERATOR_HISTORIES: usize = 128;
/// Maximum canonical encoded replacement-state size.
pub const MAX_STATE_BYTES: usize = 20_000;

const SNAPSHOT_VERSION: u8 = 1;
const MAX_SIGNATURE_BYTES: usize = 80;
const SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"HNS-MESHMINE-POOL-STATS-V1\0";
const AUTHORITY_DIGEST_DOMAIN: &[u8] = b"HNS-MESHMINE-AUTHORITY-STATE-V1\0";
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"HNS-MESHMINE-SNAPSHOT-STATE-V1\0";
const STATE_CHECKSUM_DOMAIN: &[u8] = b"HNS-MESHMINE-POOL-STATE-CHECKSUM-V1\0";
const STATE_MAGIC: &[u8; 4] = b"MPS1";
const STATE_VERSION: u8 = 1;
const STATE_CHECKSUM_BYTES: usize = 32;

/// Independent identity, external generations, and trusted native time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStatsRequest<'a> {
    expected_name: &'a [u8],
    expected_network_magic: u32,
    resource_generation: u64,
    profile_policy_generation: u64,
    trusted_now: u64,
}

impl<'a> PoolStatsRequest<'a> {
    /// Construct a request from an independently selected HNS label and network.
    pub fn new(
        expected_name: &'a [u8],
        expected_network_magic: u32,
        resource_generation: u64,
        profile_policy_generation: u64,
        trusted_now: u64,
    ) -> Result<Self, PoolStatsError> {
        if !is_canonical_hns_label(expected_name) {
            return Err(PoolStatsError::InvalidExpectedName);
        }
        if expected_network_magic == 0 {
            return Err(PoolStatsError::InvalidExpectedNetwork);
        }
        if resource_generation == 0 || profile_policy_generation == 0 {
            return Err(PoolStatsError::InvalidContextGeneration);
        }
        Ok(Self {
            expected_name,
            expected_network_magic,
            resource_generation,
            profile_policy_generation,
            trusted_now,
        })
    }

    /// Independently selected exact lowercase HNS label.
    #[must_use]
    pub const fn expected_name(self) -> &'a [u8] {
        self.expected_name
    }

    /// Independently selected exact Handshake packet magic.
    #[must_use]
    pub const fn expected_network_magic(self) -> u32 {
        self.expected_network_magic
    }

    /// Monotonic generation of the platform's accepted proof-backed resource.
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    /// Monotonic generation of the fixed profile policy.
    #[must_use]
    pub const fn profile_policy_generation(self) -> u64 {
        self.profile_policy_generation
    }

    /// Trusted Unix time observed by the native platform.
    #[must_use]
    pub const fn trusted_now(self) -> u64 {
        self.trusted_now
    }
}

/// Public operator mode from a verified endpoint-signed snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicMode {
    Bootstrapping,
    Mining,
    Degraded,
    Fallback,
    Draining,
    Stopped,
}

impl TryFrom<u8> for PublicMode {
    type Error = PoolStatsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bootstrapping),
            1 => Ok(Self::Mining),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Fallback),
            4 => Ok(Self::Draining),
            5 => Ok(Self::Stopped),
            _ => Err(PoolStatsError::InvalidSnapshot("unknown operator mode")),
        }
    }
}

/// A last-found block included in a verified snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFoundBlock {
    height: u32,
    hash: [u8; 32],
}

impl VerifiedFoundBlock {
    #[must_use]
    pub const fn height(self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn hash(self) -> [u8; 32] {
        self.hash
    }
}

/// Minimized public statistics that passed every native verification layer.
///
/// HNSA encodings, signatures, public keys, and raw proof material are omitted.
/// Statistics are authenticated operator claims, not Handshake consensus or
/// chain truth. Cached use additionally requires trusted time below
/// [`Self::valid_until`] and the current persisted state generation to equal
/// [`Self::admission_generation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPoolStatsSnapshot {
    hns_name: Vec<u8>,
    network_magic: u32,
    resource_generation: u64,
    profile_policy_generation: u64,
    admission_generation: u64,
    verified_at: u64,
    operator_id: [u8; 32],
    endpoint_sequence: u64,
    sequence: u64,
    generated_at: u64,
    snapshot_expires_at: u64,
    valid_until: u64,
    tip_height: u32,
    tip_hash: [u8; 32],
    connected_miners: u32,
    connected_mesh_peers: u32,
    accepted_shares: u64,
    rejected_shares: u64,
    pending_captures: u32,
    last_found_block: Option<VerifiedFoundBlock>,
    mode: PublicMode,
    production_eligible: bool,
}

impl VerifiedPoolStatsSnapshot {
    #[must_use]
    pub fn hns_name(&self) -> &[u8] {
        &self.hns_name
    }

    #[must_use]
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    #[must_use]
    pub const fn profile_policy_generation(&self) -> u64 {
        self.profile_policy_generation
    }

    /// State generation durably committed before this value was released.
    #[must_use]
    pub const fn admission_generation(&self) -> u64 {
        self.admission_generation
    }

    #[must_use]
    pub const fn verified_at(&self) -> u64 {
        self.verified_at
    }

    #[must_use]
    pub const fn operator_id(&self) -> [u8; 32] {
        self.operator_id
    }

    #[must_use]
    pub const fn endpoint_sequence(&self) -> u64 {
        self.endpoint_sequence
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn generated_at(&self) -> u64 {
        self.generated_at
    }

    /// Expiry carried by the authenticated operator snapshot.
    #[must_use]
    pub const fn snapshot_expires_at(&self) -> u64 {
        self.snapshot_expires_at
    }

    /// Earliest of the snapshot expiry and proof-anchor currency expiry.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    #[must_use]
    pub const fn tip_height(&self) -> u32 {
        self.tip_height
    }

    #[must_use]
    pub const fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    #[must_use]
    pub const fn connected_miners(&self) -> u32 {
        self.connected_miners
    }

    #[must_use]
    pub const fn connected_mesh_peers(&self) -> u32 {
        self.connected_mesh_peers
    }

    #[must_use]
    pub const fn accepted_shares(&self) -> u64 {
        self.accepted_shares
    }

    #[must_use]
    pub const fn rejected_shares(&self) -> u64 {
        self.rejected_shares
    }

    #[must_use]
    pub const fn pending_captures(&self) -> u32 {
        self.pending_captures
    }

    #[must_use]
    pub const fn last_found_block(&self) -> Option<VerifiedFoundBlock> {
        self.last_found_block
    }

    #[must_use]
    pub const fn mode(&self) -> PublicMode {
        self.mode
    }

    /// Authenticated operator claim; never consensus or settlement authority.
    #[must_use]
    pub const fn production_eligible(&self) -> bool {
        self.production_eligible
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum StateStatus {
    Active = 1,
    Conflicted = 2,
    Exhausted = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationState {
    serial: u64,
    id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DelegationState {
    sequence: u64,
    id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperatorState {
    operator_id: [u8; 32],
    sequence: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EndpointState {
    endpoint_key: [u8; 33],
    delegation: Option<DelegationState>,
}

/// Bounded durable serial, sequence, trusted-time, and conflict state.
///
/// The canonical checksum is not an authenticator. Use [`verify_and_commit`]
/// with a store that provides atomic compare-generation persistence and
/// external rollback resistance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolStatsState {
    generation: u64,
    resource_generation: u64,
    authority_resource_generation: u64,
    profile_policy_generation: u64,
    trusted_time_high_water: u64,
    status: StateStatus,
    network_magic: u32,
    name_hash: [u8; 32],
    authority_digest: [u8; 32],
    authorization: Option<AuthorizationState>,
    endpoints: Vec<EndpointState>,
    operators: Vec<OperatorState>,
}

impl PoolStatsState {
    /// Construct an unscoped state for first use.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            resource_generation: 0,
            authority_resource_generation: 0,
            profile_policy_generation: 0,
            trusted_time_high_water: 0,
            status: StateStatus::Active,
            network_magic: 0,
            name_hash: [0; 32],
            authority_digest: [0; 32],
            authorization: None,
            endpoints: Vec::new(),
            operators: Vec::new(),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    #[must_use]
    pub const fn profile_policy_generation(&self) -> u64 {
        self.profile_policy_generation
    }

    #[must_use]
    pub const fn trusted_time_high_water(&self) -> u64 {
        self.trusted_time_high_water
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, StateStatus::Active)
    }

    #[must_use]
    pub const fn is_conflicted(&self) -> bool {
        matches!(self.status, StateStatus::Conflicted)
    }

    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        matches!(self.status, StateStatus::Exhausted)
    }

    /// Canonically encode the complete scoped state with a corruption checksum.
    pub fn encode(&self) -> Result<Vec<u8>, PoolStatsError> {
        if !self.valid_shape() {
            return Err(PoolStatsError::InvalidState);
        }
        let mut output = Vec::with_capacity(MAX_STATE_BYTES);
        output.extend_from_slice(STATE_MAGIC);
        output.push(STATE_VERSION);
        output.extend_from_slice(&self.generation.to_le_bytes());
        output.extend_from_slice(&self.resource_generation.to_le_bytes());
        output.extend_from_slice(&self.authority_resource_generation.to_le_bytes());
        output.extend_from_slice(&self.profile_policy_generation.to_le_bytes());
        output.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        output.push(self.status as u8);
        output.extend_from_slice(&self.network_magic.to_le_bytes());
        output.extend_from_slice(&self.name_hash);
        output.extend_from_slice(&self.authority_digest);
        output.push(u8::from(self.authorization.is_some()));
        match self.authorization {
            Some(authorization) => {
                output.extend_from_slice(&authorization.serial.to_le_bytes());
                output.extend_from_slice(&authorization.id);
            }
            None => output.extend_from_slice(&[0; 40]),
        }
        output.push(u8::try_from(self.endpoints.len()).map_err(|_| PoolStatsError::InvalidState)?);
        for endpoint in &self.endpoints {
            output.extend_from_slice(&endpoint.endpoint_key);
            output.push(u8::from(endpoint.delegation.is_some()));
            match endpoint.delegation {
                Some(delegation) => {
                    output.extend_from_slice(&delegation.sequence.to_le_bytes());
                    output.extend_from_slice(&delegation.id);
                }
                None => output.extend_from_slice(&[0; 40]),
            }
        }
        output.push(u8::try_from(self.operators.len()).map_err(|_| PoolStatsError::InvalidState)?);
        for operator in &self.operators {
            output.extend_from_slice(&operator.operator_id);
            output.extend_from_slice(&operator.sequence.to_le_bytes());
            output.extend_from_slice(&operator.digest);
        }
        if output.len().saturating_add(STATE_CHECKSUM_BYTES) > MAX_STATE_BYTES {
            return Err(PoolStatsError::InvalidState);
        }
        let checksum = blake2b_256(STATE_CHECKSUM_DOMAIN, &[&output])?;
        output.extend_from_slice(&checksum);
        Ok(output)
    }

    /// Decode one canonical checksummed state from trusted platform storage.
    pub fn decode(input: &[u8]) -> Result<Self, PoolStatsError> {
        if input.len() <= STATE_CHECKSUM_BYTES || input.len() > MAX_STATE_BYTES {
            return Err(PoolStatsError::InvalidState);
        }
        let payload_length = input.len() - STATE_CHECKSUM_BYTES;
        let (payload, encoded_checksum) = input.split_at(payload_length);
        if blake2b_256(STATE_CHECKSUM_DOMAIN, &[payload])? != encoded_checksum {
            return Err(PoolStatsError::InvalidState);
        }
        let mut reader = StateReader::new(payload);
        if reader.array::<4>()? != *STATE_MAGIC || reader.u8()? != STATE_VERSION {
            return Err(PoolStatsError::InvalidState);
        }
        let generation = reader.u64()?;
        let resource_generation = reader.u64()?;
        let authority_resource_generation = reader.u64()?;
        let profile_policy_generation = reader.u64()?;
        let trusted_time_high_water = reader.u64()?;
        let status = match reader.u8()? {
            1 => StateStatus::Active,
            2 => StateStatus::Conflicted,
            3 => StateStatus::Exhausted,
            _ => return Err(PoolStatsError::InvalidState),
        };
        let network_magic = reader.u32()?;
        let name_hash = reader.array()?;
        let authority_digest = reader.array()?;
        let authorization_present = reader.u8()?;
        let authorization_serial = reader.u64()?;
        let authorization_id = reader.array()?;
        let authorization = match authorization_present {
            0 if authorization_serial == 0 && authorization_id == [0; 32] => None,
            1 if authorization_serial != 0 && authorization_id != [0; 32] => {
                Some(AuthorizationState {
                    serial: authorization_serial,
                    id: authorization_id,
                })
            }
            _ => return Err(PoolStatsError::InvalidState),
        };
        let endpoint_count = usize::from(reader.u8()?);
        if endpoint_count > MAX_ENDPOINT_HISTORIES {
            return Err(PoolStatsError::InvalidState);
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            let endpoint_key = reader.array()?;
            VerifyingKey::from_sec1_bytes(&endpoint_key)
                .map_err(|_| PoolStatsError::InvalidState)?;
            let delegation_present = reader.u8()?;
            let delegation_sequence = reader.u64()?;
            let delegation_id = reader.array()?;
            let delegation = match delegation_present {
                0 if delegation_sequence == 0 && delegation_id == [0; 32] => None,
                1 if delegation_sequence != 0 && delegation_id != [0; 32] => {
                    Some(DelegationState {
                        sequence: delegation_sequence,
                        id: delegation_id,
                    })
                }
                _ => return Err(PoolStatsError::InvalidState),
            };
            endpoints.push(EndpointState {
                endpoint_key,
                delegation,
            });
        }
        if !strictly_sorted_by(&endpoints, |endpoint| endpoint.endpoint_key) {
            return Err(PoolStatsError::InvalidState);
        }
        let operator_count = usize::from(reader.u8()?);
        if operator_count > MAX_OPERATOR_HISTORIES {
            return Err(PoolStatsError::InvalidState);
        }
        let mut operators = Vec::with_capacity(operator_count);
        for _ in 0..operator_count {
            let operator = OperatorState {
                operator_id: reader.array()?,
                sequence: reader.u64()?,
                digest: reader.array()?,
            };
            if operator.operator_id == [0; 32]
                || operator.sequence == 0
                || operator.digest == [0; 32]
            {
                return Err(PoolStatsError::InvalidState);
            }
            operators.push(operator);
        }
        reader.finish()?;
        if !strictly_sorted_by(&operators, |operator| operator.operator_id) {
            return Err(PoolStatsError::InvalidState);
        }
        let state = Self {
            generation,
            resource_generation,
            authority_resource_generation,
            profile_policy_generation,
            trusted_time_high_water,
            status,
            network_magic,
            name_hash,
            authority_digest,
            authorization,
            endpoints,
            operators,
        };
        if !state.valid_shape() || state.encode()?.as_slice() != input {
            return Err(PoolStatsError::InvalidState);
        }
        Ok(state)
    }

    fn valid_shape(&self) -> bool {
        self.generation != 0
            && self.network_magic != 0
            && self.endpoints.len() <= MAX_ENDPOINT_HISTORIES
            && strictly_sorted_by(&self.endpoints, |endpoint| endpoint.endpoint_key)
            && self.endpoints.iter().all(|endpoint| {
                endpoint.endpoint_key != [0; 33]
                    && endpoint.delegation.is_none_or(|delegation| {
                        delegation.sequence != 0 && delegation.id != [0; 32]
                    })
            })
            && self.operators.len() <= MAX_OPERATOR_HISTORIES
            && strictly_sorted_by(&self.operators, |operator| operator.operator_id)
            && self.operators.iter().all(|operator| {
                operator.operator_id != [0; 32]
                    && operator.sequence != 0
                    && operator.digest != [0; 32]
            })
            && if self.authority_digest == [0; 32] {
                self.resource_generation != 0
                    && self.authority_resource_generation == 0
                    && self.profile_policy_generation != 0
                    && matches!(self.status, StateStatus::Active)
                    && self.authorization.is_none()
                    && self.endpoints.is_empty()
                    && self.operators.is_empty()
            } else {
                self.resource_generation != 0
                    && self.authority_resource_generation != 0
                    && self.authority_resource_generation <= self.resource_generation
                    && self.profile_policy_generation != 0
                    && match self.authorization {
                        Some(authorization) => {
                            authorization.serial != 0 && authorization.id != [0; 32]
                        }
                        None => self.endpoints.is_empty() && self.operators.is_empty(),
                    }
            }
    }

    fn scope_matches(&self, network_magic: u32, name_hash: [u8; 32]) -> bool {
        self.generation == 0 || (self.network_magic == network_magic && self.name_hash == name_hash)
    }

    fn observe_context(
        &mut self,
        evidence: ResourceEvidence<'_>,
        request: PoolStatsRequest<'_>,
    ) -> Result<(), PoolStatsError> {
        if self.generation == 0 {
            self.bump_generation()?;
            self.resource_generation = request.resource_generation;
            self.profile_policy_generation = request.profile_policy_generation;
            self.trusted_time_high_water = request.trusted_now;
            self.status = StateStatus::Active;
            self.network_magic = evidence.network_magic;
            self.name_hash = evidence.name_hash;
            return Ok(());
        }
        if !self.scope_matches(evidence.network_magic, evidence.name_hash) {
            return Err(PoolStatsError::StateScopeMismatch);
        }
        let generation_rollback = request.resource_generation < self.resource_generation
            || request.profile_policy_generation < self.profile_policy_generation;
        let clock_rollback = request.trusted_now < self.trusted_time_high_water;
        if request.resource_generation > self.resource_generation
            || request.profile_policy_generation > self.profile_policy_generation
            || request.trusted_now > self.trusted_time_high_water
        {
            self.bump_generation()?;
            self.resource_generation = self.resource_generation.max(request.resource_generation);
            self.profile_policy_generation = self
                .profile_policy_generation
                .max(request.profile_policy_generation);
            self.trusted_time_high_water = self.trusted_time_high_water.max(request.trusted_now);
        }
        if generation_rollback {
            return Err(PoolStatsError::StateRollback);
        }
        if clock_rollback {
            return Err(PoolStatsError::TrustedClockRollback);
        }
        Ok(())
    }

    fn bind_resource(
        &mut self,
        evidence: ResourceEvidence<'_>,
        request: PoolStatsRequest<'_>,
        authority_digest: [u8; 32],
    ) -> Result<(), PoolStatsError> {
        self.observe_context(evidence, request)?;
        if self.authority_digest == [0; 32] {
            self.bump_generation()?;
            self.authority_resource_generation = request.resource_generation;
            self.authority_digest = authority_digest;
            return Ok(());
        }
        if authority_digest != self.authority_digest {
            if request.resource_generation <= self.authority_resource_generation {
                return Err(PoolStatsError::StateRollback);
            }
            self.bump_generation()?;
            self.authority_resource_generation = request.resource_generation;
            self.authority_digest = authority_digest;
            self.authorization = None;
            self.endpoints.clear();
            self.operators.clear();
            self.status = StateStatus::Active;
            return Ok(());
        }
        if request.resource_generation > self.authority_resource_generation {
            self.bump_generation()?;
            self.authority_resource_generation = request.resource_generation;
        }
        Ok(())
    }

    fn require_active(&self) -> Result<(), PoolStatsError> {
        match self.status {
            StateStatus::Active => Ok(()),
            StateStatus::Conflicted => Err(PoolStatsError::StateConflicted),
            StateStatus::Exhausted => Err(PoolStatsError::StateExhausted),
        }
    }

    fn advance_authorization(&mut self, serial: u64, id: [u8; 32]) -> Result<(), PoolStatsError> {
        match self.authorization {
            None => {
                self.bump_generation()?;
                self.authorization = Some(AuthorizationState { serial, id });
                Ok(())
            }
            Some(current) if serial < current.serial => Err(PoolStatsError::SequenceRollback),
            Some(current) if serial == current.serial && id != current.id => {
                self.mark_conflicted()?;
                Err(PoolStatsError::ConflictingSequence)
            }
            Some(current) if serial == current.serial => Ok(()),
            Some(_) => {
                self.bump_generation()?;
                self.authorization = Some(AuthorizationState { serial, id });
                for endpoint in &mut self.endpoints {
                    endpoint.delegation = None;
                }
                Ok(())
            }
        }
    }

    fn advance_delegation(
        &mut self,
        endpoint_key: [u8; 33],
        sequence: u64,
        id: [u8; 32],
    ) -> Result<(), PoolStatsError> {
        match self
            .endpoints
            .binary_search_by_key(&endpoint_key, |endpoint| endpoint.endpoint_key)
        {
            Ok(position) => {
                let current = self
                    .endpoints
                    .get(position)
                    .ok_or(PoolStatsError::InvalidState)?
                    .delegation;
                match current {
                    Some(current) if sequence < current.sequence => {
                        Err(PoolStatsError::SequenceRollback)
                    }
                    Some(current) if sequence == current.sequence && id != current.id => {
                        self.mark_conflicted()?;
                        Err(PoolStatsError::ConflictingSequence)
                    }
                    Some(current) if sequence == current.sequence => Ok(()),
                    _ => {
                        self.bump_generation()?;
                        self.endpoints
                            .get_mut(position)
                            .ok_or(PoolStatsError::InvalidState)?
                            .delegation = Some(DelegationState { sequence, id });
                        Ok(())
                    }
                }
            }
            Err(position) => {
                if self.endpoints.len() >= MAX_ENDPOINT_HISTORIES {
                    self.mark_exhausted()?;
                    return Err(PoolStatsError::StateExhausted);
                }
                self.bump_generation()?;
                self.endpoints.insert(
                    position,
                    EndpointState {
                        endpoint_key,
                        delegation: Some(DelegationState { sequence, id }),
                    },
                );
                Ok(())
            }
        }
    }

    fn advance_snapshot(
        &mut self,
        operator_id: [u8; 32],
        sequence: u64,
        digest: [u8; 32],
    ) -> Result<(), PoolStatsError> {
        let operator_position = self
            .operators
            .binary_search_by_key(&operator_id, |operator| operator.operator_id);
        match operator_position {
            Ok(position) => {
                let current = self
                    .operators
                    .get(position)
                    .copied()
                    .ok_or(PoolStatsError::InvalidState)?;
                if sequence < current.sequence {
                    return Err(PoolStatsError::SequenceRollback);
                }
                if sequence == current.sequence && digest != current.digest {
                    self.mark_conflicted()?;
                    return Err(PoolStatsError::ConflictingSequence);
                }
                if sequence > current.sequence {
                    self.bump_generation()?;
                    self.operators
                        .get_mut(position)
                        .ok_or(PoolStatsError::InvalidState)?
                        .sequence = sequence;
                    self.operators
                        .get_mut(position)
                        .ok_or(PoolStatsError::InvalidState)?
                        .digest = digest;
                }
                Ok(())
            }
            Err(position) => {
                if self.operators.len() >= MAX_OPERATOR_HISTORIES {
                    self.mark_exhausted()?;
                    return Err(PoolStatsError::StateExhausted);
                }
                self.bump_generation()?;
                self.operators.insert(
                    position,
                    OperatorState {
                        operator_id,
                        sequence,
                        digest,
                    },
                );
                Ok(())
            }
        }
    }

    fn mark_conflicted(&mut self) -> Result<(), PoolStatsError> {
        if !matches!(self.status, StateStatus::Conflicted) {
            self.bump_generation()?;
            self.status = StateStatus::Conflicted;
        }
        Ok(())
    }

    fn mark_exhausted(&mut self) -> Result<(), PoolStatsError> {
        if !matches!(self.status, StateStatus::Exhausted) {
            self.bump_generation()?;
            self.status = StateStatus::Exhausted;
        }
        Ok(())
    }

    fn bump_generation(&mut self) -> Result<(), PoolStatsError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(PoolStatsError::StateGenerationExhausted)?;
        Ok(())
    }
}

impl Default for PoolStatsState {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned by commit-before-release admission.
#[derive(Debug)]
pub enum PoolStatsAdmissionError<E> {
    Verification(PoolStatsError),
    Persistence(E),
}

impl<E: fmt::Display> fmt::Display for PoolStatsAdmissionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => {
                write!(formatter, "pool-statistics verification failed: {error}")
            }
            Self::Persistence(error) => {
                write!(formatter, "pool-statistics state commit failed: {error}")
            }
        }
    }
}

impl<E> Error for PoolStatsAdmissionError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Verification(error) => Some(error),
            Self::Persistence(error) => Some(error),
        }
    }
}

/// Verify one bounded document and commit every state mutation before release.
///
/// `commit` receives the generation loaded by the caller and the complete new
/// canonical state. It must compare the old generation, atomically replace the
/// value, and add authenticity and rollback protection. It is called for
/// trusted-time advancement and terminal conflict state even when verification
/// ultimately fails. The caller-visible state advances only after the commit
/// succeeds, and a verified snapshot is never returned after commit failure.
pub fn verify_and_commit<E>(
    resource: &VerifiedHnsResource,
    request: PoolStatsRequest<'_>,
    document: &[u8],
    state: &mut PoolStatsState,
    commit: impl FnMut(u64, &[u8]) -> Result<(), E>,
) -> Result<VerifiedPoolStatsSnapshot, PoolStatsAdmissionError<E>> {
    let previous_generation = state.generation();
    let mut candidate = state.clone();
    let result = verify_resource_document(resource, request, document, &mut candidate);
    commit_admission_result(previous_generation, result, state, candidate, commit)
}

fn commit_admission_result<E>(
    previous_generation: u64,
    result: Result<VerifiedPoolStatsSnapshot, PoolStatsError>,
    state: &mut PoolStatsState,
    candidate: PoolStatsState,
    mut commit: impl FnMut(u64, &[u8]) -> Result<(), E>,
) -> Result<VerifiedPoolStatsSnapshot, PoolStatsAdmissionError<E>> {
    if candidate.generation() != previous_generation {
        let encoded = candidate
            .encode()
            .map_err(PoolStatsAdmissionError::Verification)?;
        commit(previous_generation, &encoded).map_err(PoolStatsAdmissionError::Persistence)?;
        *state = candidate;
    }
    result.map_err(PoolStatsAdmissionError::Verification)
}

/// Profile, proof, signature, replacement, or state failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PoolStatsError {
    #[error("the independently selected HNS name is invalid")]
    InvalidExpectedName,
    #[error("the independently selected Handshake network is invalid")]
    InvalidExpectedNetwork,
    #[error("a required external authority generation is zero")]
    InvalidContextGeneration,
    #[error("the verified HNS resource does not match the independently selected name")]
    ExpectedNameMismatch,
    #[error("the verified HNS resource does not match the independently selected network")]
    HnsNetworkMismatch,
    #[error("the verified HNS chain anchor is not current")]
    AnchorNotCurrent,
    #[error("the HNS resource contains a noncanonical hsa1 TXT record")]
    NoncanonicalAuthorityTxt,
    #[error("the MeshMine public document is invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("the MeshMine signed snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    #[error("the endpoint snapshot signature is invalid")]
    SnapshotCryptography,
    #[error("the persistent pool-statistics state belongs to another HNS name")]
    StateScopeMismatch,
    #[error("the persistent pool-statistics authority or generation moved backwards")]
    StateRollback,
    #[error("the trusted clock moved backwards")]
    TrustedClockRollback,
    #[error("a signed replacement sequence moved backwards")]
    SequenceRollback,
    #[error("different signed objects occupy the same replacement sequence")]
    ConflictingSequence,
    #[error("the authority scope is terminally blocked by signed equivocation")]
    StateConflicted,
    #[error("the bounded authority scope exhausted its history capacity")]
    StateExhausted,
    #[error("the state generation cannot advance without wrapping")]
    StateGenerationExhausted,
    #[error("the canonical persistent pool-statistics state is invalid")]
    InvalidState,
    #[error("HNSA verification failed: {0}")]
    Authority(#[from] AuthorityError),
}

#[derive(Clone, Copy)]
struct ResourceEvidence<'a> {
    name: &'a [u8],
    name_hash: [u8; 32],
    network_magic: u32,
    height: u32,
    validated_at: u64,
    valid_until: u64,
}

impl<'a> ResourceEvidence<'a> {
    fn from_verified(resource: &'a VerifiedHnsResource) -> Self {
        let anchor = resource.anchor();
        Self {
            name: resource.name(),
            name_hash: resource.name_hash().into_bytes(),
            network_magic: anchor.network().parameters().packet_magic,
            height: anchor.height().get(),
            validated_at: anchor.validated_at().get(),
            valid_until: anchor.valid_until().get(),
        }
    }
}

fn verify_resource_document(
    resource: &VerifiedHnsResource,
    request: PoolStatsRequest<'_>,
    document: &[u8],
    state: &mut PoolStatsState,
) -> Result<VerifiedPoolStatsSnapshot, PoolStatsError> {
    let evidence = ResourceEvidence::from_verified(resource);
    preflight_resource_evidence(evidence, request, state)?;
    let authority = authority_from_resource(resource)?;
    verify_evidence_document(evidence, authority, request, document, state)
}

fn preflight_resource_evidence(
    evidence: ResourceEvidence<'_>,
    request: PoolStatsRequest<'_>,
    state: &mut PoolStatsState,
) -> Result<(), PoolStatsError> {
    if evidence.name != request.expected_name {
        return Err(PoolStatsError::ExpectedNameMismatch);
    }
    if evidence.network_magic != request.expected_network_magic {
        return Err(PoolStatsError::HnsNetworkMismatch);
    }
    state.observe_context(evidence, request)?;
    if request.trusted_now < evidence.validated_at || request.trusted_now >= evidence.valid_until {
        return Err(PoolStatsError::AnchorNotCurrent);
    }
    Ok(())
}

fn verify_evidence_document(
    evidence: ResourceEvidence<'_>,
    authority: AuthorityRecord,
    request: PoolStatsRequest<'_>,
    document: &[u8],
    state: &mut PoolStatsState,
) -> Result<VerifiedPoolStatsSnapshot, PoolStatsError> {
    let authority_digest = authority_digest(&authority)?;
    state.bind_resource(evidence, request, authority_digest)?;
    state.require_active()?;

    let document = PoolStatsDocument::decode(document)?;
    let authorization_bytes = decode_lower_hex(
        &document.service_authorization,
        MAX_HNSA_OBJECT_BYTES,
        "invalid service authorization",
    )?;
    let delegation_bytes = decode_lower_hex(
        &document.endpoint_delegation,
        MAX_HNSA_OBJECT_BYTES,
        "invalid endpoint delegation",
    )?;
    let snapshot_bytes = decode_lower_hex(
        &document.snapshot,
        MAX_SNAPSHOT_BYTES,
        "invalid signed snapshot",
    )?;

    let authorization = ServiceAuthorizationV1::decode(&authorization_bytes)?;
    let identity = ServiceIdentity {
        network_magic: evidence.network_magic,
        name_hash: evidence.name_hash,
        service_name: SERVICE_NAME.to_owned(),
        profile_id: EXPERIMENTAL_PROFILE_ID,
    };
    authorization.verify(&authority, &identity, evidence.height, 0)?;
    let authorization_id = authorization.id()?;
    state.advance_authorization(authorization.serial, authorization_id)?;

    let delegation = EndpointDelegationV1::decode(&delegation_bytes)?;
    delegation.verify(
        &authorization,
        request.trusted_now,
        READ_STATS_CAPABILITY,
        [0; 32],
    )?;
    let delegation_id = delegation.id()?;
    state.advance_delegation(
        delegation.endpoint_key,
        delegation.endpoint_sequence,
        delegation_id,
    )?;
    if delegation.capabilities != READ_STATS_CAPABILITY {
        return Err(PoolStatsError::InvalidDocument(
            "endpoint lacks the exact read-statistics capability",
        ));
    }

    let snapshot = PoolStatsSnapshot::decode(&snapshot_bytes)?;
    snapshot.verify(
        evidence.network_magic,
        authorization_id,
        delegation_id,
        &delegation,
        request.trusted_now,
    )?;
    let snapshot_digest = blake2b_256(SNAPSHOT_DIGEST_DOMAIN, &[&snapshot_bytes])?;
    state.advance_snapshot(snapshot.operator_id, snapshot.sequence, snapshot_digest)?;

    Ok(snapshot.minimize(
        evidence.name,
        request,
        evidence.valid_until,
        state.generation(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolStatsDocument {
    schema: String,
    service_name: String,
    profile_id: u16,
    service_authorization: String,
    endpoint_delegation: String,
    snapshot: String,
}

impl PoolStatsDocument {
    fn decode(input: &[u8]) -> Result<Self, PoolStatsError> {
        if input.is_empty() || input.len() > MAX_DOCUMENT_BYTES {
            return Err(PoolStatsError::InvalidDocument("invalid document size"));
        }
        let document: Self = serde_json::from_slice(input)
            .map_err(|_| PoolStatsError::InvalidDocument("invalid strict JSON document"))?;
        if document.schema != "meshmine-pool-stats-v1"
            || document.service_name != SERVICE_NAME
            || document.profile_id != EXPERIMENTAL_PROFILE_ID
        {
            return Err(PoolStatsError::InvalidDocument(
                "unsupported schema, service, or profile",
            ));
        }
        Ok(document)
    }
}

struct PoolStatsSnapshot {
    network_magic: u32,
    profile_id: u16,
    authorization_id: [u8; 32],
    delegation_id: [u8; 32],
    endpoint_sequence: u64,
    sequence: u64,
    generated_at: u64,
    expires_at: u64,
    operator_id: [u8; 32],
    tip_height: u32,
    tip_hash: [u8; 32],
    connected_miners: u32,
    connected_mesh_peers: u32,
    accepted_shares: u64,
    rejected_shares: u64,
    pending_captures: u32,
    last_found_block: Option<VerifiedFoundBlock>,
    mode: PublicMode,
    production_eligible: bool,
    unsigned: Vec<u8>,
    endpoint_signature: Vec<u8>,
}

impl PoolStatsSnapshot {
    fn decode(input: &[u8]) -> Result<Self, PoolStatsError> {
        if input.is_empty() || input.len() > MAX_SNAPSHOT_BYTES {
            return Err(PoolStatsError::InvalidSnapshot("invalid snapshot size"));
        }
        let mut reader = SnapshotReader::new(input);
        if reader.u8()? != SNAPSHOT_VERSION {
            return Err(PoolStatsError::InvalidSnapshot(
                "unsupported snapshot version",
            ));
        }
        let network_magic = reader.u32()?;
        let profile_id = reader.u16()?;
        let authorization_id = reader.array()?;
        let delegation_id = reader.array()?;
        let endpoint_sequence = reader.u64()?;
        let sequence = reader.u64()?;
        let generated_at = reader.u64()?;
        let expires_at = reader.u64()?;
        let operator_id = reader.array()?;
        let tip_height = reader.u32()?;
        let tip_hash = reader.array()?;
        let connected_miners = reader.u32()?;
        let connected_mesh_peers = reader.u32()?;
        let accepted_shares = reader.u64()?;
        let rejected_shares = reader.u64()?;
        let pending_captures = reader.u32()?;
        let last_found_block = match reader.u8()? {
            0 => None,
            1 => Some(VerifiedFoundBlock {
                height: reader.u32()?,
                hash: reader.array()?,
            }),
            _ => {
                return Err(PoolStatsError::InvalidSnapshot(
                    "invalid last-found-block option",
                ));
            }
        };
        let mode = PublicMode::try_from(reader.u8()?)?;
        let production_eligible = match reader.u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(PoolStatsError::InvalidSnapshot(
                    "invalid production-eligible flag",
                ));
            }
        };
        let unsigned = input
            .get(..reader.offset())
            .ok_or(PoolStatsError::InvalidSnapshot("truncated snapshot"))?
            .to_vec();
        let signature_length = usize::from(reader.u8()?);
        if !(1..=MAX_SIGNATURE_BYTES).contains(&signature_length) {
            return Err(PoolStatsError::InvalidSnapshot(
                "invalid endpoint signature length",
            ));
        }
        let endpoint_signature = reader.bytes(signature_length)?.to_vec();
        reader.finish()?;
        if profile_id != EXPERIMENTAL_PROFILE_ID
            || authorization_id == [0; 32]
            || delegation_id == [0; 32]
            || endpoint_sequence == 0
            || sequence == 0
            || operator_id == [0; 32]
            || expires_at <= generated_at
            || expires_at.saturating_sub(generated_at) > MAX_SNAPSHOT_LIFETIME_SECONDS
            || last_found_block.is_some_and(|block| block.height > tip_height)
        {
            return Err(PoolStatsError::InvalidSnapshot(
                "invalid bounded snapshot fields",
            ));
        }
        parse_low_s_signature(&endpoint_signature)?;
        Ok(Self {
            network_magic,
            profile_id,
            authorization_id,
            delegation_id,
            endpoint_sequence,
            sequence,
            generated_at,
            expires_at,
            operator_id,
            tip_height,
            tip_hash,
            connected_miners,
            connected_mesh_peers,
            accepted_shares,
            rejected_shares,
            pending_captures,
            last_found_block,
            mode,
            production_eligible,
            unsigned,
            endpoint_signature,
        })
    }

    fn verify(
        &self,
        network_magic: u32,
        authorization_id: [u8; 32],
        delegation_id: [u8; 32],
        delegation: &EndpointDelegationV1,
        trusted_now: u64,
    ) -> Result<(), PoolStatsError> {
        if self.network_magic != network_magic
            || self.profile_id != EXPERIMENTAL_PROFILE_ID
            || self.authorization_id != authorization_id
            || self.delegation_id != delegation_id
            || self.endpoint_sequence != delegation.endpoint_sequence
            || self.expires_at > delegation.expires_at
            || trusted_now < self.generated_at
            || trusted_now >= self.expires_at
        {
            return Err(PoolStatsError::InvalidSnapshot(
                "snapshot trust context mismatch",
            ));
        }
        let signature = parse_low_s_signature(&self.endpoint_signature)?;
        let digest = blake2b_256(
            SNAPSHOT_SIGNATURE_DOMAIN,
            &[self
                .unsigned
                .get(1..)
                .ok_or(PoolStatsError::InvalidSnapshot("missing snapshot body"))?],
        )?;
        VerifyingKey::from_sec1_bytes(&delegation.endpoint_key)
            .map_err(|_| PoolStatsError::SnapshotCryptography)?
            .verify_prehash(&digest, &signature)
            .map_err(|_| PoolStatsError::SnapshotCryptography)
    }

    fn minimize(
        self,
        hns_name: &[u8],
        request: PoolStatsRequest<'_>,
        anchor_valid_until: u64,
        admission_generation: u64,
    ) -> VerifiedPoolStatsSnapshot {
        VerifiedPoolStatsSnapshot {
            hns_name: hns_name.to_vec(),
            network_magic: self.network_magic,
            resource_generation: request.resource_generation,
            profile_policy_generation: request.profile_policy_generation,
            admission_generation,
            verified_at: request.trusted_now,
            operator_id: self.operator_id,
            endpoint_sequence: self.endpoint_sequence,
            sequence: self.sequence,
            generated_at: self.generated_at,
            snapshot_expires_at: self.expires_at,
            valid_until: self.expires_at.min(anchor_valid_until),
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            connected_miners: self.connected_miners,
            connected_mesh_peers: self.connected_mesh_peers,
            accepted_shares: self.accepted_shares,
            rejected_shares: self.rejected_shares,
            pending_captures: self.pending_captures,
            last_found_block: self.last_found_block,
            mode: self.mode,
            production_eligible: self.production_eligible,
        }
    }
}

fn authority_from_resource(
    resource: &VerifiedHnsResource,
) -> Result<AuthorityRecord, PoolStatsError> {
    let mut candidates = Vec::new();
    for record in resource.resource().records() {
        let HnsResourceRecord::Txt(strings) = record else {
            continue;
        };
        if !strings.iter().any(|value| is_hsa1_candidate(value)) {
            continue;
        }
        if strings.len() != 1 {
            return Err(PoolStatsError::NoncanonicalAuthorityTxt);
        }
        let value = strings
            .first()
            .ok_or(PoolStatsError::NoncanonicalAuthorityTxt)?;
        candidates.push(
            std::str::from_utf8(value).map_err(|_| PoolStatsError::NoncanonicalAuthorityTxt)?,
        );
    }
    select_authority_record(candidates).map_err(PoolStatsError::Authority)
}

fn is_hsa1_candidate(value: &[u8]) -> bool {
    value == b"hsa1" || value.starts_with(b"hsa1 ")
}

fn authority_digest(authority: &AuthorityRecord) -> Result<[u8; 32], PoolStatsError> {
    let encoded = authority.encode()?;
    blake2b_256(AUTHORITY_DIGEST_DOMAIN, &[encoded.as_bytes()])
}

fn decode_lower_hex(
    input: &str,
    maximum_bytes: usize,
    message: &'static str,
) -> Result<Vec<u8>, PoolStatsError> {
    if input.is_empty()
        || input.len() > maximum_bytes.saturating_mul(2)
        || !input.len().is_multiple_of(2)
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PoolStatsError::InvalidDocument(message));
    }
    hex::decode(input).map_err(|_| PoolStatsError::InvalidDocument(message))
}

fn parse_low_s_signature(input: &[u8]) -> Result<Signature, PoolStatsError> {
    if input.is_empty() || input.len() > MAX_SIGNATURE_BYTES {
        return Err(PoolStatsError::SnapshotCryptography);
    }
    let signature = Signature::from_der(input).map_err(|_| PoolStatsError::SnapshotCryptography)?;
    if signature.normalize_s().is_some() {
        return Err(PoolStatsError::SnapshotCryptography);
    }
    Ok(signature)
}

fn blake2b_256(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], PoolStatsError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| PoolStatsError::SnapshotCryptography)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| PoolStatsError::SnapshotCryptography)?;
    Ok(output)
}

fn is_canonical_hns_label(name: &[u8]) -> bool {
    (1..=63).contains(&name.len())
        && name.first() != Some(&b'-')
        && name.last() != Some(&b'-')
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

struct SnapshotReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], PoolStatsError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PoolStatsError::InvalidSnapshot("snapshot offset overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(PoolStatsError::InvalidSnapshot("truncated snapshot"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PoolStatsError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PoolStatsError::InvalidSnapshot("truncated snapshot"))
    }

    fn u8(&mut self) -> Result<u8, PoolStatsError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, PoolStatsError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, PoolStatsError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, PoolStatsError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), PoolStatsError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(PoolStatsError::InvalidSnapshot("trailing snapshot bytes"))
        }
    }
}

struct StateReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> StateReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], PoolStatsError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PoolStatsError::InvalidState)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(PoolStatsError::InvalidState)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PoolStatsError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PoolStatsError::InvalidState)
    }

    fn u8(&mut self) -> Result<u8, PoolStatsError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, PoolStatsError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, PoolStatsError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), PoolStatsError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(PoolStatsError::InvalidState)
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use serde_json::json;

    use super::*;

    const NAME: &[u8] = b"alpha";
    const MAGIC: u32 = 0xae38_95cf;
    const NOW: u64 = 1_700_000_100;

    #[derive(Clone)]
    struct Fixture {
        authority: AuthorityRecord,
        authorization: ServiceAuthorizationV1,
        delegation: EndpointDelegationV1,
        root_private: [u8; 32],
        service_private: [u8; 32],
        endpoint_private: [u8; 32],
    }

    fn fixture() -> Fixture {
        let root_private = [1; 32];
        let service_private = [2; 32];
        let endpoint_private = [3; 32];
        let authority = AuthorityRecord {
            root_key: hns_service_authority::public_key(&root_private).expect("root key"),
            epoch: 4,
        };
        let mut authorization = ServiceAuthorizationV1 {
            network_magic: MAGIC,
            name_hash: [4; 32],
            authority_epoch: authority.epoch,
            service_name: SERVICE_NAME.to_owned(),
            profile_id: EXPERIMENTAL_PROFILE_ID,
            service_key: hns_service_authority::public_key(&service_private).expect("service key"),
            flags: 0,
            serial: 1,
            valid_from_height: 100,
            valid_until_height: 200,
            max_endpoint_lifetime: 3_600,
            root_signature: Vec::new(),
        };
        authorization.sign(&root_private).expect("authorization");
        let mut delegation = EndpointDelegationV1 {
            network_magic: MAGIC,
            authorization_id: authorization.id().expect("authorization id"),
            endpoint_key: hns_service_authority::public_key(&endpoint_private)
                .expect("endpoint key"),
            endpoint_sequence: 1,
            issued_at: NOW - 10,
            expires_at: NOW + 900,
            capabilities: READ_STATS_CAPABILITY,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(&service_private).expect("delegation");
        Fixture {
            authority,
            authorization,
            delegation,
            root_private,
            service_private,
            endpoint_private,
        }
    }

    fn derived_fixture(
        base: &Fixture,
        authorization_serial: u64,
        service_private: [u8; 32],
        endpoint_private: [u8; 32],
        endpoint_sequence: u64,
        capabilities: u32,
    ) -> Fixture {
        let mut authorization = base.authorization.clone();
        authorization.service_key =
            hns_service_authority::public_key(&service_private).expect("service key");
        authorization.serial = authorization_serial;
        authorization.root_signature.clear();
        authorization
            .sign(&base.root_private)
            .expect("authorization");

        let mut delegation = base.delegation.clone();
        delegation.authorization_id = authorization.id().expect("authorization id");
        delegation.endpoint_key =
            hns_service_authority::public_key(&endpoint_private).expect("endpoint key");
        delegation.endpoint_sequence = endpoint_sequence;
        delegation.capabilities = capabilities;
        delegation.service_signature.clear();
        delegation.sign(&service_private).expect("delegation");

        Fixture {
            authority: base.authority.clone(),
            authorization,
            delegation,
            root_private: base.root_private,
            service_private,
            endpoint_private,
        }
    }

    fn evidence() -> ResourceEvidence<'static> {
        ResourceEvidence {
            name: NAME,
            name_hash: [4; 32],
            network_magic: MAGIC,
            height: 150,
            validated_at: NOW - 100,
            valid_until: NOW + 1_000,
        }
    }

    fn request(now: u64) -> PoolStatsRequest<'static> {
        PoolStatsRequest::new(NAME, MAGIC, 1, 1, now).expect("request")
    }

    #[derive(Clone)]
    struct SnapshotFields {
        sequence: u64,
        connected_miners: u32,
        operator_id: [u8; 32],
    }

    fn signed_snapshot(fixture: &Fixture, fields: SnapshotFields) -> Vec<u8> {
        let mut unsigned = Vec::new();
        unsigned.push(SNAPSHOT_VERSION);
        unsigned.extend_from_slice(&MAGIC.to_le_bytes());
        unsigned.extend_from_slice(&EXPERIMENTAL_PROFILE_ID.to_le_bytes());
        unsigned.extend_from_slice(&fixture.authorization.id().expect("authorization id"));
        unsigned.extend_from_slice(&fixture.delegation.id().expect("delegation id"));
        unsigned.extend_from_slice(&fixture.delegation.endpoint_sequence.to_le_bytes());
        unsigned.extend_from_slice(&fields.sequence.to_le_bytes());
        unsigned.extend_from_slice(&(NOW - 1).to_le_bytes());
        unsigned.extend_from_slice(&(NOW + 60).to_le_bytes());
        unsigned.extend_from_slice(&fields.operator_id);
        unsigned.extend_from_slice(&150_u32.to_le_bytes());
        unsigned.extend_from_slice(&[5; 32]);
        unsigned.extend_from_slice(&fields.connected_miners.to_le_bytes());
        unsigned.extend_from_slice(&3_u32.to_le_bytes());
        unsigned.extend_from_slice(&5_u64.to_le_bytes());
        unsigned.extend_from_slice(&1_u64.to_le_bytes());
        unsigned.extend_from_slice(&1_u32.to_le_bytes());
        unsigned.push(1);
        unsigned.extend_from_slice(&149_u32.to_le_bytes());
        unsigned.extend_from_slice(&[6; 32]);
        unsigned.push(1);
        unsigned.push(0);
        let digest =
            blake2b_256(SNAPSHOT_SIGNATURE_DOMAIN, &[&unsigned[1..]]).expect("snapshot digest");
        let key = SigningKey::from_bytes((&fixture.endpoint_private).into()).expect("endpoint key");
        let signature: Signature = key.sign_prehash(&digest).expect("snapshot signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature = signature.to_der();
        let mut encoded = unsigned;
        encoded.push(u8::try_from(signature.as_bytes().len()).expect("signature length"));
        encoded.extend_from_slice(signature.as_bytes());
        encoded
    }

    fn document(fixture: &Fixture, snapshot: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "meshmine-pool-stats-v1",
            "service_name": SERVICE_NAME,
            "profile_id": EXPERIMENTAL_PROFILE_ID,
            "service_authorization": hex::encode(fixture.authorization.encode().expect("authorization")),
            "endpoint_delegation": hex::encode(fixture.delegation.encode().expect("delegation")),
            "snapshot": hex::encode(snapshot),
        }))
        .expect("document")
    }

    fn admit(
        fixture: &Fixture,
        snapshot: &[u8],
        state: &mut PoolStatsState,
        now: u64,
        commits: &mut Vec<(u64, Vec<u8>)>,
    ) -> Result<VerifiedPoolStatsSnapshot, PoolStatsError> {
        let previous = state.generation();
        preflight_resource_evidence(evidence(), request(now), state)?;
        let result = verify_evidence_document(
            evidence(),
            fixture.authority.clone(),
            request(now),
            &document(fixture, snapshot),
            state,
        );
        if state.generation() != previous {
            commits.push((previous, state.encode().expect("state")));
        }
        result
    }

    #[test]
    fn complete_chain_returns_only_minimized_verified_statistics() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        let verified =
            admit(&fixture, &snapshot, &mut state, NOW, &mut commits).expect("verified snapshot");

        assert_eq!(verified.hns_name(), NAME);
        assert_eq!(verified.network_magic(), MAGIC);
        assert_eq!(verified.resource_generation(), 1);
        assert_eq!(verified.profile_policy_generation(), 1);
        assert_eq!(verified.admission_generation(), state.generation());
        assert_eq!(verified.verified_at(), NOW);
        assert_eq!(verified.sequence(), 1);
        assert_eq!(verified.snapshot_expires_at(), NOW + 60);
        assert_eq!(verified.valid_until(), NOW + 60);
        assert_eq!(verified.connected_miners(), 2);
        assert_eq!(verified.mode(), PublicMode::Mining);
        assert!(!verified.production_eligible());
        assert!(state.is_active());
        assert_eq!(commits.len(), 1);
        assert_eq!(
            PoolStatsState::decode(&commits[0].1).expect("decode"),
            state
        );
    }

    #[test]
    fn minimized_validity_never_outlives_proof_anchor() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut short_anchor = evidence();
        short_anchor.valid_until = NOW + 30;
        let mut state = PoolStatsState::new();
        preflight_resource_evidence(short_anchor, request(NOW), &mut state).expect("preflight");
        let verified = verify_evidence_document(
            short_anchor,
            fixture.authority.clone(),
            request(NOW),
            &document(&fixture, &snapshot),
            &mut state,
        )
        .expect("verified");

        assert_eq!(verified.snapshot_expires_at(), NOW + 60);
        assert_eq!(verified.valid_until(), NOW + 30);
        assert_eq!(verified.admission_generation(), state.generation());
    }

    #[test]
    fn operator_sequence_cannot_reset_across_endpoint_rotation() {
        let initial = fixture();
        let rotated = derived_fixture(
            &initial,
            initial.authorization.serial,
            initial.service_private,
            [4; 32],
            1,
            READ_STATS_CAPABILITY,
        );
        let latest = signed_snapshot(
            &initial,
            SnapshotFields {
                sequence: 2,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let replay = signed_snapshot(
            &rotated,
            SnapshotFields {
                sequence: 1,
                connected_miners: 1,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&initial, &latest, &mut state, NOW, &mut commits).expect("latest");
        assert!(matches!(
            admit(&rotated, &replay, &mut state, NOW + 1, &mut commits),
            Err(PoolStatsError::SequenceRollback)
        ));
        assert_eq!(state.endpoints.len(), 2);
        assert_eq!(state.operators.len(), 1);
        assert_eq!(state.operators[0].sequence, 2);
        assert_eq!(
            PoolStatsState::decode(&commits.last().expect("commit").1).expect("decode"),
            state
        );
    }

    #[test]
    fn higher_authorization_resets_delegation_but_not_operator_sequence() {
        let base = fixture();
        let initial = derived_fixture(
            &base,
            1,
            base.service_private,
            base.endpoint_private,
            2,
            READ_STATS_CAPABILITY,
        );
        let rotated = derived_fixture(
            &initial,
            2,
            [5; 32],
            initial.endpoint_private,
            1,
            READ_STATS_CAPABILITY,
        );
        let first = signed_snapshot(
            &initial,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let second = signed_snapshot(
            &rotated,
            SnapshotFields {
                sequence: 2,
                connected_miners: 3,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&initial, &first, &mut state, NOW, &mut commits).expect("first authorization");
        admit(&rotated, &second, &mut state, NOW + 1, &mut commits).expect("rotated authorization");

        assert_eq!(state.authorization.expect("authorization").serial, 2);
        assert_eq!(state.endpoints.len(), 1);
        assert_eq!(
            state.endpoints[0].delegation.expect("delegation").sequence,
            1
        );
        assert_eq!(state.operators[0].sequence, 2);
        assert_eq!(
            PoolStatsState::decode(&commits.last().expect("commit").1).expect("decode"),
            state
        );
    }

    #[test]
    fn snapshot_rollback_and_equal_sequence_conflict_fail_closed_durably() {
        let fixture = fixture();
        let latest = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 2,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let old = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 1,
                operator_id: [7; 32],
            },
        );
        let conflict = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 2,
                connected_miners: 9,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&fixture, &latest, &mut state, NOW, &mut commits).expect("latest");
        assert!(matches!(
            admit(&fixture, &old, &mut state, NOW + 1, &mut commits),
            Err(PoolStatsError::SequenceRollback)
        ));
        assert!(matches!(
            admit(&fixture, &conflict, &mut state, NOW + 2, &mut commits),
            Err(PoolStatsError::ConflictingSequence)
        ));
        assert!(state.is_conflicted());
        assert!(matches!(
            admit(&fixture, &latest, &mut state, NOW + 3, &mut commits),
            Err(PoolStatsError::StateConflicted)
        ));
        assert_eq!(
            PoolStatsState::decode(&commits.last().expect("commit").1).expect("decode"),
            state
        );
    }

    #[test]
    fn authorization_serial_rollback_and_conflict_are_sticky() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&fixture, &snapshot, &mut state, NOW, &mut commits).expect("verified");

        state
            .advance_authorization(2, [8; 32])
            .expect("new authorization");
        assert!(matches!(
            state.advance_authorization(1, fixture.authorization.id().expect("authorization id")),
            Err(PoolStatsError::SequenceRollback)
        ));
        assert!(state.is_active());
        assert!(matches!(
            state.advance_authorization(2, [9; 32]),
            Err(PoolStatsError::ConflictingSequence)
        ));
        assert!(state.is_conflicted());
        assert!(
            PoolStatsState::decode(&state.encode().expect("state"))
                .expect("decode")
                .is_conflicted()
        );
    }

    #[test]
    fn endpoint_sequence_rollback_and_conflict_are_sticky() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&fixture, &snapshot, &mut state, NOW, &mut commits).expect("verified");

        let endpoint_key = fixture.delegation.endpoint_key;
        state
            .advance_delegation(endpoint_key, 2, [8; 32])
            .expect("new delegation");
        assert!(matches!(
            state.advance_delegation(
                endpoint_key,
                1,
                fixture.delegation.id().expect("delegation id")
            ),
            Err(PoolStatsError::SequenceRollback)
        ));
        assert!(state.is_active());
        assert!(matches!(
            state.advance_delegation(endpoint_key, 2, [9; 32]),
            Err(PoolStatsError::ConflictingSequence)
        ));
        assert!(state.is_conflicted());
        assert!(
            PoolStatsState::decode(&state.encode().expect("state"))
                .expect("decode")
                .is_conflicted()
        );
    }

    #[test]
    fn newer_capability_revocation_is_durable_and_blocks_replay() {
        let initial = fixture();
        let revoked = derived_fixture(
            &initial,
            initial.authorization.serial,
            initial.service_private,
            initial.endpoint_private,
            2,
            0,
        );
        let first = signed_snapshot(
            &initial,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let revoked_snapshot = signed_snapshot(
            &revoked,
            SnapshotFields {
                sequence: 2,
                connected_miners: 0,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&initial, &first, &mut state, NOW, &mut commits).expect("initial");
        assert!(matches!(
            admit(
                &revoked,
                &revoked_snapshot,
                &mut state,
                NOW + 1,
                &mut commits
            ),
            Err(PoolStatsError::InvalidDocument(
                "endpoint lacks the exact read-statistics capability"
            ))
        ));
        assert_eq!(
            state.endpoints[0].delegation.expect("revocation").sequence,
            2
        );
        assert!(matches!(
            admit(&initial, &first, &mut state, NOW + 2, &mut commits),
            Err(PoolStatsError::SequenceRollback)
        ));
        assert_eq!(
            PoolStatsState::decode(&commits.last().expect("commit").1).expect("decode"),
            state
        );
    }

    #[test]
    fn endpoint_signature_failure_still_advances_trusted_time() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&fixture, &snapshot, &mut state, NOW, &mut commits).expect("first");

        let mut tampered = snapshot;
        let miners_offset = 1 + 4 + 2 + 32 + 32 + 8 + 8 + 8 + 8 + 32 + 4 + 32;
        tampered[miners_offset] ^= 1;
        assert!(matches!(
            admit(&fixture, &tampered, &mut state, NOW + 1, &mut commits),
            Err(PoolStatsError::SnapshotCryptography)
        ));
        assert_eq!(state.trusted_time_high_water(), NOW + 1);
        assert_eq!(
            PoolStatsState::decode(&commits.last().expect("commit").1)
                .expect("decode")
                .trusted_time_high_water(),
            NOW + 1
        );
    }

    #[test]
    fn failed_first_preflight_commits_context_high_waters() {
        let mut expired = evidence();
        expired.valid_until = NOW + 10;
        let high_request = PoolStatsRequest::new(NAME, MAGIC, 2, 3, NOW + 20).expect("request");
        let mut state = PoolStatsState::new();
        let previous_generation = state.generation();
        let mut candidate = state.clone();
        let result: Result<VerifiedPoolStatsSnapshot, PoolStatsError> =
            match preflight_resource_evidence(expired, high_request, &mut candidate) {
                Ok(()) => panic!("expired anchor accepted"),
                Err(error) => Err(error),
            };
        let mut committed = None;
        let admission = commit_admission_result(
            previous_generation,
            result,
            &mut state,
            candidate,
            |_, encoded| {
                committed = Some(encoded.to_vec());
                Ok::<(), std::convert::Infallible>(())
            },
        );
        assert!(matches!(
            admission,
            Err(PoolStatsAdmissionError::Verification(
                PoolStatsError::AnchorNotCurrent
            ))
        ));
        assert_eq!(state.resource_generation(), 2);
        assert_eq!(state.profile_policy_generation(), 3);
        assert_eq!(state.trusted_time_high_water(), NOW + 20);
        assert_eq!(
            PoolStatsState::decode(&committed.expect("commit")).expect("decode"),
            state
        );

        let lower_generation = PoolStatsRequest::new(NAME, MAGIC, 1, 2, NOW + 21).expect("request");
        assert!(matches!(
            preflight_resource_evidence(evidence(), lower_generation, &mut state),
            Err(PoolStatsError::StateRollback)
        ));
        assert_eq!(state.trusted_time_high_water(), NOW + 21);

        let higher_generation_lower_time =
            PoolStatsRequest::new(NAME, MAGIC, 4, 5, NOW + 20).expect("request");
        assert!(matches!(
            preflight_resource_evidence(evidence(), higher_generation_lower_time, &mut state),
            Err(PoolStatsError::TrustedClockRollback)
        ));
        assert_eq!(state.resource_generation(), 4);
        assert_eq!(state.profile_policy_generation(), 5);
        let lower_time = PoolStatsRequest::new(NAME, MAGIC, 4, 5, NOW).expect("request");
        assert!(matches!(
            preflight_resource_evidence(evidence(), lower_time, &mut state),
            Err(PoolStatsError::TrustedClockRollback)
        ));
    }

    #[test]
    fn canonical_state_rejects_corruption_and_trailing_bytes() {
        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let mut commits = Vec::new();
        admit(&fixture, &snapshot, &mut state, NOW, &mut commits).expect("verified");
        let encoded = state.encode().expect("state");
        assert_eq!(PoolStatsState::decode(&encoded).expect("round trip"), state);

        let mut corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assert!(PoolStatsState::decode(&corrupt).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PoolStatsState::decode(&trailing).is_err());
    }

    #[test]
    fn invalid_independent_identity_and_commit_failure_never_release_values() {
        assert!(PoolStatsRequest::new(b"Alpha", MAGIC, 1, 1, NOW).is_err());
        assert!(PoolStatsRequest::new(NAME, 0, 1, 1, NOW).is_err());
        assert!(PoolStatsRequest::new(NAME, MAGIC, 0, 1, NOW).is_err());
        let wrong_network = PoolStatsRequest::new(NAME, MAGIC ^ 1, 1, 1, NOW).expect("request");
        let mut unscoped = PoolStatsState::new();
        assert!(matches!(
            preflight_resource_evidence(evidence(), wrong_network, &mut unscoped),
            Err(PoolStatsError::HnsNetworkMismatch)
        ));
        assert_eq!(unscoped.generation(), 0);

        let fixture = fixture();
        let snapshot = signed_snapshot(
            &fixture,
            SnapshotFields {
                sequence: 1,
                connected_miners: 2,
                operator_id: [7; 32],
            },
        );
        let mut state = PoolStatsState::new();
        let original_state = state.clone();
        let previous_generation = state.generation();
        let mut candidate = state.clone();
        let result = verify_evidence_document(
            evidence(),
            fixture.authority.clone(),
            request(NOW),
            &document(&fixture, &snapshot),
            &mut candidate,
        );
        assert!(result.is_ok());
        let mut commit_attempts = 0;
        let persistence_result = commit_admission_result(
            previous_generation,
            result,
            &mut state,
            candidate,
            |_, _| {
                commit_attempts += 1;
                Err("store unavailable")
            },
        );
        assert!(matches!(
            persistence_result,
            Err(PoolStatsAdmissionError::Persistence("store unavailable"))
        ));
        assert_eq!(commit_attempts, 1);
        assert_eq!(state, original_state);

        let previous_generation = state.generation();
        let mut retry_candidate = state.clone();
        let retry_result = verify_evidence_document(
            evidence(),
            fixture.authority.clone(),
            request(NOW),
            &document(&fixture, &snapshot),
            &mut retry_candidate,
        );
        let verified = commit_admission_result(
            previous_generation,
            retry_result,
            &mut state,
            retry_candidate,
            |_, _| {
                commit_attempts += 1;
                Ok::<(), &str>(())
            },
        )
        .expect("retry committed");
        assert_eq!(verified.sequence(), 1);
        assert_eq!(commit_attempts, 2);
        assert_ne!(state, original_state);
    }

    #[test]
    fn authority_txt_candidate_rules_match_the_canonical_selector() {
        assert!(is_hsa1_candidate(b"hsa1"));
        assert!(is_hsa1_candidate(b"hsa1 k=x e=1"));
        assert!(!is_hsa1_candidate(b"hsa10 k=x e=1"));
        assert!(!is_hsa1_candidate(b"unrelated"));
    }
}
