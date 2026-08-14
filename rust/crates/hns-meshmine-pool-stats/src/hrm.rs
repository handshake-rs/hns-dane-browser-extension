use std::error::Error;
use std::fmt;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;

use crate::{EXPERIMENTAL_PROFILE_ID, READ_STATS_CAPABILITY, SERVICE_NAME};

const DOCUMENT_SCHEMA: &str = "meshmine-pool-stats-hrm-v1";
const ENDPOINT_VERSION: u8 = 1;
const SNAPSHOT_VERSION: u8 = 2;
const MAX_SIGNATURE_BYTES: usize = 80;
const MAX_ENDPOINT_BYTES: usize = 320;
const MAX_SNAPSHOT_BYTES: usize = 640;
const MAX_DOCUMENT_BYTES: usize = 16 * 1_024;
const MAX_ENDPOINT_HISTORIES: usize = 16;
const MAX_OPERATOR_HISTORIES: usize = 128;
const MAX_STATE_BYTES: usize = 24_000;
const MIN_ENDPOINT_LIFETIME_LIMIT: u32 = 300;
const MAX_ENDPOINT_LIFETIME_LIMIT: u32 = 604_800;
const MAX_SNAPSHOT_LIFETIME_SECONDS: u64 = 120;
const NAMED_SERVICE_ID_DOMAIN: &[u8] = b"HNS-HRM-NAMED-SERVICE-ID-V1\0";
const ENDPOINT_SIGNATURE_DOMAIN: &[u8] = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\0";
const ENDPOINT_ID_DOMAIN: &[u8] = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-ID-V1\0";
const SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"HNS-HRM-MESHMINE-POOL-STATS-V1\0";
const SNAPSHOT_STATE_DOMAIN: &[u8] = b"HNS-HRM-MESHMINE-SNAPSHOT-STATE-V1\0";
const STATE_CHECKSUM_DOMAIN: &[u8] = b"HNS-HRM-MESHMINE-STATE-CHECKSUM-V1\0";
const STATE_MAGIC: &[u8; 4] = b"MHR2";
const STATE_VERSION: u8 = 2;
const STATE_CHECKSUM_BYTES: usize = 32;

/// Independently selected identity, route, network, and trusted operation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HrmPoolStatsRequest<'a> {
    expected_name: &'a [u8],
    expected_name_hash: [u8; 32],
    expected_network_magic: u32,
    expected_route_id: [u8; 32],
    trusted_now: u64,
}

impl<'a> HrmPoolStatsRequest<'a> {
    /// Construct a request without consulting the endpoint or its document.
    pub fn new(
        expected_name: &'a [u8],
        expected_network_magic: u32,
        expected_route_id: [u8; 32],
        trusted_now: u64,
    ) -> Result<Self, HrmPoolStatsError> {
        if !is_canonical_hns_label(expected_name) {
            return Err(HrmPoolStatsError::InvalidExpectedName);
        }
        let expected_name_hash = Sha3_256::digest(expected_name).into();
        if expected_route_id == [0; 32] {
            return Err(HrmPoolStatsError::InvalidExpectedRoute);
        }
        Ok(Self {
            expected_name,
            expected_name_hash,
            expected_network_magic,
            expected_route_id,
            trusted_now,
        })
    }

    #[must_use]
    pub const fn expected_name(self) -> &'a [u8] {
        self.expected_name
    }

    #[must_use]
    pub const fn expected_name_hash(self) -> [u8; 32] {
        self.expected_name_hash
    }

    #[must_use]
    pub const fn expected_network_magic(self) -> u32 {
        self.expected_network_magic
    }

    #[must_use]
    pub const fn expected_route_id(self) -> [u8; 32] {
        self.expected_route_id
    }

    #[must_use]
    pub const fn trusted_now(self) -> u64 {
        self.trusted_now
    }
}

/// Exact current named-service authority held by the trusted HRM broker.
///
/// Every field is private and this type deliberately has no public constructor.
/// A future adapter must create it only from a durably acknowledged, complete
/// current HRM/HNSA aggregate while holding the subject-wide broker operation
/// lease through dependent use. Ordinary browser, endpoint, JSON, and DNS
/// inputs cannot manufacture this capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentHrmNamedService {
    network_magic: u32,
    name_hash: [u8; 32],
    service_name: String,
    application_profile_id: u16,
    hrm_sequence: u64,
    hrm_envelope_hash: [u8; 32],
    authority_revision: u64,
    operation_lease_generation: u64,
    trusted_operation_time: u64,
    service_resource_id: [u8; 32],
    service_delegation_id: [u8; 32],
    service_generation: u64,
    service_controller_key: [u8; 33],
    resource_not_before: u64,
    resource_expires_at: u64,
    delegation_not_before: u64,
    delegation_expires_at: u64,
    max_endpoint_lifetime: u32,
    allowed_endpoint_capabilities: u32,
    endpoint_constraints_hash: [u8; 32],
}

impl CurrentHrmNamedService {
    #[must_use]
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    #[must_use]
    pub const fn name_hash(&self) -> [u8; 32] {
        self.name_hash
    }

    #[must_use]
    pub const fn hrm_sequence(&self) -> u64 {
        self.hrm_sequence
    }

    #[must_use]
    pub const fn hrm_envelope_hash(&self) -> [u8; 32] {
        self.hrm_envelope_hash
    }

    #[must_use]
    pub const fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    #[must_use]
    pub const fn operation_lease_generation(&self) -> u64 {
        self.operation_lease_generation
    }

    #[must_use]
    pub const fn service_resource_id(&self) -> [u8; 32] {
        self.service_resource_id
    }

    #[must_use]
    pub const fn service_delegation_id(&self) -> [u8; 32] {
        self.service_delegation_id
    }

    #[must_use]
    pub const fn service_generation(&self) -> u64 {
        self.service_generation
    }

    fn validate(&self) -> Result<(), HrmPoolStatsError> {
        if self.service_name != SERVICE_NAME
            || self.application_profile_id != EXPERIMENTAL_PROFILE_ID
            || self.authority_revision == 0
            || self.operation_lease_generation == 0
            || self.service_resource_id
                != named_service_resource_id(
                    self.network_magic,
                    self.name_hash,
                    self.service_name.as_bytes(),
                    self.application_profile_id,
                )
            || self.service_generation == 0
            || self.resource_not_before >= self.resource_expires_at
            || self.delegation_not_before < self.resource_not_before
            || self.delegation_expires_at > self.resource_expires_at
            || self.delegation_not_before >= self.delegation_expires_at
            || self.trusted_operation_time < self.resource_not_before
            || self.trusted_operation_time >= self.resource_expires_at
            || self.trusted_operation_time < self.delegation_not_before
            || self.trusted_operation_time >= self.delegation_expires_at
            || !(MIN_ENDPOINT_LIFETIME_LIMIT..=MAX_ENDPOINT_LIFETIME_LIMIT)
                .contains(&self.max_endpoint_lifetime)
            || self.allowed_endpoint_capabilities & READ_STATS_CAPABILITY == 0
        {
            return Err(HrmPoolStatsError::InvalidCurrentAuthority);
        }
        VerifyingKey::from_sec1_bytes(&self.service_controller_key)
            .map_err(|_| HrmPoolStatsError::InvalidCurrentAuthority)?;
        Ok(())
    }

    fn matches_request(&self, request: HrmPoolStatsRequest<'_>) -> bool {
        self.network_magic == request.expected_network_magic
            && self.name_hash == request.expected_name_hash
            && self.trusted_operation_time == request.trusted_now
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
    type Error = HrmPoolStatsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bootstrapping),
            1 => Ok(Self::Mining),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Fallback),
            4 => Ok(Self::Draining),
            5 => Ok(Self::Stopped),
            _ => Err(HrmPoolStatsError::InvalidSnapshot("unknown operator mode")),
        }
    }
}

/// A last-found block included in a verified operator snapshot.
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

/// Minimized pool statistics bound to one exact HRM/HNSA authority and route.
///
/// Counts and `production_eligible` remain authenticated operator claims, not
/// Handshake consensus, wallet, value-transfer, or settlement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHrmPoolStatsSnapshot {
    hns_name: Vec<u8>,
    network_magic: u32,
    route_id: [u8; 32],
    service_resource_id: [u8; 32],
    service_delegation_id: [u8; 32],
    service_generation: u64,
    endpoint_delegation_id: [u8; 32],
    endpoint_sequence: u64,
    authority_revision: u64,
    operation_lease_generation: u64,
    admission_generation: u64,
    verified_at: u64,
    valid_until: u64,
    operator_id: [u8; 32],
    sequence: u64,
    generated_at: u64,
    snapshot_expires_at: u64,
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

impl VerifiedHrmPoolStatsSnapshot {
    #[must_use]
    pub fn hns_name(&self) -> &[u8] {
        &self.hns_name
    }

    #[must_use]
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    #[must_use]
    pub const fn route_id(&self) -> [u8; 32] {
        self.route_id
    }

    #[must_use]
    pub const fn service_resource_id(&self) -> [u8; 32] {
        self.service_resource_id
    }

    #[must_use]
    pub const fn service_delegation_id(&self) -> [u8; 32] {
        self.service_delegation_id
    }

    #[must_use]
    pub const fn service_generation(&self) -> u64 {
        self.service_generation
    }

    #[must_use]
    pub const fn endpoint_delegation_id(&self) -> [u8; 32] {
        self.endpoint_delegation_id
    }

    #[must_use]
    pub const fn endpoint_sequence(&self) -> u64 {
        self.endpoint_sequence
    }

    #[must_use]
    pub const fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    #[must_use]
    pub const fn operation_lease_generation(&self) -> u64 {
        self.operation_lease_generation
    }

    #[must_use]
    pub const fn admission_generation(&self) -> u64 {
        self.admission_generation
    }

    #[must_use]
    pub const fn verified_at(&self) -> u64 {
        self.verified_at
    }

    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    #[must_use]
    pub const fn operator_id(&self) -> [u8; 32] {
        self.operator_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn generated_at(&self) -> u64 {
        self.generated_at
    }

    #[must_use]
    pub const fn snapshot_expires_at(&self) -> u64 {
        self.snapshot_expires_at
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

    #[must_use]
    pub const fn production_eligible(&self) -> bool {
        self.production_eligible
    }

    /// Reconfirm the exact current broker guard and committed profile state.
    ///
    /// The embedding must keep the broker's subject-wide operation exclusion
    /// held through the dependent display/use. This method cannot acquire or
    /// extend that external lease.
    pub fn reconfirm_current(
        &self,
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
        state: &HrmPoolStatsState,
    ) -> Result<(), HrmPoolStatsError> {
        authority.validate()?;
        if !authority.matches_request(request)
            || self.hns_name != request.expected_name
            || self.network_magic != request.expected_network_magic
            || self.route_id != request.expected_route_id
            || self.service_resource_id != authority.service_resource_id
            || self.service_delegation_id != authority.service_delegation_id
            || self.service_generation != authority.service_generation
            || self.authority_revision != authority.authority_revision
            || self.operation_lease_generation != authority.operation_lease_generation
            || self.admission_generation != state.generation
            || self.verified_at != request.trusted_now
            || request.trusted_now >= self.valid_until
            || !state.matches_current(authority, request)
        {
            return Err(HrmPoolStatsError::HistoricalAdmission);
        }
        Ok(())
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
struct EndpointState {
    endpoint_key: [u8; 33],
    sequence: u64,
    delegation_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperatorState {
    operator_id: [u8; 32],
    sequence: u64,
    digest: [u8; 32],
}

/// Bounded profile-local replay state beneath a separately durable HRM broker.
///
/// This state does not replace the subject-wide authenticated HRM/HNSA
/// aggregate, initialized marker, external revision floor, or fenced lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HrmPoolStatsState {
    generation: u64,
    trusted_time_high_water: u64,
    status: StateStatus,
    network_magic: u32,
    name_hash: [u8; 32],
    authority_revision: u64,
    hrm_sequence: u64,
    hrm_envelope_hash: [u8; 32],
    service_resource_id: [u8; 32],
    service_delegation_id: [u8; 32],
    service_generation: u64,
    endpoints: Vec<EndpointState>,
    operators: Vec<OperatorState>,
}

impl HrmPoolStatsState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            trusted_time_high_water: 0,
            status: StateStatus::Active,
            network_magic: 0,
            name_hash: [0; 32],
            authority_revision: 0,
            hrm_sequence: 0,
            hrm_envelope_hash: [0; 32],
            service_resource_id: [0; 32],
            service_delegation_id: [0; 32],
            service_generation: 0,
            endpoints: Vec::new(),
            operators: Vec::new(),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn trusted_time_high_water(&self) -> u64 {
        self.trusted_time_high_water
    }

    #[must_use]
    pub const fn authority_revision(&self) -> u64 {
        self.authority_revision
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

    /// Encode the canonical state with a corruption-detection checksum.
    pub fn encode(&self) -> Result<Vec<u8>, HrmPoolStatsError> {
        if !self.valid_shape() {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let mut output = Vec::with_capacity(MAX_STATE_BYTES);
        output.extend_from_slice(STATE_MAGIC);
        output.push(STATE_VERSION);
        output.extend_from_slice(&self.generation.to_le_bytes());
        output.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        output.push(self.status as u8);
        output.extend_from_slice(&self.network_magic.to_le_bytes());
        output.extend_from_slice(&self.name_hash);
        output.extend_from_slice(&self.authority_revision.to_le_bytes());
        output.extend_from_slice(&self.hrm_sequence.to_le_bytes());
        output.extend_from_slice(&self.hrm_envelope_hash);
        output.extend_from_slice(&self.service_resource_id);
        output.extend_from_slice(&self.service_delegation_id);
        output.extend_from_slice(&self.service_generation.to_le_bytes());
        output
            .push(u8::try_from(self.endpoints.len()).map_err(|_| HrmPoolStatsError::InvalidState)?);
        for endpoint in &self.endpoints {
            output.extend_from_slice(&endpoint.endpoint_key);
            output.extend_from_slice(&endpoint.sequence.to_le_bytes());
            output.extend_from_slice(&endpoint.delegation_id);
        }
        output
            .push(u8::try_from(self.operators.len()).map_err(|_| HrmPoolStatsError::InvalidState)?);
        for operator in &self.operators {
            output.extend_from_slice(&operator.operator_id);
            output.extend_from_slice(&operator.sequence.to_le_bytes());
            output.extend_from_slice(&operator.digest);
        }
        if output.len().saturating_add(STATE_CHECKSUM_BYTES) > MAX_STATE_BYTES {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let checksum = blake2b_256(STATE_CHECKSUM_DOMAIN, &[&output])?;
        output.extend_from_slice(&checksum);
        Ok(output)
    }

    /// Decode one canonical checksummed state from authenticated platform storage.
    pub fn decode(input: &[u8]) -> Result<Self, HrmPoolStatsError> {
        if input.len() <= STATE_CHECKSUM_BYTES || input.len() > MAX_STATE_BYTES {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let payload_length = input.len() - STATE_CHECKSUM_BYTES;
        let (payload, checksum) = input.split_at(payload_length);
        if blake2b_256(STATE_CHECKSUM_DOMAIN, &[payload])? != checksum {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let mut reader = Reader::state(payload);
        if reader.array::<4>()? != *STATE_MAGIC || reader.u8()? != STATE_VERSION {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let generation = reader.u64()?;
        let trusted_time_high_water = reader.u64()?;
        let status = match reader.u8()? {
            1 => StateStatus::Active,
            2 => StateStatus::Conflicted,
            3 => StateStatus::Exhausted,
            _ => return Err(HrmPoolStatsError::InvalidState),
        };
        let network_magic = reader.u32()?;
        let name_hash = reader.array()?;
        let authority_revision = reader.u64()?;
        let hrm_sequence = reader.u64()?;
        let hrm_envelope_hash = reader.array()?;
        let service_resource_id = reader.array()?;
        let service_delegation_id = reader.array()?;
        let service_generation = reader.u64()?;
        let endpoint_count = usize::from(reader.u8()?);
        if endpoint_count > MAX_ENDPOINT_HISTORIES {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            let endpoint = EndpointState {
                endpoint_key: reader.array()?,
                sequence: reader.u64()?,
                delegation_id: reader.array()?,
            };
            VerifyingKey::from_sec1_bytes(&endpoint.endpoint_key)
                .map_err(|_| HrmPoolStatsError::InvalidState)?;
            endpoints.push(endpoint);
        }
        let operator_count = usize::from(reader.u8()?);
        if operator_count > MAX_OPERATOR_HISTORIES {
            return Err(HrmPoolStatsError::InvalidState);
        }
        let mut operators = Vec::with_capacity(operator_count);
        for _ in 0..operator_count {
            operators.push(OperatorState {
                operator_id: reader.array()?,
                sequence: reader.u64()?,
                digest: reader.array()?,
            });
        }
        reader.finish()?;
        let state = Self {
            generation,
            trusted_time_high_water,
            status,
            network_magic,
            name_hash,
            authority_revision,
            hrm_sequence,
            hrm_envelope_hash,
            service_resource_id,
            service_delegation_id,
            service_generation,
            endpoints,
            operators,
        };
        if !state.valid_shape() || state.encode()?.as_slice() != input {
            return Err(HrmPoolStatsError::InvalidState);
        }
        Ok(state)
    }

    fn valid_shape(&self) -> bool {
        self.generation != 0
            && self.authority_revision != 0
            && self.service_generation != 0
            && self.endpoints.len() <= MAX_ENDPOINT_HISTORIES
            && strictly_sorted_by(&self.endpoints, |value| value.endpoint_key)
            && self.endpoints.iter().all(|value| {
                value.sequence != 0 && VerifyingKey::from_sec1_bytes(&value.endpoint_key).is_ok()
            })
            && self.operators.len() <= MAX_OPERATOR_HISTORIES
            && strictly_sorted_by(&self.operators, |value| value.operator_id)
            && self
                .operators
                .iter()
                .all(|value| value.operator_id != [0; 32] && value.sequence != 0)
    }

    fn matches_current(
        &self,
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
    ) -> bool {
        matches!(self.status, StateStatus::Active)
            && self.trusted_time_high_water == request.trusted_now
            && self.network_magic == authority.network_magic
            && self.name_hash == authority.name_hash
            && self.authority_revision == authority.authority_revision
            && self.hrm_sequence == authority.hrm_sequence
            && self.hrm_envelope_hash == authority.hrm_envelope_hash
            && self.service_resource_id == authority.service_resource_id
            && self.service_delegation_id == authority.service_delegation_id
            && self.service_generation == authority.service_generation
    }

    fn observe_authority(
        &mut self,
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
    ) -> Result<(), HrmPoolStatsError> {
        if self.generation == 0 {
            self.bump_generation()?;
            self.trusted_time_high_water = request.trusted_now;
            self.network_magic = authority.network_magic;
            self.name_hash = authority.name_hash;
            self.authority_revision = authority.authority_revision;
            self.hrm_sequence = authority.hrm_sequence;
            self.hrm_envelope_hash = authority.hrm_envelope_hash;
            self.service_resource_id = authority.service_resource_id;
            self.service_delegation_id = authority.service_delegation_id;
            self.service_generation = authority.service_generation;
            return Ok(());
        }
        if self.network_magic != authority.network_magic || self.name_hash != authority.name_hash {
            return Err(HrmPoolStatsError::StateScopeMismatch);
        }

        let previous_time = self.trusted_time_high_water;
        if request.trusted_now < previous_time {
            return Err(HrmPoolStatsError::TrustedClockRollback);
        }
        if request.trusted_now > previous_time {
            self.bump_generation()?;
            self.trusted_time_high_water = request.trusted_now;
        }
        if authority.authority_revision < self.authority_revision
            || authority.hrm_sequence < self.hrm_sequence
            || authority.service_generation < self.service_generation
        {
            return Err(HrmPoolStatsError::AuthorityRollback);
        }
        if authority.authority_revision == self.authority_revision {
            if authority.hrm_sequence != self.hrm_sequence
                || authority.hrm_envelope_hash != self.hrm_envelope_hash
                || authority.service_resource_id != self.service_resource_id
                || authority.service_delegation_id != self.service_delegation_id
                || authority.service_generation != self.service_generation
            {
                self.mark_conflicted()?;
                return Err(HrmPoolStatsError::ConflictingAuthority);
            }
            if request.trusted_now > previous_time {
                return Err(HrmPoolStatsError::AuthorityNotCurrent);
            }
        }
        if (authority.hrm_sequence == self.hrm_sequence
            && authority.hrm_envelope_hash != self.hrm_envelope_hash)
            || authority.service_resource_id != self.service_resource_id
            || (authority.service_generation == self.service_generation
                && authority.service_delegation_id != self.service_delegation_id)
            || (authority.service_generation > self.service_generation
                && authority.service_delegation_id == self.service_delegation_id)
        {
            self.mark_conflicted()?;
            return Err(HrmPoolStatsError::ConflictingAuthority);
        }

        let service_replaced = authority.service_generation > self.service_generation;
        if authority.authority_revision > self.authority_revision
            || authority.hrm_sequence > self.hrm_sequence
            || service_replaced
        {
            self.bump_generation()?;
            self.authority_revision = authority.authority_revision;
            self.hrm_sequence = authority.hrm_sequence;
            self.hrm_envelope_hash = authority.hrm_envelope_hash;
            self.service_delegation_id = authority.service_delegation_id;
            self.service_generation = authority.service_generation;
            if service_replaced {
                self.endpoints.clear();
                self.operators.clear();
            }
        }
        self.require_active()
    }

    fn advance_endpoint(
        &mut self,
        endpoint_key: [u8; 33],
        sequence: u64,
        delegation_id: [u8; 32],
    ) -> Result<(), HrmPoolStatsError> {
        match self
            .endpoints
            .binary_search_by_key(&endpoint_key, |value| value.endpoint_key)
        {
            Ok(position) => {
                let current = self.endpoints[position];
                if sequence < current.sequence {
                    return Err(HrmPoolStatsError::SequenceRollback);
                }
                if sequence == current.sequence && delegation_id != current.delegation_id {
                    self.mark_conflicted()?;
                    return Err(HrmPoolStatsError::ConflictingSequence);
                }
                if sequence > current.sequence {
                    self.bump_generation()?;
                    self.endpoints[position] = EndpointState {
                        endpoint_key,
                        sequence,
                        delegation_id,
                    };
                }
                Ok(())
            }
            Err(position) => {
                if self.endpoints.len() >= MAX_ENDPOINT_HISTORIES {
                    self.mark_exhausted()?;
                    return Err(HrmPoolStatsError::StateExhausted);
                }
                self.bump_generation()?;
                self.endpoints.insert(
                    position,
                    EndpointState {
                        endpoint_key,
                        sequence,
                        delegation_id,
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
    ) -> Result<(), HrmPoolStatsError> {
        match self
            .operators
            .binary_search_by_key(&operator_id, |value| value.operator_id)
        {
            Ok(position) => {
                let current = self.operators[position];
                if sequence < current.sequence {
                    return Err(HrmPoolStatsError::SequenceRollback);
                }
                if sequence == current.sequence && digest != current.digest {
                    self.mark_conflicted()?;
                    return Err(HrmPoolStatsError::ConflictingSequence);
                }
                if sequence > current.sequence {
                    self.bump_generation()?;
                    self.operators[position] = OperatorState {
                        operator_id,
                        sequence,
                        digest,
                    };
                }
                Ok(())
            }
            Err(position) => {
                if self.operators.len() >= MAX_OPERATOR_HISTORIES {
                    self.mark_exhausted()?;
                    return Err(HrmPoolStatsError::StateExhausted);
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

    fn require_active(&self) -> Result<(), HrmPoolStatsError> {
        match self.status {
            StateStatus::Active => Ok(()),
            StateStatus::Conflicted => Err(HrmPoolStatsError::StateConflicted),
            StateStatus::Exhausted => Err(HrmPoolStatsError::StateExhausted),
        }
    }

    fn mark_conflicted(&mut self) -> Result<(), HrmPoolStatsError> {
        if !matches!(self.status, StateStatus::Conflicted) {
            self.bump_generation()?;
            self.status = StateStatus::Conflicted;
        }
        Ok(())
    }

    fn mark_exhausted(&mut self) -> Result<(), HrmPoolStatsError> {
        if !matches!(self.status, StateStatus::Exhausted) {
            self.bump_generation()?;
            self.status = StateStatus::Exhausted;
        }
        Ok(())
    }

    fn bump_generation(&mut self) -> Result<(), HrmPoolStatsError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(HrmPoolStatsError::StateGenerationExhausted)?;
        Ok(())
    }
}

impl Default for HrmPoolStatsState {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned by commit-before-release HRM admission.
#[derive(Debug)]
pub enum HrmPoolStatsAdmissionError<E> {
    Verification(HrmPoolStatsError),
    Persistence(E),
}

impl<E: fmt::Display> fmt::Display for HrmPoolStatsAdmissionError<E> {
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

impl<E> Error for HrmPoolStatsAdmissionError<E>
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

/// Verify one HRM-backed document and commit every state mutation before release.
///
/// `commit` must compare `previous_generation`, atomically replace the complete
/// state, authenticate it, enforce an external rollback floor, and resolve an
/// ambiguous outcome by exact retry before this API is called again.
pub fn verify_hrm_and_commit<E>(
    authority: &CurrentHrmNamedService,
    request: HrmPoolStatsRequest<'_>,
    document: &[u8],
    state: &mut HrmPoolStatsState,
    mut commit: impl FnMut(u64, &[u8]) -> Result<(), E>,
) -> Result<VerifiedHrmPoolStatsSnapshot, HrmPoolStatsAdmissionError<E>> {
    let previous_generation = state.generation;
    let mut candidate = state.clone();
    let result = verify_document(authority, request, document, &mut candidate);
    if candidate.generation != previous_generation {
        let encoded = candidate
            .encode()
            .map_err(HrmPoolStatsAdmissionError::Verification)?;
        commit(previous_generation, &encoded).map_err(HrmPoolStatsAdmissionError::Persistence)?;
        *state = candidate;
    }
    result.map_err(HrmPoolStatsAdmissionError::Verification)
}

/// Profile, authority, signature, replacement, or local-state failure.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum HrmPoolStatsError {
    #[error("the independently selected HNS name is invalid")]
    InvalidExpectedName,
    #[error("the independently selected route ID is invalid")]
    InvalidExpectedRoute,
    #[error("the opaque broker-issued current HRM authority is invalid")]
    InvalidCurrentAuthority,
    #[error("the current HRM authority does not match the independent request")]
    AuthorityContextMismatch,
    #[error("the broker authority revision did not advance with trusted time")]
    AuthorityNotCurrent,
    #[error("the HRM authority, generation, revision, or trusted time moved backwards")]
    AuthorityRollback,
    #[error("equal current authority state conflicts with retained state")]
    ConflictingAuthority,
    #[error("the MeshMine HRM document is invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("the HNSA endpoint delegation is invalid: {0}")]
    InvalidEndpoint(&'static str),
    #[error("the HNSA endpoint-delegation signature is invalid")]
    EndpointCryptography,
    #[error("the MeshMine signed snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    #[error("the MeshMine endpoint snapshot signature is invalid")]
    SnapshotCryptography,
    #[error("the persistent pool-statistics state belongs to another authority scope")]
    StateScopeMismatch,
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
    #[error("the admission is historical or no longer bound to current authority")]
    HistoricalAdmission,
}

fn verify_document(
    authority: &CurrentHrmNamedService,
    request: HrmPoolStatsRequest<'_>,
    document: &[u8],
    state: &mut HrmPoolStatsState,
) -> Result<VerifiedHrmPoolStatsSnapshot, HrmPoolStatsError> {
    authority.validate()?;
    if !authority.matches_request(request) {
        return Err(HrmPoolStatsError::AuthorityContextMismatch);
    }
    state.observe_authority(authority, request)?;
    state.require_active()?;

    let document = PoolStatsDocument::decode(document)?;
    let endpoint_bytes = decode_lower_hex(
        &document.endpoint_delegation,
        MAX_ENDPOINT_BYTES,
        "invalid endpoint delegation",
    )?;
    let snapshot_bytes = decode_lower_hex(
        &document.snapshot,
        MAX_SNAPSHOT_BYTES,
        "invalid signed snapshot",
    )?;

    let endpoint = EndpointDelegation::decode(&endpoint_bytes)?;
    endpoint.verify(authority, request.trusted_now)?;
    let endpoint_id = endpoint.id();
    state.advance_endpoint(
        endpoint.endpoint_key,
        endpoint.endpoint_sequence,
        endpoint_id,
    )?;

    let snapshot = PoolStatsSnapshot::decode(&snapshot_bytes)?;
    snapshot.verify(authority, request, &endpoint, endpoint_id)?;
    let snapshot_digest = blake2b_256(SNAPSHOT_STATE_DOMAIN, &[&snapshot_bytes])?;
    state.advance_snapshot(snapshot.operator_id, snapshot.sequence, snapshot_digest)?;

    Ok(snapshot.minimize(
        authority,
        request,
        endpoint_id,
        endpoint.endpoint_sequence,
        state.generation,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolStatsDocument {
    schema: String,
    service_name: String,
    application_profile_id: u16,
    endpoint_delegation: String,
    snapshot: String,
}

impl PoolStatsDocument {
    fn decode(input: &[u8]) -> Result<Self, HrmPoolStatsError> {
        if input.is_empty() || input.len() > MAX_DOCUMENT_BYTES {
            return Err(HrmPoolStatsError::InvalidDocument("invalid document size"));
        }
        let document: Self = serde_json::from_slice(input)
            .map_err(|_| HrmPoolStatsError::InvalidDocument("invalid strict JSON document"))?;
        if document.schema != DOCUMENT_SCHEMA
            || document.service_name != SERVICE_NAME
            || document.application_profile_id != EXPERIMENTAL_PROFILE_ID
        {
            return Err(HrmPoolStatsError::InvalidDocument(
                "unsupported schema, service, or application profile",
            ));
        }
        Ok(document)
    }
}

struct EndpointDelegation {
    network_magic: u32,
    service_resource_id: [u8; 32],
    service_delegation_id: [u8; 32],
    service_generation: u64,
    endpoint_key: [u8; 33],
    endpoint_sequence: u64,
    issued_at: u64,
    expires_at: u64,
    capabilities: u32,
    constraints_hash: [u8; 32],
    unsigned: Vec<u8>,
    signature: Vec<u8>,
    encoded: Vec<u8>,
}

impl EndpointDelegation {
    fn decode(input: &[u8]) -> Result<Self, HrmPoolStatsError> {
        if input.is_empty() || input.len() > MAX_ENDPOINT_BYTES {
            return Err(HrmPoolStatsError::InvalidEndpoint("invalid object size"));
        }
        let mut reader = Reader::endpoint(input);
        if reader.u8()? != ENDPOINT_VERSION {
            return Err(HrmPoolStatsError::InvalidEndpoint("unsupported version"));
        }
        let network_magic = reader.u32()?;
        let service_resource_id = reader.array()?;
        let service_delegation_id = reader.array()?;
        let service_generation = reader.u64()?;
        let endpoint_key = reader.array()?;
        let endpoint_sequence = reader.u64()?;
        let issued_at = reader.u64()?;
        let expires_at = reader.u64()?;
        let capabilities = reader.u32()?;
        let constraints_hash = reader.array()?;
        let unsigned = input[..reader.offset].to_vec();
        let signature_length = usize::from(reader.u8()?);
        if !(1..=MAX_SIGNATURE_BYTES).contains(&signature_length) {
            return Err(HrmPoolStatsError::InvalidEndpoint(
                "invalid signature length",
            ));
        }
        let signature = reader.bytes(signature_length)?.to_vec();
        reader.finish()?;
        if service_generation == 0 || endpoint_sequence == 0 || issued_at >= expires_at {
            return Err(HrmPoolStatsError::InvalidEndpoint("invalid bounded fields"));
        }
        VerifyingKey::from_sec1_bytes(&endpoint_key)
            .map_err(|_| HrmPoolStatsError::InvalidEndpoint("invalid endpoint key"))?;
        parse_low_s_signature(&signature, HrmPoolStatsError::EndpointCryptography)?;
        Ok(Self {
            network_magic,
            service_resource_id,
            service_delegation_id,
            service_generation,
            endpoint_key,
            endpoint_sequence,
            issued_at,
            expires_at,
            capabilities,
            constraints_hash,
            unsigned,
            signature,
            encoded: input.to_vec(),
        })
    }

    fn verify(
        &self,
        authority: &CurrentHrmNamedService,
        trusted_now: u64,
    ) -> Result<(), HrmPoolStatsError> {
        if self.network_magic != authority.network_magic
            || self.service_resource_id != authority.service_resource_id
            || self.service_delegation_id != authority.service_delegation_id
            || self.service_generation != authority.service_generation
            || self.issued_at < authority.resource_not_before
            || self.issued_at < authority.delegation_not_before
            || self.expires_at > authority.resource_expires_at
            || self.expires_at > authority.delegation_expires_at
            || self.expires_at.saturating_sub(self.issued_at)
                > u64::from(authority.max_endpoint_lifetime)
            || trusted_now < self.issued_at
            || trusted_now >= self.expires_at
            || self.capabilities != READ_STATS_CAPABILITY
            || self.capabilities & !authority.allowed_endpoint_capabilities != 0
            || self.constraints_hash != authority.endpoint_constraints_hash
        {
            return Err(HrmPoolStatsError::InvalidEndpoint(
                "endpoint authority context mismatch",
            ));
        }
        let signature =
            parse_low_s_signature(&self.signature, HrmPoolStatsError::EndpointCryptography)?;
        let digest = blake2b_256(ENDPOINT_SIGNATURE_DOMAIN, &[&self.unsigned])?;
        VerifyingKey::from_sec1_bytes(&authority.service_controller_key)
            .map_err(|_| HrmPoolStatsError::EndpointCryptography)?
            .verify_prehash(&digest, &signature)
            .map_err(|_| HrmPoolStatsError::EndpointCryptography)
    }

    fn id(&self) -> [u8; 32] {
        sha256(ENDPOINT_ID_DOMAIN, &self.encoded)
    }
}

struct PoolStatsSnapshot {
    network_magic: u32,
    application_profile_id: u16,
    service_resource_id: [u8; 32],
    service_delegation_id: [u8; 32],
    service_generation: u64,
    endpoint_delegation_id: [u8; 32],
    endpoint_sequence: u64,
    route_id: [u8; 32],
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
    signature: Vec<u8>,
}

impl PoolStatsSnapshot {
    fn decode(input: &[u8]) -> Result<Self, HrmPoolStatsError> {
        if input.is_empty() || input.len() > MAX_SNAPSHOT_BYTES {
            return Err(HrmPoolStatsError::InvalidSnapshot("invalid object size"));
        }
        let mut reader = Reader::snapshot(input);
        if reader.u8()? != SNAPSHOT_VERSION {
            return Err(HrmPoolStatsError::InvalidSnapshot("unsupported version"));
        }
        let network_magic = reader.u32()?;
        let application_profile_id = reader.u16()?;
        let service_resource_id = reader.array()?;
        let service_delegation_id = reader.array()?;
        let service_generation = reader.u64()?;
        let endpoint_delegation_id = reader.array()?;
        let endpoint_sequence = reader.u64()?;
        let route_id = reader.array()?;
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
            _ => return Err(HrmPoolStatsError::InvalidSnapshot("invalid block option")),
        };
        let mode = PublicMode::try_from(reader.u8()?)?;
        let production_eligible = match reader.u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(HrmPoolStatsError::InvalidSnapshot(
                    "invalid production flag",
                ));
            }
        };
        let unsigned = input[..reader.offset].to_vec();
        let signature_length = usize::from(reader.u8()?);
        if !(1..=MAX_SIGNATURE_BYTES).contains(&signature_length) {
            return Err(HrmPoolStatsError::InvalidSnapshot(
                "invalid signature length",
            ));
        }
        let signature = reader.bytes(signature_length)?.to_vec();
        reader.finish()?;
        if application_profile_id != EXPERIMENTAL_PROFILE_ID
            || service_generation == 0
            || endpoint_sequence == 0
            || route_id == [0; 32]
            || sequence == 0
            || operator_id == [0; 32]
            || generated_at >= expires_at
            || expires_at.saturating_sub(generated_at) > MAX_SNAPSHOT_LIFETIME_SECONDS
            || last_found_block.is_some_and(|block| block.height > tip_height)
        {
            return Err(HrmPoolStatsError::InvalidSnapshot("invalid bounded fields"));
        }
        parse_low_s_signature(&signature, HrmPoolStatsError::SnapshotCryptography)?;
        Ok(Self {
            network_magic,
            application_profile_id,
            service_resource_id,
            service_delegation_id,
            service_generation,
            endpoint_delegation_id,
            endpoint_sequence,
            route_id,
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
            signature,
        })
    }

    fn verify(
        &self,
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
        endpoint: &EndpointDelegation,
        endpoint_id: [u8; 32],
    ) -> Result<(), HrmPoolStatsError> {
        if self.network_magic != authority.network_magic
            || self.application_profile_id != authority.application_profile_id
            || self.service_resource_id != authority.service_resource_id
            || self.service_delegation_id != authority.service_delegation_id
            || self.service_generation != authority.service_generation
            || self.endpoint_delegation_id != endpoint_id
            || self.endpoint_sequence != endpoint.endpoint_sequence
            || self.route_id != request.expected_route_id
            || self.generated_at < endpoint.issued_at
            || self.expires_at > endpoint.expires_at
            || request.trusted_now < self.generated_at
            || request.trusted_now >= self.expires_at
        {
            return Err(HrmPoolStatsError::InvalidSnapshot(
                "snapshot authority or route context mismatch",
            ));
        }
        let signature =
            parse_low_s_signature(&self.signature, HrmPoolStatsError::SnapshotCryptography)?;
        let digest = blake2b_256(SNAPSHOT_SIGNATURE_DOMAIN, &[&self.unsigned])?;
        VerifyingKey::from_sec1_bytes(&endpoint.endpoint_key)
            .map_err(|_| HrmPoolStatsError::SnapshotCryptography)?
            .verify_prehash(&digest, &signature)
            .map_err(|_| HrmPoolStatsError::SnapshotCryptography)
    }

    fn minimize(
        self,
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
        endpoint_delegation_id: [u8; 32],
        endpoint_sequence: u64,
        admission_generation: u64,
    ) -> VerifiedHrmPoolStatsSnapshot {
        VerifiedHrmPoolStatsSnapshot {
            hns_name: request.expected_name.to_vec(),
            network_magic: self.network_magic,
            route_id: self.route_id,
            service_resource_id: self.service_resource_id,
            service_delegation_id: self.service_delegation_id,
            service_generation: self.service_generation,
            endpoint_delegation_id,
            endpoint_sequence,
            authority_revision: authority.authority_revision,
            operation_lease_generation: authority.operation_lease_generation,
            admission_generation,
            verified_at: request.trusted_now,
            valid_until: self
                .expires_at
                .min(authority.resource_expires_at)
                .min(authority.delegation_expires_at),
            operator_id: self.operator_id,
            sequence: self.sequence,
            generated_at: self.generated_at,
            snapshot_expires_at: self.expires_at,
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

fn decode_lower_hex(
    input: &str,
    maximum_bytes: usize,
    message: &'static str,
) -> Result<Vec<u8>, HrmPoolStatsError> {
    if input.is_empty()
        || input.len() > maximum_bytes.saturating_mul(2)
        || !input.len().is_multiple_of(2)
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HrmPoolStatsError::InvalidDocument(message));
    }
    hex::decode(input).map_err(|_| HrmPoolStatsError::InvalidDocument(message))
}

fn parse_low_s_signature(
    input: &[u8],
    error: HrmPoolStatsError,
) -> Result<Signature, HrmPoolStatsError> {
    if input.is_empty() || input.len() > MAX_SIGNATURE_BYTES {
        return Err(error);
    }
    let signature = Signature::from_der(input).map_err(|_| error.clone())?;
    if signature.normalize_s().is_some() || signature.to_der().as_bytes() != input {
        return Err(error);
    }
    Ok(signature)
}

fn blake2b_256(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], HrmPoolStatsError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| HrmPoolStatsError::SnapshotCryptography)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| HrmPoolStatsError::SnapshotCryptography)?;
    Ok(output)
}

fn sha256(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, body);
    hasher.finalize().into()
}

fn named_service_resource_id(
    network_magic: u32,
    name_hash: [u8; 32],
    service_name: &[u8],
    application_profile_id: u16,
) -> [u8; 32] {
    let mut identifier = Vec::with_capacity(80);
    identifier.push(0xa4);
    identifier.push(0);
    encode_cbor_unsigned(&mut identifier, u64::from(network_magic));
    identifier.push(1);
    encode_cbor_bytes(&mut identifier, &name_hash);
    identifier.push(2);
    encode_cbor_text(&mut identifier, service_name);
    identifier.push(3);
    encode_cbor_unsigned(&mut identifier, u64::from(application_profile_id));
    sha256(NAMED_SERVICE_ID_DOMAIN, &identifier)
}

fn encode_cbor_unsigned(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => output.push(value as u8),
        24..=255 => {
            output.push(0x18);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(0x19);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0x1a);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn encode_cbor_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_cbor_length(output, 2, value.len());
    output.extend_from_slice(value);
}

fn encode_cbor_text(output: &mut Vec<u8>, value: &[u8]) {
    encode_cbor_length(output, 3, value.len());
    output.extend_from_slice(value);
}

fn encode_cbor_length(output: &mut Vec<u8>, major: u8, length: usize) {
    let prefix = major << 5;
    match length {
        0..=23 => output.push(prefix | length as u8),
        24..=255 => {
            output.push(prefix | 24);
            output.push(length as u8);
        }
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(length as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
}

fn is_canonical_hns_label(name: &[u8]) -> bool {
    // This is the root-name grammar consumed by hns_covenants::hash_name,
    // not HNSA's deliberately narrower service-name grammar.
    (1..=63).contains(&name.len())
        && !matches!(
            name,
            b"example" | b"invalid" | b"local" | b"localhost" | b"test"
        )
        && !matches!(name.first(), Some(b'-' | b'_'))
        && !matches!(name.last(), Some(b'-' | b'_'))
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

#[derive(Clone, Copy)]
enum ReaderKind {
    Endpoint,
    Snapshot,
    State,
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    kind: ReaderKind,
}

impl<'a> Reader<'a> {
    const fn endpoint(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            kind: ReaderKind::Endpoint,
        }
    }

    const fn snapshot(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            kind: ReaderKind::Snapshot,
        }
    }

    const fn state(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            kind: ReaderKind::State,
        }
    }

    fn error(&self) -> HrmPoolStatsError {
        match self.kind {
            ReaderKind::Endpoint => {
                HrmPoolStatsError::InvalidEndpoint("truncated or trailing bytes")
            }
            ReaderKind::Snapshot => {
                HrmPoolStatsError::InvalidSnapshot("truncated or trailing bytes")
            }
            ReaderKind::State => HrmPoolStatsError::InvalidState,
        }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], HrmPoolStatsError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.error())?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| self.error())?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HrmPoolStatsError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| HrmPoolStatsError::InvalidState)
    }

    fn u8(&mut self) -> Result<u8, HrmPoolStatsError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, HrmPoolStatsError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, HrmPoolStatsError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, HrmPoolStatsError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), HrmPoolStatsError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(self.error())
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
    const ROUTE_ID: [u8; 32] = [5; 32];
    const NOW: u64 = 1_700_000_100;

    fn public_key(private: [u8; 32]) -> [u8; 33] {
        SigningKey::from_bytes((&private).into())
            .expect("private key")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed public key")
    }

    fn name_hash() -> [u8; 32] {
        Sha3_256::digest(NAME).into()
    }

    fn authority() -> CurrentHrmNamedService {
        CurrentHrmNamedService {
            network_magic: MAGIC,
            name_hash: name_hash(),
            service_name: SERVICE_NAME.to_owned(),
            application_profile_id: EXPERIMENTAL_PROFILE_ID,
            hrm_sequence: 7,
            hrm_envelope_hash: [6; 32],
            authority_revision: 11,
            operation_lease_generation: 13,
            trusted_operation_time: NOW,
            service_resource_id: named_service_resource_id(
                MAGIC,
                name_hash(),
                SERVICE_NAME.as_bytes(),
                EXPERIMENTAL_PROFILE_ID,
            ),
            service_delegation_id: [8; 32],
            service_generation: 3,
            service_controller_key: public_key([2; 32]),
            resource_not_before: NOW - 1_000,
            resource_expires_at: NOW + 10_000,
            delegation_not_before: NOW - 500,
            delegation_expires_at: NOW + 5_000,
            max_endpoint_lifetime: 3_600,
            allowed_endpoint_capabilities: READ_STATS_CAPABILITY,
            endpoint_constraints_hash: [9; 32],
        }
    }

    fn request(now: u64) -> HrmPoolStatsRequest<'static> {
        HrmPoolStatsRequest::new(NAME, MAGIC, ROUTE_ID, now).expect("request")
    }

    fn sign(private: [u8; 32], domain: &[u8], body: &[u8]) -> Vec<u8> {
        let digest = blake2b_256(domain, &[body]).expect("digest");
        let signature: Signature = SigningKey::from_bytes((&private).into())
            .expect("private key")
            .sign_prehash(&digest)
            .expect("signature");
        signature.to_der().as_bytes().to_vec()
    }

    fn endpoint_with_interval(
        authority: &CurrentHrmNamedService,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut bytes = vec![ENDPOINT_VERSION];
        bytes.extend_from_slice(&authority.network_magic.to_le_bytes());
        bytes.extend_from_slice(&authority.service_resource_id);
        bytes.extend_from_slice(&authority.service_delegation_id);
        bytes.extend_from_slice(&authority.service_generation.to_le_bytes());
        bytes.extend_from_slice(&public_key([3; 32]));
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.extend_from_slice(&issued_at.to_le_bytes());
        bytes.extend_from_slice(&expires_at.to_le_bytes());
        bytes.extend_from_slice(&READ_STATS_CAPABILITY.to_le_bytes());
        bytes.extend_from_slice(&authority.endpoint_constraints_hash);
        let signature = sign([2; 32], ENDPOINT_SIGNATURE_DOMAIN, &bytes);
        bytes.push(u8::try_from(signature.len()).expect("signature length"));
        bytes.extend_from_slice(&signature);
        bytes
    }

    fn endpoint(authority: &CurrentHrmNamedService, sequence: u64) -> Vec<u8> {
        endpoint_with_interval(authority, sequence, NOW - 10, NOW + 300)
    }

    fn snapshot_with_interval(
        authority: &CurrentHrmNamedService,
        endpoint: &[u8],
        sequence: u64,
        generated_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let decoded = EndpointDelegation::decode(endpoint).expect("endpoint");
        let mut bytes = vec![SNAPSHOT_VERSION];
        bytes.extend_from_slice(&authority.network_magic.to_le_bytes());
        bytes.extend_from_slice(&EXPERIMENTAL_PROFILE_ID.to_le_bytes());
        bytes.extend_from_slice(&authority.service_resource_id);
        bytes.extend_from_slice(&authority.service_delegation_id);
        bytes.extend_from_slice(&authority.service_generation.to_le_bytes());
        bytes.extend_from_slice(&decoded.id());
        bytes.extend_from_slice(&decoded.endpoint_sequence.to_le_bytes());
        bytes.extend_from_slice(&ROUTE_ID);
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.extend_from_slice(&generated_at.to_le_bytes());
        bytes.extend_from_slice(&expires_at.to_le_bytes());
        bytes.extend_from_slice(&[10; 32]);
        bytes.extend_from_slice(&100_u32.to_le_bytes());
        bytes.extend_from_slice(&[11; 32]);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&5_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.push(0);
        bytes.push(1);
        bytes.push(0);
        let signature = sign([3; 32], SNAPSHOT_SIGNATURE_DOMAIN, &bytes);
        bytes.push(u8::try_from(signature.len()).expect("signature length"));
        bytes.extend_from_slice(&signature);
        bytes
    }

    fn snapshot(authority: &CurrentHrmNamedService, endpoint: &[u8], sequence: u64) -> Vec<u8> {
        snapshot_with_interval(authority, endpoint, sequence, NOW - 5, NOW + 60)
    }

    fn resign_endpoint(mut bytes: Vec<u8>) -> Vec<u8> {
        let body_length = EndpointDelegation::decode(&bytes)
            .expect("structurally valid endpoint")
            .unsigned
            .len();
        bytes.truncate(body_length);
        let signature = sign([2; 32], ENDPOINT_SIGNATURE_DOMAIN, &bytes);
        bytes.push(u8::try_from(signature.len()).expect("signature length"));
        bytes.extend_from_slice(&signature);
        bytes
    }

    fn resign_snapshot(mut bytes: Vec<u8>) -> Vec<u8> {
        let body_length = PoolStatsSnapshot::decode(&bytes)
            .expect("structurally valid snapshot")
            .unsigned
            .len();
        bytes.truncate(body_length);
        let signature = sign([3; 32], SNAPSHOT_SIGNATURE_DOMAIN, &bytes);
        bytes.push(u8::try_from(signature.len()).expect("signature length"));
        bytes.extend_from_slice(&signature);
        bytes
    }

    fn with_redundant_der_integer_zero(signature: &[u8]) -> Vec<u8> {
        assert_eq!(signature[0], 0x30);
        assert!(signature[1] < 0x80);
        assert_eq!(signature[2], 0x02);
        assert!(signature[3] < 0x80);
        let mut noncanonical = signature.to_vec();
        noncanonical[1] += 1;
        noncanonical[3] += 1;
        noncanonical.insert(4, 0);
        noncanonical
    }

    fn document(endpoint: &[u8], snapshot: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": DOCUMENT_SCHEMA,
            "service_name": SERVICE_NAME,
            "application_profile_id": EXPERIMENTAL_PROFILE_ID,
            "endpoint_delegation": hex::encode(endpoint),
            "snapshot": hex::encode(snapshot),
        }))
        .expect("document")
    }

    fn verify(
        authority: &CurrentHrmNamedService,
        request: HrmPoolStatsRequest<'_>,
        document: &[u8],
        state: &mut HrmPoolStatsState,
    ) -> Result<VerifiedHrmPoolStatsSnapshot, HrmPoolStatsError> {
        verify_document(authority, request, document, state)
    }

    #[test]
    fn canonical_named_service_identity_matches_the_frozen_schema_2_vector() {
        assert_eq!(
            hex::encode(name_hash()),
            "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
        );
        assert_eq!(
            hex::encode(named_service_resource_id(
                MAGIC,
                name_hash(),
                SERVICE_NAME.as_bytes(),
                EXPERIMENTAL_PROFILE_ID,
            )),
            "2727a07fe0cd866ac2a1d92b06c07fa6a067aa02c1edc4b327bff5e755523cb7"
        );
        assert_eq!(request(NOW).expected_name_hash(), name_hash());
    }

    #[test]
    fn expected_name_uses_handshake_consensus_grammar_not_service_label_grammar() {
        let request = HrmPoolStatsRequest::new(b"pool_1", MAGIC, ROUTE_ID, NOW)
            .expect("interior underscore is a canonical Handshake name");
        assert_eq!(
            hex::encode(request.expected_name_hash()),
            "57cbbbf29ae97cf301aa128c6d4b6fbda7269d491af0a659f57c0b1cfe011360"
        );
        for invalid in [
            b"_pool".as_slice(),
            b"pool_".as_slice(),
            b"example".as_slice(),
            b"invalid".as_slice(),
            b"local".as_slice(),
            b"localhost".as_slice(),
            b"test".as_slice(),
        ] {
            assert!(matches!(
                HrmPoolStatsRequest::new(invalid, MAGIC, ROUTE_ID, NOW),
                Err(HrmPoolStatsError::InvalidExpectedName)
            ));
        }
    }

    #[test]
    fn verifies_exact_hrm_endpoint_route_and_snapshot_bindings() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 9);
        let mut state = HrmPoolStatsState::new();
        let mut commits = Vec::new();
        let verified = verify_hrm_and_commit(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
            |generation, encoded| {
                commits.push((generation, encoded.to_vec()));
                Ok::<(), &str>(())
            },
        )
        .expect("verified");
        assert_eq!(verified.hns_name(), NAME);
        assert_eq!(verified.route_id(), ROUTE_ID);
        assert_eq!(verified.service_generation(), 3);
        assert_eq!(verified.endpoint_sequence(), 1);
        assert_eq!(verified.sequence(), 9);
        assert_eq!(verified.mode(), PublicMode::Mining);
        assert_eq!(verified.connected_miners(), 2);
        assert!(!verified.production_eligible());
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, 0);
        assert_eq!(
            HrmPoolStatsState::decode(&commits[0].1).expect("decode"),
            state
        );
        verified
            .reconfirm_current(&authority, request(NOW), &state)
            .expect("current");
    }

    #[test]
    fn accepts_initial_hrm_sequence_zero_and_round_trips_committed_state() {
        // HRM Core permits the initial commitment sequence to be zero. HNSA
        // endpoint and application-record replacement sequences remain
        // independently nonzero, so they stay at one here.
        let mut authority = authority();
        authority.hrm_sequence = 0;
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        let mut committed = None;
        let verified = verify_hrm_and_commit(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
            |previous_generation, encoded| {
                assert_eq!(previous_generation, 0);
                committed = Some(encoded.to_vec());
                Ok::<(), &str>(())
            },
        )
        .expect("HRM sequence zero is valid");

        assert_eq!(authority.hrm_sequence(), 0);
        assert_eq!(
            HrmPoolStatsState::decode(&committed.expect("committed state"))
                .expect("decode sequence-zero state"),
            state
        );
        verified
            .reconfirm_current(&authority, request(NOW), &state)
            .expect("sequence-zero authority remains current");
    }

    #[test]
    fn accepts_zero_where_hrm_and_hnsa_define_unsigned_or_digest_fields() {
        let mut zero_authority = authority();
        zero_authority.network_magic = 0;
        zero_authority.hrm_envelope_hash = [0; 32];
        zero_authority.service_delegation_id = [0; 32];
        zero_authority.endpoint_constraints_hash = [0; 32];
        zero_authority.service_resource_id = named_service_resource_id(
            zero_authority.network_magic,
            zero_authority.name_hash,
            zero_authority.service_name.as_bytes(),
            zero_authority.application_profile_id,
        );
        let endpoint = endpoint(&zero_authority, 1);
        let snapshot = snapshot(&zero_authority, &endpoint, 1);
        let zero_network_request = HrmPoolStatsRequest::new(NAME, 0, ROUTE_ID, NOW)
            .expect("network magic is the exact active u32, including zero");
        let mut state = HrmPoolStatsState::new();
        let verified = verify(
            &zero_authority,
            zero_network_request,
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("zero-valued unsigned network and digest fields are not sentinels");
        assert_eq!(verified.network_magic(), 0);
        assert_eq!(verified.service_delegation_id(), [0; 32]);
        assert_eq!(
            HrmPoolStatsState::decode(&state.encode().expect("encode"))
                .expect("decode zero-valued fields"),
            state
        );

        let mut epoch_authority = authority();
        epoch_authority.trusted_operation_time = 0;
        epoch_authority.resource_not_before = 0;
        epoch_authority.resource_expires_at = 1_000;
        epoch_authority.delegation_not_before = 0;
        epoch_authority.delegation_expires_at = 600;
        let epoch_endpoint = endpoint_with_interval(&epoch_authority, 1, 0, 300);
        let epoch_snapshot = snapshot_with_interval(&epoch_authority, &epoch_endpoint, 1, 0, 60);
        let mut epoch_state = HrmPoolStatsState::new();
        verify(
            &epoch_authority,
            request(0),
            &document(&epoch_endpoint, &epoch_snapshot),
            &mut epoch_state,
        )
        .expect("Unix epoch is a valid exact trusted operation time");
        assert_eq!(epoch_state.trusted_time_high_water(), 0);
        HrmPoolStatsState::decode(&epoch_state.encode().expect("encode epoch state"))
            .expect("decode epoch state");
    }

    #[test]
    fn rejects_noncanonical_der_before_signature_verification() {
        let canonical = sign([2; 32], ENDPOINT_SIGNATURE_DOMAIN, b"canonical body");
        parse_low_s_signature(&canonical, HrmPoolStatsError::EndpointCryptography)
            .expect("canonical low-S DER");
        let noncanonical = with_redundant_der_integer_zero(&canonical);
        assert!(matches!(
            parse_low_s_signature(&noncanonical, HrmPoolStatsError::EndpointCryptography),
            Err(HrmPoolStatsError::EndpointCryptography)
        ));
    }

    #[test]
    fn rejects_legacy_hsa1_document_shape_and_schema() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let legacy = serde_json::to_vec(&json!({
            "schema": "meshmine-pool-stats-v1",
            "service_name": SERVICE_NAME,
            "profile_id": EXPERIMENTAL_PROFILE_ID,
            "service_authorization": "aa",
            "endpoint_delegation": hex::encode(endpoint),
            "snapshot": hex::encode(snapshot),
        }))
        .expect("legacy document");
        let mut state = HrmPoolStatsState::new();
        assert!(matches!(
            verify(&authority, request(NOW), &legacy, &mut state),
            Err(HrmPoolStatsError::InvalidDocument(_))
        ));
    }

    #[test]
    fn rejects_every_endpoint_authority_context_mismatch() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let cases = [(1, 4), (5, 32), (37, 32), (69, 8), (126, 4), (130, 32)];
        for (offset, length) in cases {
            let mut invalid = endpoint.clone();
            invalid[offset..offset + length].fill(0x55);
            let snapshot = snapshot(&authority, &endpoint, 1);
            let mut state = HrmPoolStatsState::new();
            assert!(
                verify(
                    &authority,
                    request(NOW),
                    &document(&invalid, &snapshot),
                    &mut state,
                )
                .is_err()
            );
        }
        let mut trailing = endpoint.clone();
        trailing.push(0);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        assert!(matches!(
            verify(
                &authority,
                request(NOW),
                &document(&trailing, &snapshot),
                &mut state,
            ),
            Err(HrmPoolStatsError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn enforces_signed_endpoint_interval_capability_and_constraint_rules() {
        let current = authority();
        let base = endpoint(&current, 1);
        let mut cases = Vec::new();

        let mut missing_capability = base.clone();
        missing_capability[134..138].copy_from_slice(&0_u32.to_le_bytes());
        cases.push((current.clone(), resign_endpoint(missing_capability)));

        let mut extra_capability_authority = current.clone();
        extra_capability_authority.allowed_endpoint_capabilities |= 2;
        let mut extra_capability = endpoint(&extra_capability_authority, 1);
        extra_capability[134..138].copy_from_slice(&3_u32.to_le_bytes());
        cases.push((
            extra_capability_authority,
            resign_endpoint(extra_capability),
        ));

        let mut wrong_constraints = base.clone();
        wrong_constraints[138..170].fill(77);
        cases.push((current.clone(), resign_endpoint(wrong_constraints)));

        let mut excessive_lifetime = base.clone();
        excessive_lifetime[126..134].copy_from_slice(&(NOW - 10 + 3_601).to_le_bytes());
        cases.push((current.clone(), resign_endpoint(excessive_lifetime)));

        let mut outside_resource = base;
        outside_resource[118..126]
            .copy_from_slice(&(current.resource_not_before - 1).to_le_bytes());
        cases.push((current, resign_endpoint(outside_resource)));

        for (authority, endpoint) in cases {
            let snapshot = snapshot(&authority, &endpoint, 1);
            let mut state = HrmPoolStatsState::new();
            assert!(matches!(
                verify(
                    &authority,
                    request(NOW),
                    &document(&endpoint, &snapshot),
                    &mut state,
                ),
                Err(HrmPoolStatsError::InvalidEndpoint(_))
            ));
        }

        for maximum in [
            MIN_ENDPOINT_LIFETIME_LIMIT - 1,
            MAX_ENDPOINT_LIFETIME_LIMIT + 1,
        ] {
            let mut invalid = authority();
            invalid.max_endpoint_lifetime = maximum;
            let mut state = HrmPoolStatsState::new();
            assert!(matches!(
                verify(&invalid, request(NOW), b"{}", &mut state),
                Err(HrmPoolStatsError::InvalidCurrentAuthority)
            ));
        }
    }

    #[test]
    fn rejects_snapshot_profile_route_generation_endpoint_and_expiry_mismatches() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let valid = snapshot(&authority, &endpoint, 1);
        let cases = [
            (5, 2),
            (7, 32),
            (39, 32),
            (71, 8),
            (79, 32),
            (111, 8),
            (119, 32),
            (167, 8),
        ];
        for (offset, length) in cases {
            let mut invalid = valid.clone();
            invalid[offset..offset + length].fill(0x44);
            let mut state = HrmPoolStatsState::new();
            assert!(
                verify(
                    &authority,
                    request(NOW),
                    &document(&endpoint, &invalid),
                    &mut state,
                )
                .is_err()
            );
        }
        let wrong_route =
            HrmPoolStatsRequest::new(NAME, MAGIC, [12; 32], NOW).expect("wrong route request");
        let mut state = HrmPoolStatsState::new();
        assert!(matches!(
            verify(
                &authority,
                wrong_route,
                &document(&endpoint, &valid),
                &mut state,
            ),
            Err(HrmPoolStatsError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn enforces_endpoint_signed_snapshot_context_and_interval_rules() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let base = snapshot(&authority, &endpoint, 1);

        let mut wrong_route = base.clone();
        wrong_route[119..151].fill(88);
        let mut wrong_endpoint_id = base.clone();
        wrong_endpoint_id[79..111].fill(89);
        let mut wrong_endpoint_sequence = base.clone();
        wrong_endpoint_sequence[111..119].copy_from_slice(&2_u64.to_le_bytes());
        let mut before_endpoint = base;
        before_endpoint[159..167].copy_from_slice(&(NOW - 11).to_le_bytes());

        for snapshot in [
            resign_snapshot(wrong_route),
            resign_snapshot(wrong_endpoint_id),
            resign_snapshot(wrong_endpoint_sequence),
            resign_snapshot(before_endpoint),
        ] {
            let mut state = HrmPoolStatsState::new();
            assert!(matches!(
                verify(
                    &authority,
                    request(NOW),
                    &document(&endpoint, &snapshot),
                    &mut state,
                ),
                Err(HrmPoolStatsError::InvalidSnapshot(_))
            ));
        }

        let short_endpoint = endpoint_with_interval(&authority, 1, NOW - 10, NOW + 30);
        let outside_endpoint = snapshot(&authority, &short_endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        assert!(matches!(
            verify(
                &authority,
                request(NOW),
                &document(&short_endpoint, &outside_endpoint),
                &mut state,
            ),
            Err(HrmPoolStatsError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn commits_time_advance_before_returning_cryptographic_failure() {
        let authority = authority();
        let initial_endpoint = endpoint(&authority, 1);
        let first_snapshot = snapshot(&authority, &initial_endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        verify(
            &authority,
            request(NOW),
            &document(&initial_endpoint, &first_snapshot),
            &mut state,
        )
        .expect("first");

        let mut later = authority.clone();
        later.authority_revision += 1;
        later.trusted_operation_time += 1;
        let later_request = request(NOW + 1);
        let mut conflicted_endpoint = endpoint(&later, 1);
        let signature_offset = conflicted_endpoint.len() - 70;
        conflicted_endpoint[signature_offset] ^= 1;
        let mut commits = Vec::new();
        let result = verify_hrm_and_commit(
            &later,
            later_request,
            &document(&conflicted_endpoint, &first_snapshot),
            &mut state,
            |generation, encoded| {
                commits.push((generation, encoded.to_vec()));
                Ok::<(), &str>(())
            },
        );
        assert!(result.is_err());
        assert_eq!(state.trusted_time_high_water(), NOW + 1);
        assert_eq!(state.authority_revision(), later.authority_revision);
        assert_eq!(commits.len(), 1);
    }

    #[test]
    fn service_generation_rollback_and_equal_generation_conflict_fail_closed() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        verify(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("first");

        let mut rollback = authority.clone();
        rollback.authority_revision += 1;
        rollback.hrm_sequence += 1;
        rollback.service_generation -= 1;
        assert!(matches!(
            verify(&rollback, request(NOW), b"{}", &mut state),
            Err(HrmPoolStatsError::AuthorityRollback)
        ));

        let mut conflict = authority.clone();
        conflict.authority_revision += 1;
        conflict.hrm_sequence += 1;
        conflict.service_delegation_id = [22; 32];
        assert!(matches!(
            verify(&conflict, request(NOW), b"{}", &mut state),
            Err(HrmPoolStatsError::ConflictingAuthority)
        ));
        assert!(state.is_conflicted());
    }

    #[test]
    fn greater_service_generation_resets_profile_replacement_scope() {
        let authority = authority();
        let initial_endpoint = endpoint(&authority, 9);
        let initial_snapshot = snapshot(&authority, &initial_endpoint, 9);
        let mut state = HrmPoolStatsState::new();
        let historical = verify(
            &authority,
            request(NOW),
            &document(&initial_endpoint, &initial_snapshot),
            &mut state,
        )
        .expect("initial generation");

        let mut replacement = authority.clone();
        replacement.authority_revision += 1;
        replacement.hrm_sequence += 1;
        replacement.hrm_envelope_hash = [33; 32];
        replacement.service_generation += 1;
        replacement.service_delegation_id = [34; 32];
        let replacement_endpoint = endpoint(&replacement, 1);
        let replacement_snapshot = snapshot(&replacement, &replacement_endpoint, 1);
        let current = verify(
            &replacement,
            request(NOW),
            &document(&replacement_endpoint, &replacement_snapshot),
            &mut state,
        )
        .expect("greater service generation resets endpoint and record sequence scope");
        assert_eq!(
            current.service_generation(),
            authority.service_generation() + 1
        );
        assert_eq!(current.endpoint_sequence(), 1);
        assert_eq!(current.sequence(), 1);
        assert!(matches!(
            historical.reconfirm_current(&authority, request(NOW), &state),
            Err(HrmPoolStatsError::HistoricalAdmission)
        ));
    }

    #[test]
    fn endpoint_and_snapshot_replacement_are_monotonic_and_equivocation_is_sticky() {
        let authority = authority();
        let endpoint_one = endpoint(&authority, 1);
        let snapshot_one = snapshot(&authority, &endpoint_one, 1);
        let mut state = HrmPoolStatsState::new();
        let first = verify(
            &authority,
            request(NOW),
            &document(&endpoint_one, &snapshot_one),
            &mut state,
        )
        .expect("first admission");

        let endpoint_two = endpoint(&authority, 2);
        let snapshot_two = snapshot(&authority, &endpoint_two, 2);
        let second = verify(
            &authority,
            request(NOW),
            &document(&endpoint_two, &snapshot_two),
            &mut state,
        )
        .expect("greater endpoint and snapshot sequences replace");
        assert_eq!(second.endpoint_sequence(), 2);
        assert_eq!(second.sequence(), 2);
        assert!(matches!(
            first.reconfirm_current(&authority, request(NOW), &state),
            Err(HrmPoolStatsError::HistoricalAdmission)
        ));

        let mut endpoint_equivocation = endpoint_two.clone();
        endpoint_equivocation[126..134].copy_from_slice(&(NOW + 299).to_le_bytes());
        let endpoint_equivocation = resign_endpoint(endpoint_equivocation);
        let endpoint_equivocation_snapshot = snapshot(&authority, &endpoint_equivocation, 3);
        assert!(matches!(
            verify(
                &authority,
                request(NOW),
                &document(&endpoint_equivocation, &endpoint_equivocation_snapshot),
                &mut state,
            ),
            Err(HrmPoolStatsError::ConflictingSequence)
        ));
        assert!(state.is_conflicted());

        let mut separate_state = HrmPoolStatsState::new();
        verify(
            &authority,
            request(NOW),
            &document(&endpoint_one, &snapshot_one),
            &mut separate_state,
        )
        .expect("separate first admission");
        let mut snapshot_equivocation = snapshot_one;
        snapshot_equivocation[243..247].copy_from_slice(&99_u32.to_le_bytes());
        let snapshot_equivocation = resign_snapshot(snapshot_equivocation);
        assert!(matches!(
            verify(
                &authority,
                request(NOW),
                &document(&endpoint_one, &snapshot_equivocation),
                &mut separate_state,
            ),
            Err(HrmPoolStatsError::ConflictingSequence)
        ));
        assert!(separate_state.is_conflicted());
    }

    #[test]
    fn equal_aggregate_revision_cannot_carry_a_changed_hrm_or_service_observation() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);

        for changed in [
            {
                let mut changed = authority.clone();
                changed.hrm_sequence += 1;
                changed.hrm_envelope_hash = [44; 32];
                changed
            },
            {
                let mut changed = authority.clone();
                changed.hrm_sequence += 1;
                changed.service_generation += 1;
                changed.service_delegation_id = [45; 32];
                changed
            },
        ] {
            let mut state = HrmPoolStatsState::new();
            verify(
                &authority,
                request(NOW),
                &document(&endpoint, &snapshot),
                &mut state,
            )
            .expect("initial authority");
            assert!(matches!(
                verify(&changed, request(NOW), b"{}", &mut state),
                Err(HrmPoolStatsError::ConflictingAuthority)
            ));
            assert!(state.is_conflicted());
        }
    }

    #[test]
    fn time_only_advance_is_committed_but_requires_a_fresh_aggregate_revision() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        let admitted = verify(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("initial authority");

        let mut stale_revision = authority.clone();
        stale_revision.trusted_operation_time = NOW + 1;
        let mut commits = 0;
        let result = verify_hrm_and_commit(
            &stale_revision,
            request(NOW + 1),
            &document(&endpoint, &snapshot),
            &mut state,
            |previous_generation, encoded| {
                assert!(previous_generation < HrmPoolStatsState::decode(encoded)?.generation());
                commits += 1;
                Ok::<(), HrmPoolStatsError>(())
            },
        );
        assert!(matches!(
            result,
            Err(HrmPoolStatsAdmissionError::Verification(
                HrmPoolStatsError::AuthorityNotCurrent
            ))
        ));
        assert_eq!(commits, 1);
        assert_eq!(state.trusted_time_high_water(), NOW + 1);
        assert_eq!(state.authority_revision(), authority.authority_revision());
        assert!(matches!(
            admitted.reconfirm_current(&authority, request(NOW), &state),
            Err(HrmPoolStatsError::HistoricalAdmission)
        ));

        let mut acknowledged = stale_revision;
        acknowledged.authority_revision += 1;
        let current = verify(
            &acknowledged,
            request(NOW + 1),
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("fresh aggregate revision acknowledges the time transition");
        current
            .reconfirm_current(&acknowledged, request(NOW + 1), &state)
            .expect("fresh time-bound authority is current");
    }

    #[test]
    fn persistence_failure_withholds_snapshot_and_preserves_loaded_state() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        let original = state.clone();
        let result = verify_hrm_and_commit(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
            |_, _| Err("store unavailable"),
        );
        assert!(matches!(
            result,
            Err(HrmPoolStatsAdmissionError::Persistence("store unavailable"))
        ));
        assert_eq!(state, original);
    }

    #[test]
    fn historical_result_rejects_authority_state_and_lease_changes() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        let verified = verify(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("verified");
        let mut replaced_lease = authority.clone();
        replaced_lease.operation_lease_generation += 1;
        assert!(matches!(
            verified.reconfirm_current(&replaced_lease, request(NOW), &state),
            Err(HrmPoolStatsError::HistoricalAdmission)
        ));
        state.generation += 1;
        assert!(matches!(
            verified.reconfirm_current(&authority, request(NOW), &state),
            Err(HrmPoolStatsError::HistoricalAdmission)
        ));
    }

    #[test]
    fn state_encoding_is_canonical_and_corruption_detecting() {
        let authority = authority();
        let endpoint = endpoint(&authority, 1);
        let snapshot = snapshot(&authority, &endpoint, 1);
        let mut state = HrmPoolStatsState::new();
        verify(
            &authority,
            request(NOW),
            &document(&endpoint, &snapshot),
            &mut state,
        )
        .expect("verified");
        let encoded = state.encode().expect("encode");
        assert_eq!(HrmPoolStatsState::decode(&encoded).expect("decode"), state);
        let mut corrupt = encoded;
        corrupt[20] ^= 1;
        assert!(HrmPoolStatsState::decode(&corrupt).is_err());
    }
}
