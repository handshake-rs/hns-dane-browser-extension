//! Dormant HRM/HNSA verification for MeshMine public pool statistics.
//!
//! The superseded `hsa1` and `ServiceAuthorizationV1` authority path is not
//! compiled into this crate. The verifier consumes an opaque
//! [`CurrentHrmNamedService`] that only a future trusted native broker can
//! construct, then verifies the HRM-backed HNSA endpoint delegation and the
//! profile-specific signed record. No constructor or production adapter for
//! that authority is exposed yet, so this core cannot enable a product path by
//! itself.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "the API keeps the experimental profile and dormant authority boundary explicit"
)]

mod hrm;

pub use hrm::{
    CurrentHrmNamedService, HrmPoolStatsAdmissionError, HrmPoolStatsError, HrmPoolStatsRequest,
    HrmPoolStatsState, PublicMode, VerifiedFoundBlock, VerifiedHrmPoolStatsSnapshot,
    verify_hrm_and_commit,
};

/// Version of the HRM-backed verifier/state contract.
pub const VERIFIER_SCHEMA_VERSION: u32 = 2;
/// Private experimental application profile pending a standards assignment.
pub const EXPERIMENTAL_PROFILE_ID: u16 = 0xff00;
/// Exact HNSA service selected independently of an operator response.
pub const SERVICE_NAME: &str = "pool-stats";
/// Sole endpoint capability admitted by this read-only profile.
pub const READ_STATS_CAPABILITY: u32 = 1;
/// No production broker can construct current HRM authority yet.
pub const HRM_AUTHORITY_ADAPTER_AVAILABLE: bool = false;
/// Superseded `hsa1` authority is never accepted by the production crate.
pub const LEGACY_HSA1_ACCEPTED: bool = false;
