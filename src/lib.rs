#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Itinerary {
    pub schema_version: u32,
    pub itinerary_id: String,
    pub tenant_id: String,
    pub workload_id: String,
    pub state_epoch: u64,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub allowed_zones: Vec<String>,
    pub require_attestation: bool,
    pub max_total_latency_ms: u64,
    pub expires_at_ms: u64,
    pub permitted_action: PermittedAction,
    pub fallback: Fallback,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedItinerary {
    pub contract: Itinerary,
    pub hmac_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermittedAction {
    ReadOnly,
    Actuate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    SafeStop,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffReceipt {
    pub sequence: u64,
    pub itinerary_id: String,
    pub tenant_id: String,
    pub state_epoch: u64,
    pub from_zone: String,
    pub to_zone: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub elapsed_ms: u64,
    pub observed_at_ms: u64,
    pub attestation_sha256: Option<String>,
    pub action: ObservedAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservedAction {
    None,
    Read,
    Actuate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub itinerary_id: String,
    pub decision: Decision,
    pub fallback: Fallback,
    pub receipts_checked: usize,
    pub violations: Vec<Violation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Violation {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_sequence: Option<u64>,
}

#[derive(Debug, Error)]
pub enum TierlockError {
    #[error("the signing key must not be empty")]
    EmptyKey,
    #[error("could not serialize the itinerary: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid HMAC encoding")]
    InvalidMacEncoding,
}

pub fn seal(contract: Itinerary, key: &[u8]) -> Result<SealedItinerary, TierlockError> {
    let payload = canonical_contract(&contract)?;
    let mut mac = new_mac(key)?;
    mac.update(&payload);
    Ok(SealedItinerary {
        contract,
        hmac_sha256: hex::encode(mac.finalize().into_bytes()),
    })
}

pub fn verify(
    bundle: &SealedItinerary,
    receipts: &[HandoffReceipt],
    key: &[u8],
    now_ms: u64,
) -> Result<VerificationReport, TierlockError> {
    let contract = &bundle.contract;
    let mut violations = Vec::new();
    let payload = canonical_contract(contract)?;
    let supplied_mac =
        hex::decode(&bundle.hmac_sha256).map_err(|_| TierlockError::InvalidMacEncoding)?;
    let mut mac = new_mac(key)?;
    mac.update(&payload);
    if mac.verify_slice(&supplied_mac).is_err() {
        push_violation(
            &mut violations,
            "invalid_signature",
            "the itinerary HMAC does not match",
            None,
        );
        return Ok(report(contract, receipts.len(), violations));
    }

    validate_contract(contract, now_ms, &mut violations);

    if receipts.is_empty() {
        push_violation(
            &mut violations,
            "missing_receipts",
            "at least one handoff receipt is required",
            None,
        );
    }

    let zones: BTreeSet<&str> = contract.allowed_zones.iter().map(String::as_str).collect();
    let mut previous_to: Option<&str> = None;
    let mut previous_elapsed: Option<u64> = None;

    for (index, receipt) in receipts.iter().enumerate() {
        let sequence = Some(receipt.sequence);
        if receipt.sequence != index as u64 {
            push_violation(
                &mut violations,
                "sequence_gap",
                format!("expected sequence {index}, got {}", receipt.sequence),
                sequence,
            );
        }
        if receipt.itinerary_id != contract.itinerary_id {
            push_violation(
                &mut violations,
                "itinerary_mismatch",
                "receipt belongs to another itinerary",
                sequence,
            );
        }
        if receipt.tenant_id != contract.tenant_id {
            push_violation(
                &mut violations,
                "tenant_mismatch",
                "receipt belongs to another tenant",
                sequence,
            );
        }
        if receipt.state_epoch != contract.state_epoch {
            push_violation(
                &mut violations,
                "stale_epoch",
                "receipt state epoch does not match the itinerary",
                sequence,
            );
        }
        if receipt.model_sha256 != contract.model_sha256 {
            push_violation(
                &mut violations,
                "model_mismatch",
                "receipt model digest does not match",
                sequence,
            );
        }
        if receipt.runtime_sha256 != contract.runtime_sha256 {
            push_violation(
                &mut violations,
                "runtime_mismatch",
                "receipt runtime digest does not match",
                sequence,
            );
        }
        if !zones.contains(receipt.from_zone.as_str()) || !zones.contains(receipt.to_zone.as_str())
        {
            push_violation(
                &mut violations,
                "zone_not_allowed",
                "handoff enters or leaves a zone outside the contract",
                sequence,
            );
        }
        if let Some(expected_from) = previous_to
            && receipt.from_zone != expected_from
        {
            push_violation(
                &mut violations,
                "broken_chain",
                format!(
                    "handoff starts in {}, but the previous handoff ended in {expected_from}",
                    receipt.from_zone
                ),
                sequence,
            );
        }
        if let Some(previous) = previous_elapsed
            && receipt.elapsed_ms < previous
        {
            push_violation(
                &mut violations,
                "latency_regression",
                "cumulative latency moved backwards",
                sequence,
            );
        }
        if receipt.elapsed_ms > contract.max_total_latency_ms {
            push_violation(
                &mut violations,
                "latency_budget_exceeded",
                format!(
                    "{} ms exceeds the {} ms contract budget",
                    receipt.elapsed_ms, contract.max_total_latency_ms
                ),
                sequence,
            );
        }
        if receipt.observed_at_ms > contract.expires_at_ms {
            push_violation(
                &mut violations,
                "receipt_after_expiry",
                "receipt was observed after the itinerary expired",
                sequence,
            );
        }
        if contract.require_attestation {
            match receipt.attestation_sha256.as_deref() {
                Some(digest) if is_sha256(digest) => {}
                _ => push_violation(
                    &mut violations,
                    "attestation_required",
                    "a valid attestation digest is required",
                    sequence,
                ),
            }
        }
        if receipt.action == ObservedAction::Actuate
            && contract.permitted_action != PermittedAction::Actuate
        {
            push_violation(
                &mut violations,
                "actuation_not_permitted",
                "receipt attempted actuation under a read-only itinerary",
                sequence,
            );
        }

        previous_to = Some(&receipt.to_zone);
        previous_elapsed = Some(receipt.elapsed_ms);
    }

    Ok(report(contract, receipts.len(), violations))
}

fn validate_contract(contract: &Itinerary, now_ms: u64, violations: &mut Vec<Violation>) {
    if contract.schema_version != SCHEMA_VERSION {
        push_violation(
            violations,
            "unsupported_schema",
            format!(
                "schema version {} is not supported",
                contract.schema_version
            ),
            None,
        );
    }
    if contract.itinerary_id.trim().is_empty()
        || contract.tenant_id.trim().is_empty()
        || contract.workload_id.trim().is_empty()
        || contract.nonce.trim().is_empty()
    {
        push_violation(
            violations,
            "missing_identity",
            "itinerary, tenant, workload, and nonce must be non-empty",
            None,
        );
    }
    if !is_sha256(&contract.model_sha256) || !is_sha256(&contract.runtime_sha256) {
        push_violation(
            violations,
            "invalid_digest",
            "model and runtime digests must be lowercase SHA-256 hex",
            None,
        );
    }
    if contract.allowed_zones.is_empty()
        || contract
            .allowed_zones
            .iter()
            .any(|zone| zone.trim().is_empty())
    {
        push_violation(
            violations,
            "invalid_zones",
            "at least one non-empty allowed zone is required",
            None,
        );
    }
    let unique_zones: BTreeSet<&str> = contract.allowed_zones.iter().map(String::as_str).collect();
    if unique_zones.len() != contract.allowed_zones.len() {
        push_violation(
            violations,
            "duplicate_zone",
            "allowed zones must be unique",
            None,
        );
    }
    if contract.max_total_latency_ms == 0 {
        push_violation(
            violations,
            "invalid_latency_budget",
            "latency budget must be greater than zero",
            None,
        );
    }
    if now_ms > contract.expires_at_ms {
        push_violation(
            violations,
            "contract_expired",
            "itinerary has expired",
            None,
        );
    }
}

fn report(
    contract: &Itinerary,
    receipts_checked: usize,
    violations: Vec<Violation>,
) -> VerificationReport {
    VerificationReport {
        itinerary_id: contract.itinerary_id.clone(),
        decision: if violations.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny
        },
        fallback: contract.fallback.clone(),
        receipts_checked,
        violations,
    }
}

fn canonical_contract(contract: &Itinerary) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(contract)
}

fn new_mac(key: &[u8]) -> Result<HmacSha256, TierlockError> {
    if key.is_empty() {
        return Err(TierlockError::EmptyKey);
    }
    HmacSha256::new_from_slice(key).map_err(|_| TierlockError::EmptyKey)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_violation(
    violations: &mut Vec<Violation>,
    code: impl Into<String>,
    message: impl Into<String>,
    receipt_sequence: Option<u64>,
) {
    violations.push(Violation {
        code: code.into(),
        message: message.into(),
        receipt_sequence,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const KEY: &[u8] = b"test-only-secret";

    fn contract() -> Itinerary {
        Itinerary {
            schema_version: SCHEMA_VERSION,
            itinerary_id: "route-7".into(),
            tenant_id: "acme".into(),
            workload_id: "vision-42".into(),
            state_epoch: 9,
            model_sha256: DIGEST_A.into(),
            runtime_sha256: DIGEST_B.into(),
            allowed_zones: vec!["device".into(), "edge".into(), "cloud".into()],
            require_attestation: true,
            max_total_latency_ms: 250,
            expires_at_ms: 2_000,
            permitted_action: PermittedAction::ReadOnly,
            fallback: Fallback::SafeStop,
            nonce: "n-123".into(),
        }
    }

    fn receipt(sequence: u64, from: &str, to: &str, elapsed_ms: u64) -> HandoffReceipt {
        HandoffReceipt {
            sequence,
            itinerary_id: "route-7".into(),
            tenant_id: "acme".into(),
            state_epoch: 9,
            from_zone: from.into(),
            to_zone: to.into(),
            model_sha256: DIGEST_A.into(),
            runtime_sha256: DIGEST_B.into(),
            elapsed_ms,
            observed_at_ms: 1_500,
            attestation_sha256: Some(DIGEST_C.into()),
            action: ObservedAction::Read,
        }
    }

    fn codes(report: &VerificationReport) -> Vec<&str> {
        report.violations.iter().map(|v| v.code.as_str()).collect()
    }

    #[test]
    fn accepts_a_valid_chained_itinerary() {
        let sealed = seal(contract(), KEY).unwrap();
        let receipts = [
            receipt(0, "device", "edge", 40),
            receipt(1, "edge", "cloud", 120),
        ];
        let report = verify(&sealed, &receipts, KEY, 1_600).unwrap();
        assert_eq!(report.decision, Decision::Allow);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn rejects_tampered_contract() {
        let mut sealed = seal(contract(), KEY).unwrap();
        sealed.contract.state_epoch = 10;
        let report = verify(&sealed, &[receipt(0, "device", "edge", 40)], KEY, 1_600).unwrap();
        assert_eq!(codes(&report), vec!["invalid_signature"]);
    }

    #[test]
    fn rejects_wrong_key() {
        let sealed = seal(contract(), KEY).unwrap();
        let report = verify(
            &sealed,
            &[receipt(0, "device", "edge", 40)],
            b"wrong",
            1_600,
        )
        .unwrap();
        assert_eq!(codes(&report), vec!["invalid_signature"]);
    }

    #[test]
    fn rejects_empty_receipts() {
        let sealed = seal(contract(), KEY).unwrap();
        let report = verify(&sealed, &[], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"missing_receipts"));
    }

    #[test]
    fn rejects_expired_contract() {
        let sealed = seal(contract(), KEY).unwrap();
        let report = verify(&sealed, &[receipt(0, "device", "edge", 40)], KEY, 2_001).unwrap();
        assert!(codes(&report).contains(&"contract_expired"));
    }

    #[test]
    fn rejects_cross_tenant_receipt() {
        let sealed = seal(contract(), KEY).unwrap();
        let mut bad = receipt(0, "device", "edge", 40);
        bad.tenant_id = "other".into();
        let report = verify(&sealed, &[bad], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"tenant_mismatch"));
    }

    #[test]
    fn rejects_stale_epoch() {
        let sealed = seal(contract(), KEY).unwrap();
        let mut bad = receipt(0, "device", "edge", 40);
        bad.state_epoch = 8;
        let report = verify(&sealed, &[bad], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"stale_epoch"));
    }

    #[test]
    fn rejects_unapproved_zone() {
        let sealed = seal(contract(), KEY).unwrap();
        let report = verify(
            &sealed,
            &[receipt(0, "device", "satellite", 40)],
            KEY,
            1_600,
        )
        .unwrap();
        assert!(codes(&report).contains(&"zone_not_allowed"));
    }

    #[test]
    fn rejects_broken_chain_and_gap() {
        let sealed = seal(contract(), KEY).unwrap();
        let receipts = [
            receipt(0, "device", "edge", 40),
            receipt(2, "device", "cloud", 80),
        ];
        let report = verify(&sealed, &receipts, KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"sequence_gap"));
        assert!(codes(&report).contains(&"broken_chain"));
    }

    #[test]
    fn rejects_latency_budget_violation() {
        let sealed = seal(contract(), KEY).unwrap();
        let report = verify(&sealed, &[receipt(0, "device", "edge", 251)], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"latency_budget_exceeded"));
    }

    #[test]
    fn rejects_latency_regression() {
        let sealed = seal(contract(), KEY).unwrap();
        let receipts = [
            receipt(0, "device", "edge", 100),
            receipt(1, "edge", "cloud", 99),
        ];
        let report = verify(&sealed, &receipts, KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"latency_regression"));
    }

    #[test]
    fn rejects_missing_attestation() {
        let sealed = seal(contract(), KEY).unwrap();
        let mut bad = receipt(0, "device", "edge", 40);
        bad.attestation_sha256 = None;
        let report = verify(&sealed, &[bad], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"attestation_required"));
    }

    #[test]
    fn rejects_model_and_runtime_substitution() {
        let sealed = seal(contract(), KEY).unwrap();
        let mut bad = receipt(0, "device", "edge", 40);
        bad.model_sha256 = DIGEST_C.into();
        bad.runtime_sha256 = DIGEST_C.into();
        let report = verify(&sealed, &[bad], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"model_mismatch"));
        assert!(codes(&report).contains(&"runtime_mismatch"));
    }

    #[test]
    fn rejects_unauthorized_actuation() {
        let sealed = seal(contract(), KEY).unwrap();
        let mut bad = receipt(0, "device", "edge", 40);
        bad.action = ObservedAction::Actuate;
        let report = verify(&sealed, &[bad], KEY, 1_600).unwrap();
        assert!(codes(&report).contains(&"actuation_not_permitted"));
    }

    #[test]
    fn permits_actuation_when_explicitly_authorized() {
        let mut allowed = contract();
        allowed.permitted_action = PermittedAction::Actuate;
        let sealed = seal(allowed, KEY).unwrap();
        let mut event = receipt(0, "device", "edge", 40);
        event.action = ObservedAction::Actuate;
        let report = verify(&sealed, &[event], KEY, 1_600).unwrap();
        assert_eq!(report.decision, Decision::Allow);
    }

    #[test]
    fn refuses_empty_signing_key() {
        assert!(matches!(
            seal(contract(), b""),
            Err(TierlockError::EmptyKey)
        ));
    }
}
