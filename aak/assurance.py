"""External trust-domain primitives for staged AAK deployments.

These are deliberately provider-neutral verification boundaries.  Production
adapters should obtain identities from SPIFFE/SPIRE or a cloud workload
identity service and policy decisions from a separately administered PDP.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, b64decode, b64encode
from .store import StateStore


class PolicyDecisionProvider(Protocol):
    def decide(self, proposal: Any, *, now: int) -> "ExternalPolicyDecision": ...


class WorkloadAssertionProvider(Protocol):
    def assertion(self, *, audience: str, now: int) -> "WorkloadIdentityAssertion": ...


def _sign(signer: CapabilitySigner, claim: dict[str, Any]) -> str:
    return b64encode(signer.sign(canonical_bytes(claim)))


def _verify(verifier: CapabilitySigner, claim: dict[str, Any], signature: str) -> bool:
    try:
        return verifier.verify(canonical_bytes(claim), b64decode(signature))
    except (TypeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True)
class ExternalPolicyDecision:
    """Signed, short-lived PDP result bound to one exact AAK proposal."""

    schema_version: int
    decision_id: str
    proposal_hash: str
    allowed: bool
    policy_hash: str
    policy_revision: int
    audience: str
    issued_at: int
    expires_at: int
    issuer_key_id: str
    signature: str

    def claim(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}


class ExternalPolicyIssuer:
    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer

    def issue(
        self, *, decision_id: str, proposal: Any, allowed: bool,
        policy_hash: str, policy_revision: int, audience: str,
        issued_at: int, expires_at: int,
    ) -> ExternalPolicyDecision:
        claim = {
            "schema_version": 1, "decision_id": decision_id, "proposal_hash": digest(asdict(proposal)),
            "allowed": allowed, "policy_hash": policy_hash,
            "policy_revision": policy_revision, "audience": audience,
            "issued_at": issued_at, "expires_at": expires_at,
            "issuer_key_id": self.signer.key_id,
        }
        return ExternalPolicyDecision(**claim, signature=_sign(self.signer, claim))


class ExternalPolicyVerifier:
    """Fail-closed verifier with Zanzibar/TUF-style monotonic policy revision."""

    def __init__(
        self, verifier: CapabilitySigner, *, audience: str,
        expected_policy_hash: str, minimum_revision: int = 0,
        store: StateStore | None = None,
    ) -> None:
        self.verifier = verifier
        self.audience = audience
        self.expected_policy_hash = expected_policy_hash
        self.store = store or StateStore()
        self._namespace = digest({
            "kind": "policy", "issuer": verifier.key_id,
            "audience": audience, "policy_hash": expected_policy_hash,
        })
        self.store.raise_assurance_floor(f"external_policy_revision:{self._namespace}", minimum_revision)

    @property
    def minimum_revision(self) -> int:
        return self.store.assurance_floor(f"external_policy_revision:{self._namespace}")

    def verify(self, decision: ExternalPolicyDecision, proposal: Any, *, now: int) -> tuple[bool, str]:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return False, "invalid_policy_time"
        if not isinstance(decision, ExternalPolicyDecision):
            return False, "malformed_policy_decision"
        claim = decision.claim()
        if decision.schema_version != 1:
            return False, "unsupported_policy_schema"
        if decision.issuer_key_id != self.verifier.key_id or not _verify(self.verifier, claim, decision.signature):
            return False, "invalid_policy_signature"
        try:
            proposal_hash = digest(asdict(proposal))
        except (TypeError, ValueError, OverflowError):
            return False, "policy_input_mismatch"
        if (not isinstance(decision.decision_id, str) or not 1 <= len(decision.decision_id) <= 256
                or decision.proposal_hash != proposal_hash):
            return False, "policy_input_mismatch"
        if not isinstance(decision.allowed, bool):
            return False, "malformed_policy_decision"
        if decision.audience != self.audience or decision.policy_hash != self.expected_policy_hash:
            return False, "policy_binding_mismatch"
        if (isinstance(decision.policy_revision, bool) or not isinstance(decision.policy_revision, int)
                or decision.policy_revision < 0
                or isinstance(decision.issued_at, bool) or not isinstance(decision.issued_at, int)
                or isinstance(decision.expires_at, bool) or not isinstance(decision.expires_at, int)
                or decision.issued_at < 0 or decision.expires_at <= decision.issued_at
                or now < decision.issued_at or now >= decision.expires_at):
            return False, "policy_expired_or_invalid"
        if not decision.allowed:
            return False, "external_policy_denied"
        accepted, reason = self.store.accept_assurance_once(
            kind="policy", identifier=f"{self._namespace}:{decision.decision_id}",
            expires_at=decision.expires_at, now=now,
            monotonic_name=f"external_policy_revision:{self._namespace}", monotonic_value=decision.policy_revision,
        )
        if not accepted:
            return False, "policy_revision_rollback" if reason == "assurance_rollback" else "policy_decision_replay"
        return True, "external_policy_allowed"


@dataclass(frozen=True)
class WorkloadIdentityAssertion:
    """Assertion emitted only after an external mTLS identity check."""

    schema_version: int
    assertion_id: str
    spiffe_id: str
    trust_domain: str
    audience: str
    certificate_fingerprint: str
    channel_binding: str
    issued_at: int
    expires_at: int
    issuer_key_id: str
    signature: str

    def claim(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}


class WorkloadIdentityIssuer:
    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer

    def issue(
        self, *, assertion_id: str, spiffe_id: str, trust_domain: str, audience: str,
        certificate_fingerprint: str, channel_binding: str,
        issued_at: int, expires_at: int,
    ) -> WorkloadIdentityAssertion:
        claim = {
            "schema_version": 1, "assertion_id": assertion_id,
            "spiffe_id": spiffe_id, "trust_domain": trust_domain,
            "audience": audience, "certificate_fingerprint": certificate_fingerprint,
            "channel_binding": channel_binding,
            "issued_at": issued_at, "expires_at": expires_at,
            "issuer_key_id": self.signer.key_id,
        }
        return WorkloadIdentityAssertion(**claim, signature=_sign(self.signer, claim))


class WorkloadIdentityVerifier:
    def __init__(
        self, verifier: CapabilitySigner, *, expected_spiffe_id: str,
        trust_domain: str, audience: str, store: StateStore | None = None,
    ) -> None:
        self.verifier = verifier
        self.expected_spiffe_id = expected_spiffe_id
        self.trust_domain = trust_domain
        self.audience = audience
        self.store = store or StateStore()
        self._namespace = digest({
            "kind": "identity", "issuer": verifier.key_id,
            "spiffe_id": expected_spiffe_id, "trust_domain": trust_domain,
            "audience": audience,
        })

    def verify(
        self, assertion: WorkloadIdentityAssertion, *, now: int,
        expected_channel_binding: str | None = None,
    ) -> tuple[bool, str]:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return False, "invalid_identity_time"
        if not isinstance(assertion, WorkloadIdentityAssertion):
            return False, "malformed_workload_identity"
        if assertion.schema_version != 1:
            return False, "unsupported_identity_schema"
        if assertion.issuer_key_id != self.verifier.key_id or not _verify(self.verifier, assertion.claim(), assertion.signature):
            return False, "invalid_workload_identity_signature"
        if (assertion.spiffe_id != self.expected_spiffe_id
                or assertion.trust_domain != self.trust_domain
                or assertion.audience != self.audience):
            return False, "workload_identity_binding_mismatch"
        if (not isinstance(assertion.assertion_id, str) or not 1 <= len(assertion.assertion_id) <= 256
                or not isinstance(assertion.certificate_fingerprint, str)
                or not 1 <= len(assertion.certificate_fingerprint) <= 512
                or not isinstance(assertion.channel_binding, str) or not 1 <= len(assertion.channel_binding) <= 256
                or isinstance(assertion.issued_at, bool) or not isinstance(assertion.issued_at, int)
                or isinstance(assertion.expires_at, bool) or not isinstance(assertion.expires_at, int)
                or assertion.issued_at < 0 or assertion.expires_at <= assertion.issued_at
                or now < assertion.issued_at or now >= assertion.expires_at):
            return False, "workload_identity_expired_or_invalid"
        if not isinstance(expected_channel_binding, str) or not expected_channel_binding:
            return False, "workload_channel_binding_required"
        if assertion.channel_binding != expected_channel_binding:
            return False, "workload_channel_binding_mismatch"
        accepted, reason = self.store.accept_assurance_once(
            kind="identity", identifier=f"{self._namespace}:{assertion.assertion_id}",
            expires_at=assertion.expires_at, now=now,
        )
        if not accepted:
            return False, "workload_identity_replay" if reason == "assurance_replay" else "workload_identity_state_failure"
        return True, "workload_identity_verified"
