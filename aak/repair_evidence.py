"""Deterministic, non-executing repair evidence gate.

This module NEVER authorizes execution. The AAK action gateway must approve
and consume exact-action grants separately before any tool performs effects.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json

MAX_EVIDENCE = 20
MAX_CHARS = 4096

def _text(value: str, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_CHARS:
        raise ValueError("invalid_" + label)
    return value

def _digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

@dataclass(frozen=True)
class RepairProposal:
    incident_id: str
    repository: str
    base_commit: str
    patch_sha256: str
    evidence_ids: tuple[str, ...]
    proposed_reason: str

    def __post_init__(self):
        for key in ("incident_id", "repository", "base_commit", "proposed_reason"):
            _text(getattr(self, key), key)
        if not isinstance(self.patch_sha256, str) or len(self.patch_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.patch_sha256):
            raise ValueError("invalid_patch_sha256")
        if not isinstance(self.evidence_ids, tuple) or not 1 <= len(self.evidence_ids) <= MAX_EVIDENCE:
            raise ValueError("invalid_evidence_ids")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate_evidence_ids")
        for evidence in self.evidence_ids:
            _text(evidence, "evidence_id")

    @property
    def proposal_id(self) -> str:
        return _digest({"incident_id": self.incident_id, "repository": self.repository,
                        "base_commit": self.base_commit, "patch_sha256": self.patch_sha256,
                        "evidence_ids": list(self.evidence_ids), "reason": self.proposed_reason})

@dataclass(frozen=True)
class Verification:
    proposal_id: str
    independently_tested: bool
    regression_passed: bool
    artifact_sha256: str
    verifier_id: str

    def __post_init__(self):
        _text(self.proposal_id, "proposal_id")
        _text(self.verifier_id, "verifier_id")
        if type(self.independently_tested) is not bool or type(self.regression_passed) is not bool:
            raise ValueError("invalid_verification_flags")
        if not isinstance(self.artifact_sha256, str) or len(self.artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.artifact_sha256):
            raise ValueError("invalid_artifact_sha256")

def reuse_decision(proposal: RepairProposal, verification: Verification | None, *,
                   approval_proposal_id: str | None, authority_consumed: bool) -> dict:
    """Advisory publication gate; NEVER a substitute for verifying grants at action execution."""
    if type(authority_consumed) is not bool:
        raise ValueError("invalid_authority_flag")
    reasons = []
    if approval_proposal_id != proposal.proposal_id or not authority_consumed:
        reasons.append("approval_or_authority_not_confirmed")
    if verification is None or verification.proposal_id != proposal.proposal_id:
        reasons.append("verification_missing_or_mismatched")
    elif not verification.independently_tested or not verification.regression_passed:
        reasons.append("verification_incomplete")
    return {"proposal_id": proposal.proposal_id, "publishable": not reasons,
            "reasons": reasons, "authorization": "metadata_only_never_execute"}
