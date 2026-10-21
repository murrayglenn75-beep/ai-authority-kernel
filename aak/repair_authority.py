"""Bind evidence-only repair proposals to AAK's signed action authority.

No write operations or repair execution occur in this adapter. Only resource
side callers holding trusted envelope and verifier objects may consume grants.
"""
from __future__ import annotations
from typing import Mapping
from .action_gateway import ActionEnvelope, ActionEnvelopeVerifier, ToolCall, ToolManifest
from .repair_evidence import RepairProposal, Verification, reuse_decision

def authorized_repair_record(
    proposal: RepairProposal,
    verification: Verification | None,
    *,
    envelope: ActionEnvelope,
    call: ToolCall,
    manifest: ToolManifest,
    verifier: ActionEnvelopeVerifier,
    now: int,
    effect_limits: Mapping[str, int],
) -> dict:
    """Consume scoped authority before declaring a repair record publishable.

    Callers MUST NOT execute the patch from this result; actual patch execution
    requires an independently authorized, separate action at the resource.
    """
    if not isinstance(proposal, RepairProposal):
        raise TypeError("invalid_repair_proposal")
    if verification is not None and not isinstance(verification, Verification):
        raise TypeError("invalid_verification")
    if not isinstance(call, ToolCall):
        raise TypeError("invalid_tool_call")
    if not isinstance(envelope, ActionEnvelope):
        raise TypeError("invalid_action_envelope")
    if not isinstance(manifest, ToolManifest):
        raise TypeError("invalid_tool_manifest")
    if not isinstance(verifier, ActionEnvelopeVerifier):
        raise TypeError("invalid_verifier")
    # This must be an evidence publication action, NOT a patch apply action.
    if call.action != "engineering.repair_record.publish":
        return {"publishable": False, "reason": "wrong_publication_action"}
    if (
        call.parameters != {"proposal_id": proposal.proposal_id, "artifact_sha256": (
            verification.artifact_sha256 if verification is not None else None
        )}
        or verification is None
        or verification.proposal_id != proposal.proposal_id
    ):
        return {"publishable": False, "reason": "evidence_binding_mismatch"}
    if not verification.independently_tested or not verification.regression_passed:
        return {"publishable": False, "reason": "verification_incomplete"}
    if not envelope.approval_refs:
        return {"publishable": False, "reason": "missing_approval_refs"}
    consumed, reason = verifier.verify_and_consume(
        envelope, call, manifest, now=now, effect_limits=effect_limits
    )
    if not consumed:
        return {"publishable": False, "reason": reason}
    advisory = reuse_decision(
        proposal, verification,
        approval_proposal_id=proposal.proposal_id, authority_consumed=True
    )
    return {"publishable": advisory["publishable"], "reason": "authorized_record" if advisory["publishable"] else "advisory_rejected",
            "proposal_id": proposal.proposal_id, "authorization": "record_only"}
