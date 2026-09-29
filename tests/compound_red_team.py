"""Compound, multi-boundary defensive attack simulation for AAK v0.8."""

import os
import random
from dataclasses import asdict, replace

from aak import (
    AuthorityAttestation, AuthorityBundle, DispatchCapability, DownstreamEnforcer,
    Ed25519Signer, EnforcementGateway, ExternalAuditAnchor, IndependentAuthority,
    KeyRegistry, KeyStatus, Proposal, SenderProofVerifier, ThresholdVerifier,
    ToolContract, create_sender_proof, make_authority_claim,
)
from aak.canonical import canonical_bytes, digest
from aak.boundary import digest_bytes
from aak.crypto import b64encode


TOTAL = int(os.environ.get("AAK_COMPOUND_ATTEMPTS", "100000"))
if TOTAL < 10:
    raise ValueError("AAK_COMPOUND_ATTEMPTS must be at least 10")
rng = random.Random(20260917)
effects: list[tuple[str, int]] = []

proposal = Proposal(
    "tx-base", "tenant-a", "model", "pay approved invoice", "payment.transfer",
    "account/vendor", {"amount": 10}, {"money": 10, "operations": 1},
    ("invoice-1",), ("reviewer",),
)
authority_keys = [Ed25519Signer.generate() for _ in range(3)]
authorities = [
    IndependentAuthority(
        key,
        lambda p: p.action == "payment.transfer" and p.resource == "account/vendor"
        and p.parameters.get("amount", 10_000) <= 100 and p.evidence == ("invoice-1",),
    )
    for key in authority_keys
]
threshold = ThresholdVerifier(authority_keys, 2)
gateway_key = Ed25519Signer.generate()
gateway = EnforcementGateway(
    gateway_key, threshold, "payments-prod", expected_policy_hash="policy-v7",
    expected_system_version="v0.7", allow_test_time_override=True,
)
anchor_key = Ed25519Signer.generate()
anchor = ExternalAuditAnchor(anchor_key)
tool = ToolContract(
    "payment.transfer",
    lambda resource, params: resource == "account/vendor" and set(params) == {"amount"},
    lambda _resource, params: {"money": float(params["amount"]), "operations": 1.0},
    lambda resource, params: effects.append((resource, params["amount"])) or {"settled": True},
)
downstream = DownstreamEnforcer(
    gateway_verifier=gateway_key, authorities=threshold, anchor=anchor,
    anchor_verifier=anchor_key, expected_workload_identity="executor-prod",
    audience="payments-prod", tools=(tool,), principal_limits={"money": 100, "operations": 10},
    global_limits={"money": 100, "operations": 10}, expected_policy_hash="policy-v7",
    expected_system_version="v0.7", allow_test_time_override=True,
)
sender_key = Ed25519Signer.generate()
sender_registry = KeyRegistry((KeyStatus(sender_key, 90, 200),))
proof_verifier = SenderProofVerifier(
    sender_registry, audience="downstream", route="/v1/effects", method="POST",
    expected_subject="executor-prod", allow_test_time_override=True,
    max_replay_entries=TOTAL + 10,
)
downstream.bind_sender_proof_verifier(proof_verifier)
attacker_key = Ed25519Signer.generate()


def body_for(p: Proposal, b: AuthorityBundle, d: DispatchCapability) -> bytes:
    return canonical_bytes({
        "proposal": asdict(p),
        "bundle": {"claim": b.claim, "attestations": [asdict(item) for item in b.attestations]},
        "dispatch": asdict(d),
    })


attempts = 0
unauthorized_effects = 0
crashes = 0
denied = {"authority": 0, "gateway": 0, "transport": 0, "downstream": 0}

for index in range(TOTAL):
    before = len(effects)
    try:
        mode = index % 5

        # 1: compromised model + one authority + forged quorum + compromised-looking gateway.
        if mode == 0:
            changed = replace(
                proposal, transaction_id=f"c-{index}", principal_id="victim",
                resource="account/admin", parameters={"amount": 1_000_000},
                maximum_effect={"money": 1, "operations": 1}, evidence=("forged",),
            )
            claim = make_authority_claim(
                changed, policy_hash="attacker-policy", system_version="v0.7",
                audience="payments-prod", issued_at=100, expires_at=110,
                tenant_id="tenant-a",
            )
            one = AuthorityAttestation(
                authority_keys[0].key_id,
                b64encode(authority_keys[0].sign(canonical_bytes(claim))),
            )
            forged = AuthorityAttestation(attacker_key.key_id, b64encode(attacker_key.sign(canonical_bytes(claim))))
            bundle = AuthorityBundle(claim, (one, one, forged))
            fake_claim = {
                "v": 2, "bundle_hash": digest({"claim": claim, "attestations": [asdict(x) for x in bundle.attestations]}),
                "proposal_hash": claim["proposal_hash"], "nonce": claim["nonce"],
                "audience": "payments-prod", "expires_at": 110,
            }
            dispatch = DispatchCapability(
                fake_claim, gateway_key.key_id,
                b64encode(gateway_key.sign(canonical_bytes(fake_claim))),
            )
            result = downstream.execute(changed, bundle, dispatch, workload_identity="executor-prod", now=101)
            denied["authority" if result.reason == "insufficient_authority_quorum" else "downstream"] += 1

        # 2: valid captured authorization, but proposal + body + sender identity all substituted.
        elif mode == 1:
            p = replace(proposal, transaction_id=f"c-{index}")
            claim = make_authority_claim(p, policy_hash="policy-v7", system_version="v0.7",
                                         audience="payments-prod", issued_at=100, expires_at=110)
            bundle = AuthorityBundle(claim, tuple(a.attest(p, claim) for a in authorities[:2]))
            dispatch = gateway.dispatch(p, bundle, now=101)
            assert dispatch is not None
            body = body_for(p, bundle, dispatch)
            proof = create_sender_proof(
                sender_key, method="POST", route="/v1/effects", audience="downstream",
                body=body, issued_at=100, nonce=f"proof-{index}", subject="executor-prod",
            )
            changed = replace(p, resource="account/attacker", parameters={"amount": 99})
            poisoned_body = canonical_bytes({"captured": body.hex(), "override": "admin"})
            proof = replace(proof, subject="admin", body_hash=digest_bytes(poisoned_body), route="/v1/admin")
            result = downstream.execute_secure(
                changed, bundle, dispatch, request_body=poisoned_body, sender_proof=proof,
                proof_verifier=proof_verifier, workload_identity="executor-prod", now=101,
            )
            denied["transport"] += 1

        # 3: several signed authority-claim fields are changed together before quorum.
        elif mode == 2:
            p = replace(proposal, transaction_id=f"c-{index}")
            claim = make_authority_claim(p, policy_hash="policy-v7", system_version="v0.7",
                                         audience="payments-prod", issued_at=100, expires_at=110)
            claim.update({"tenant_id": "victim", "maximum_effect": {"money": 0, "operations": 0},
                          "audience": "admin", "resource_state_version": -1})
            attestations = tuple(x for a in authorities if (x := a.attest(p, claim)) is not None)
            bundle = AuthorityBundle(claim, attestations)
            if gateway.dispatch(p, bundle, now=101) is None:
                denied["authority"] += 1
            else:
                raise AssertionError("compound smuggled claim dispatched")

        # 4: exact valid proof is simultaneously rebound to method, route, audience and body.
        elif mode == 3:
            safe_body = canonical_bytes({"transaction_id": f"c-{index}", "amount": 10})
            proof = create_sender_proof(
                sender_key, method="POST", route="/v1/effects", audience="downstream",
                body=safe_body, issued_at=100, nonce=f"proof-{index}", subject="executor-prod",
            )
            mutated = replace(proof, method="DELETE", route="/v1/admin", audience="admin",
                              subject="root", body_hash="0" * 64)
            if proof_verifier.verify(mutated, b'{"admin":true}', now=101)[0]:
                raise AssertionError("compound sender substitution verified")
            denied["transport"] += 1

        # 5: stale/future/replay-style temporal confusion plus key/signature substitution.
        else:
            unsafe_body = canonical_bytes({"transaction_id": f"c-{index}", "amount": rng.randrange(1, 101)})
            proof = create_sender_proof(
                attacker_key, method="POST", route="/v1/effects", audience="downstream",
                body=unsafe_body, issued_at=10_000, nonce=f"proof-{index}", subject="executor-prod",
            )
            proof = replace(proof, key_id=sender_key.key_id, issued_at=-10_000)
            if proof_verifier.verify(proof, unsafe_body, now=101)[0]:
                raise AssertionError("temporal/key substitution verified")
            denied["transport"] += 1

    except Exception:
        crashes += 1
        raise
    finally:
        attempts += 1
        if len(effects) != before:
            unauthorized_effects += len(effects) - before

assert attempts == TOTAL
assert unauthorized_effects == 0, unauthorized_effects
assert crashes == 0, crashes
print(
    f"compound_attempts={attempts} unauthorized_effects={unauthorized_effects} crashes={crashes} "
    f"denials={denied}"
)
