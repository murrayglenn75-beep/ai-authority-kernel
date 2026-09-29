"""Deterministic local defensive red-team campaign against AAK trust boundaries."""

import os
import random
from dataclasses import replace

from aak import (
    AuthorityBundle, Ed25519Signer, EnforcementGateway, IndependentAuthority,
    KeyRegistry, KeyStatus, Proposal, SenderProofVerifier, StrictJSONGate,
    ThresholdVerifier, create_sender_proof, make_authority_claim,
)
from aak.boundary import BoundaryError
from aak.canonical import canonical_bytes


rng = random.Random(20260916)
TOTAL_ATTEMPTS = int(os.environ.get("AAK_ATTACK_ATTEMPTS", "30000"))
if TOTAL_ATTEMPTS < 3:
    raise ValueError("AAK_ATTACK_ATTEMPTS must be at least 3")
claim_attempts = TOTAL_ATTEMPTS // 3
proof_attempts = TOTAL_ATTEMPTS // 3
parser_attempts = TOTAL_ATTEMPTS - claim_attempts - proof_attempts
proposal = Proposal(
    "tx-1", "tenant-a", "agent", "invoice", "payment.transfer",
    "account/vendor", {"amount_minor": 1000},
    {"money_minor": 1000, "operations": 1}, ("invoice-1",), ("reviewer",),
)
authority_keys = [Ed25519Signer.generate() for _ in range(3)]
authorities = [IndependentAuthority(key, lambda item: item.parameters["amount_minor"] <= 10_000) for key in authority_keys]
threshold = ThresholdVerifier(authority_keys, 2)
gateway_key = Ed25519Signer.generate()
gateway = EnforcementGateway(
    gateway_key, threshold, "payments-prod", expected_policy_hash="policy-v6",
    expected_system_version="v0.6", allow_test_time_override=True,
)

attempts = 0
unauthorized_dispatches = 0

# Adaptive claim smuggling: change one trust-bearing field and seek a quorum plus dispatch.
fields = ("tenant_id", "policy_hash", "system_version", "audience", "proposal_hash", "maximum_effect", "extra")
for index in range(claim_attempts):
    claim = make_authority_claim(
        proposal, policy_hash="policy-v6", system_version="v0.6",
        audience="payments-prod", issued_at=100, expires_at=110,
    )
    field = fields[index % len(fields)]
    if field == "tenant_id":
        claim[field] = "victim"
    elif field == "policy_hash":
        claim[field] = "attacker-policy"
    elif field == "system_version":
        claim[field] = "attacker-system"
    elif field == "audience":
        claim[field] = "admin"
    elif field == "proposal_hash":
        claim[field] = "0" * 64
    elif field == "maximum_effect":
        claim[field] = {"money_minor": 1, "operations": 1}
    else:
        claim[field] = True
    attestations = tuple(item for authority in authorities if (item := authority.attest(proposal, claim)) is not None)
    bundle = AuthorityBundle(claim, attestations)
    if gateway.dispatch(proposal, bundle, now=101) is not None:
        unauthorized_dispatches += 1
    attempts += 1

# Captured proof mutation and context substitution.
sender = Ed25519Signer.generate()
registry = KeyRegistry((KeyStatus(sender, 90, 200),))
body = canonical_bytes({"amount_minor": 1000, "transaction_id": "tx-1"})
for index in range(proof_attempts):
    verifier = SenderProofVerifier(
        registry, audience="payments", route="/v1/effects", method="POST",
        expected_subject="executor", allow_test_time_override=True,
    )
    proof = create_sender_proof(
        sender, method="POST", route="/v1/effects", audience="payments",
        body=body, issued_at=100, nonce=f"proof-{index}", subject="executor",
    )
    mode = index % 5
    if mode == 0:
        proof = replace(proof, subject="admin")
    elif mode == 1:
        proof = replace(proof, route="/v1/admin")
    elif mode == 2:
        proof = replace(proof, method="DELETE")
    elif mode == 3:
        proof = replace(proof, audience="admin")
    else:
        proof = replace(proof, body_hash="0" * 64)
    if verifier.verify(proof, body, now=101)[0]:
        unauthorized_dispatches += 1
    attempts += 1

# Parser abuse: random binary, duplicate keys, deep nesting and noncanonical encodings.
gate = StrictJSONGate(required_fields=("amount_minor", "transaction_id"), max_bytes=256, max_depth=8)
for index in range(parser_attempts):
    if index % 4 == 0:
        raw = b'{"amount_minor":1000,"amount_minor":1,"transaction_id":"tx"}'
    elif index % 4 == 1:
        raw = canonical_bytes({"amount_minor": 1000, "transaction_id": "x" * 300})
    elif index % 4 == 2:
        raw = b'{ "amount_minor":1000,"transaction_id":"tx"}'
    else:
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
    try:
        gate.parse(raw)
    except BoundaryError:
        pass
    else:
        # Random input is permitted only if it accidentally formed the exact safe schema.
        value = gate.parse(raw)
        assert canonical_bytes(value) == raw and set(value) == {"amount_minor", "transaction_id"}
    attempts += 1

assert unauthorized_dispatches == 0, unauthorized_dispatches
print(f"professional_red_team_attempts={attempts} unauthorized_acceptances=0 crashes=0")
