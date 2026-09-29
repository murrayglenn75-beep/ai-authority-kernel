"""Deterministic hostile mutations against external assurance boundaries."""

import os
from dataclasses import replace

from aak import (
    Ed25519Signer, ExternalPolicyIssuer, ExternalPolicyVerifier, Proposal,
    WorkloadIdentityIssuer, WorkloadIdentityVerifier,
)


ATTEMPTS = int(os.environ.get("AAK_ASSURANCE_ATTEMPTS", "100000"))
if ATTEMPTS < 2:
    raise ValueError("AAK_ASSURANCE_ATTEMPTS must be at least 2")

proposal = Proposal(
    "tx-1", "tenant-a", "agent-a", "invoice", "payment.transfer",
    "account/vendor", {"amount_minor": 1000}, {"money_minor": 1000},
    ("invoice-1",), ("reviewer",),
)
policy_key = Ed25519Signer.generate()
identity_key = Ed25519Signer.generate()
policy = ExternalPolicyIssuer(policy_key).issue(
    decision_id="decision-original", proposal=proposal, allowed=True,
    policy_hash="policy-a", policy_revision=10, audience="payments",
    issued_at=100, expires_at=110,
)
identity = WorkloadIdentityIssuer(identity_key).issue(
    assertion_id="identity-original", spiffe_id="spiffe://example.org/executor",
    trust_domain="example.org", audience="payments",
    certificate_fingerprint="sha256:trusted", channel_binding="request-a",
    issued_at=100, expires_at=110,
)

policy_mutations = (
    lambda x, i: replace(x, decision_id=f"forged-{i}"),
    lambda x, _i: replace(x, allowed=False),
    lambda x, _i: replace(x, policy_hash="attacker"),
    lambda x, _i: replace(x, policy_revision=11),
    lambda x, _i: replace(x, audience="admin"),
    lambda x, _i: replace(x, expires_at=999999),
    lambda x, _i: replace(x, proposal_hash="0" * 64),
    lambda x, _i: replace(x, schema_version=2),
)
identity_mutations = (
    lambda x, i: replace(x, assertion_id=f"forged-{i}"),
    lambda x, _i: replace(x, spiffe_id="spiffe://evil.example/admin"),
    lambda x, _i: replace(x, trust_domain="evil.example"),
    lambda x, _i: replace(x, audience="admin"),
    lambda x, _i: replace(x, certificate_fingerprint="sha256:evil"),
    lambda x, _i: replace(x, channel_binding="request-b"),
    lambda x, _i: replace(x, expires_at=999999),
    lambda x, _i: replace(x, schema_version=2),
)

unauthorized = 0
crashes = 0
policy_verifier = ExternalPolicyVerifier(
    policy_key, audience="payments", expected_policy_hash="policy-a",
)
identity_verifier = WorkloadIdentityVerifier(
    identity_key, expected_spiffe_id="spiffe://example.org/executor",
    trust_domain="example.org", audience="payments",
)
for index in range(ATTEMPTS):
    try:
        if index % 2 == 0:
            mutated = policy_mutations[(index // 2) % len(policy_mutations)](policy, index)
            accepted, _ = policy_verifier.verify(mutated, proposal, now=101)
        else:
            mutated = identity_mutations[(index // 2) % len(identity_mutations)](identity, index)
            accepted, _ = identity_verifier.verify(mutated, now=101, expected_channel_binding="request-a")
        unauthorized += int(accepted)
    except Exception:
        crashes += 1

if unauthorized or crashes:
    raise SystemExit(f"assurance_red_team_failed unauthorized={unauthorized} crashes={crashes}")
print(f"assurance_red_team_attempts={ATTEMPTS} unauthorized_acceptances=0 crashes=0")
