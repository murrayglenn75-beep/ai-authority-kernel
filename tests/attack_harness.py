"""Black-box hostile-input exercise. Success means zero unauthorized effects."""

import random
import secrets
import string
from dataclasses import replace

from aak import AuthorityKernel, Ed25519Signer, Policy, Proposal, Rule, ToolContract


effects = 0


def handler(_resource, _parameters):
    global effects
    effects += 1
    return {"ok": True}


tool = ToolContract(
    "payment.transfer",
    lambda resource, params: resource == "account/vendor" and set(params) == {"amount"},
    lambda _resource, params: {"money": float(params["amount"]), "operations": 1},
    handler,
)
policy = Policy("p1", (Rule(
    "payment.transfer", "account/", frozenset({"glenn"}),
    {"money": 100, "operations": 1}, 1, frozenset({"reviewer"}),
),))
kernel = AuthorityKernel(
    signer=Ed25519Signer.generate(), policy=policy, system_version="s1",
    budget_limits={"money": 10_000, "operations": 10_000}, tools=(tool,),
    evidence_verifier=lambda item: item == "verified-invoice",
    allow_test_time_override=True,
)
proposal = Proposal(
    "tx-1", "glenn", "agent", "invoice", "payment.transfer", "account/vendor",
    {"amount": 10}, {"money": 10, "operations": 1}, ("verified-invoice",), ("reviewer",),
)
token = kernel.authorize(proposal, now=100).capability
assert token

rng = random.Random(20260911)
alphabet = string.ascii_letters + string.digits + "-_"

# Signed-token mutations must never execute.
for _ in range(10_000):
    chars = list(token)
    index = rng.randrange(len(chars))
    choices = alphabet.replace(chars[index], "") if chars[index] in alphabet else alphabet
    chars[index] = rng.choice(choices)
    result = kernel.execute(proposal, "".join(chars), now=101)
    assert not result.allowed

# Exact-contract substitutions must never execute with an otherwise valid token.
mutations = (
    replace(proposal, principal_id="attacker"),
    replace(proposal, resource="account/attacker"),
    replace(proposal, action="system.shell"),
    replace(proposal, parameters={"amount": 1000}),
    replace(proposal, maximum_effect={"money": 1, "operations": 1}),
    replace(proposal, evidence=("fake",)),
    replace(proposal, approvals=("attacker",)),
    replace(proposal, transaction_id="other"),
)
for item in mutations:
    assert not kernel.execute(item, token, now=101).allowed

# Random garbage must fail closed without crashing.
for _ in range(10_000):
    garbage = "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 300)))
    assert not kernel.execute(proposal, garbage, now=101).allowed

assert effects == 0, f"unauthorized effects occurred: {effects}"
assert kernel.execute(proposal, token, now=101).allowed
assert effects == 1
assert not kernel.execute(proposal, token, now=101).allowed
assert effects == 1

print("attacks=20008 unauthorized_effects=0 authorized_effects=1 replay_effects=0")
