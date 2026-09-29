import secrets

from aak import AuthorityKernel, Policy, Proposal, Rule, ToolContract


policy = Policy(
    version="policy-1",
    rules=(
        Rule(
            action="message.send",
            resource_prefix="recipient/approved-",
            principals=frozenset({"user-glenn"}),
            max_effect={"messages": 1, "recipients": 1},
            authorized_approvers=frozenset(),
        ),
    ),
)

kernel = AuthorityKernel(
    signing_key=secrets.token_bytes(32),
    policy=policy,
    system_version="example-1",
    budget_limits={"messages": 10, "recipients": 10},
    tools=(ToolContract(
        action="message.send",
        validate=lambda resource, parameters: resource.startswith("recipient/approved-") and set(parameters) == {"body"},
        derive_effect=lambda _resource, _parameters: {"messages": 1, "recipients": 1},
        handler=lambda _resource, parameters: {"sent": parameters["body"]},
    ),),
    evidence_verifier=lambda evidence_id: evidence_id == "request/demo-1",
)

proposal = Proposal(
    transaction_id="demo-1",
    principal_id="user-glenn",
    agent_instance="example-agent",
    purpose="send-approved-update",
    action="message.send",
    resource="recipient/approved-client",
    parameters={"body": "Approved update"},
    maximum_effect={"messages": 1, "recipients": 1},
    evidence=("request/demo-1",),
)

decision = kernel.authorize(proposal)
assert decision.allowed and decision.capability
print(kernel.execute(proposal, decision.capability))
