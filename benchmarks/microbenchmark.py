import secrets
import statistics
import time

from aak import AuthorityKernel, Ed25519Signer, Policy, Proposal, Rule, ToolContract


tool = ToolContract(
    "operation.run",
    lambda resource, params: resource.startswith("resource/") and set(params) == {"units"},
    lambda _resource, params: {"operations": 1, "units": params["units"]},
    lambda _resource, params: {"processed": params["units"]},
)
policy = Policy("p1", (Rule("operation.run", "resource/", frozenset({"bench"}), {"operations": 1, "units": 1}),))
kernel = AuthorityKernel(
    signer=Ed25519Signer.generate(),
    policy=policy,
    system_version="s1",
    budget_limits={"operations": 100_000, "units": 100_000},
    tools=(tool,),
    evidence_verifier=lambda evidence_id: evidence_id == "benchmark",
)


def proposal(index: int) -> Proposal:
    return Proposal(
        transaction_id=f"tx-{index}", principal_id="bench", agent_instance="bench-agent",
        purpose="benchmark", action="operation.run", resource="resource/1",
        parameters={"units": 1}, maximum_effect={"operations": 1, "units": 1},
        evidence=("benchmark",),
    )


authorize_ms = []
execute_ms = []
for index in range(10_000):
    item = proposal(index)
    start = time.perf_counter_ns()
    decision = kernel.authorize(item)
    authorize_ms.append((time.perf_counter_ns() - start) / 1_000_000)
    if index < 1_000:
        start = time.perf_counter_ns()
        result = kernel.execute(item, decision.capability)
        execute_ms.append((time.perf_counter_ns() - start) / 1_000_000)
        assert result.allowed


def percentile(values: list[float], percent: float) -> float:
    return sorted(values)[min(len(values) - 1, int(len(values) * percent))]


print(f"authorize_count=10000 p50_ms={statistics.median(authorize_ms):.4f} p95_ms={percentile(authorize_ms, .95):.4f} p99_ms={percentile(authorize_ms, .99):.4f}")
print(f"execute_count=1000 p50_ms={statistics.median(execute_ms):.4f} p95_ms={percentile(execute_ms, .95):.4f} p99_ms={percentile(execute_ms, .99):.4f}")
