"""Offline evaluation gate for candidate agent-harness changes.

Only independently measured results belong here. This component never
runs tools, modifies policies, or deploys a candidate.
"""
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Evaluation:
    cases: Mapping[str, bool]
    security_failures: int
    latency_ms: int
    tokens: int

    def __post_init__(self):
        if not isinstance(self.cases, Mapping) or not self.cases or any(
            not isinstance(k, str) or not k or type(v) is not bool
            for k, v in self.cases.items()
        ):
            raise ValueError("invalid cases")
        if any(type(n) is not int or n < 0 for n in (
            self.security_failures, self.latency_ms, self.tokens
        )):
            raise ValueError("invalid measurement")


@dataclass(frozen=True)
class GateDecision:
    accepted: bool
    reasons: tuple[str, ...]


def compare(baseline: Evaluation, candidate: Evaluation,
            *, max_latency_growth_percent: int = 20,
            max_token_growth_percent: int = 20) -> GateDecision:
    """Fail closed when the evaluation set changes or any previous success fails."""
    if not isinstance(baseline, Evaluation) or not isinstance(candidate, Evaluation):
        raise ValueError("invalid evaluations")
    if any(type(v) is not int or v < 0 for v in (
        max_latency_growth_percent, max_token_growth_percent
    )):
        raise ValueError("invalid growth limits")
    reasons: list[str] = []
    if set(baseline.cases) != set(candidate.cases):
        reasons.append("evaluation corpus changed")
    if any(not candidate.cases.get(k, False) for k, passed in baseline.cases.items() if passed):
        reasons.append("previously passing case regressed")
    if candidate.security_failures != 0 or baseline.security_failures != 0:
        reasons.append("security failure present")
    if sum(candidate.cases.values()) <= sum(baseline.cases.values()):
        reasons.append("no demonstrated improvement")
    if candidate.latency_ms * 100 > baseline.latency_ms * (100 + max_latency_growth_percent):
        reasons.append("latency budget exceeded")
    if candidate.tokens * 100 > baseline.tokens * (100 + max_token_growth_percent):
        reasons.append("token budget exceeded")
    return GateDecision(not reasons, tuple(reasons))
