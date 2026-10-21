"""Reproducible synthetic agent failure matrix (not real model benchmark).

Run: python benchmark_agent_reliability.py
"""
from __future__ import annotations

import json
from aak.agent_runtime import (
    BoundedAgent, ModelReply, Outcome, ProviderFailure, ToolRequest
)
from aak.reliability_contract import (
    ProviderEvidence, RecoveryDecision, reconcile, normalized_native_tool_call
)


class DeterministicModel:
    def __init__(self, events):
        self.events = iter(events)

    def complete(self, history):
        event = next(self.events)
        if isinstance(event, BaseException):
            raise event
        return event


def evaluate(label, replies, expected, *, fail_effect=False, max_steps=4):
    effects = []
    journal = []

    def dispatch(call, tx):
        effects.append(tx)
        if fail_effect:
            raise TimeoutError("unknown remote outcome")
        return "ok"

    agent = BoundedAgent(
        DeterministicModel(replies), dispatch, journal.append,
        allowed_tools=frozenset({"read", "publish"}),
        max_steps=max_steps, max_tokens=200
    )
    result = agent.run(label)
    assert result.outcome == expected, (label, result.outcome, expected)
    return {"scenario": label, "outcome": result.outcome.value,
            "effects_dispatched": len(effects), "steps": result.steps}


def main():
    sample = ToolRequest("publish", {"item": "demo"})
    scenarios = [
        evaluate("clean", [ModelReply(calls=(sample,), tokens=3),
                           ModelReply(text="done", tokens=4)], Outcome.COMPLETE),
        evaluate("provider_429", [ProviderFailure(429, 2)], Outcome.PROVIDER_RETRY_LATER),
        evaluate("provider_503", [ProviderFailure(503)], Outcome.PROVIDER_ERROR),
        evaluate("model_exception", [ValueError("invalid result")], Outcome.MODEL_ERROR),
        evaluate("unknown_tool", [ModelReply(calls=(ToolRequest("forbidden", {}),))], Outcome.DENIED),
        evaluate("ambiguous_effect", [ModelReply(calls=(sample,))], Outcome.QUARANTINED, fail_effect=True),
        evaluate("post_effect_429", [ModelReply(calls=(sample,)),
                                    ProviderFailure(429, 4)], Outcome.QUARANTINED),
        evaluate("loop", [ModelReply(calls=(ToolRequest("read", {}),))] * 6,
                 Outcome.LIMIT_REACHED, max_steps=3)
    ]
    tx = "a" * 64
    assert reconcile(tx, ProviderEvidence(
        tx, "p", "committed", True, True
    )) == RecoveryDecision.RECORD_SUCCESS
    assert reconcile(tx, ProviderEvidence(
        tx, "p", "committed", False, True
    )) == RecoveryDecision.REQUIRE_OPERATOR
    for payload in ({"x": float("nan")}, {"unexpected": object()}):
        try:
            normalized_native_tool_call("read", payload, approved_names=frozenset({"read"}))
        except ValueError:
            pass
        else:
            raise AssertionError("malformed native arguments accepted")
    print(json.dumps({"kind": "synthetic_fixture_only",
                      "scenario_count": len(scenarios), "scenarios": scenarios}, indent=2))


if __name__ == "__main__":
    main()
