"""Standalone regression checks without provider credentials."""
import os
import tempfile
from aak.runtime_store import RuntimeCheckpointStore
from aak.reliability_contract import (
    ProviderEvidence, RecoveryDecision, reconcile,
    VerifiedAAKExecutor, normalized_native_tool_call,
)
from aak.agent_runtime import (
    BoundedAgent, ModelReply, Outcome, ProviderFailure, ToolRequest,
    parse_prompt_tool_call,
)


class FakeModel:
    def __init__(self, replies):
        self.replies = iter(replies)

    def complete(self, history):
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply


def runtime(replies, **opts):
    effects, events = [], []

    def verified_effect(call, tx):
        effects.append(tx)
        return "ok"

    return (BoundedAgent(FakeModel(replies), verified_effect, events.append,
                         allowed_tools=frozenset({"read", "publish"}), **opts),
            effects, events)


def verify():
    assert parse_prompt_tool_call('{"final":"ok"}').text == "ok"
    assert parse_prompt_tool_call('{"tool":"read","arguments":{}}').calls[0].name == "read"
    for invalid in ('{"final":"a","final":"b"}', '[]',
                    '{"tool":"read","arguments":{},"surprise":true}'):
        try:
            parse_prompt_tool_call(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid model JSON accepted")

    agent, effects, events = runtime([
        ModelReply(calls=(ToolRequest("publish", {"id": 1}),), tokens=4),
        ModelReply(text="done", tokens=3)])
    assert agent.run("normal").outcome == Outcome.COMPLETE
    assert len(effects) == 1
    assert [e["phase"] for e in events] == ["pending", "completed", "complete"]

    agent, effects, _ = runtime([ProviderFailure(429, 7)])
    reply = agent.run("rate-limit")
    assert reply.outcome == Outcome.PROVIDER_RETRY_LATER
    assert reply.next_retry_seconds == 7
    assert not effects

    agent, effects, _ = runtime([ModelReply(calls=(ToolRequest("other", {}),))])
    assert agent.run("unknown-tool").outcome == Outcome.DENIED
    assert not effects

    agent, effects, _ = runtime(
        [ModelReply(calls=(ToolRequest("read", {}),))] * 5, max_steps=2)
    assert agent.run("loop").outcome == Outcome.LIMIT_REACHED
    assert len(effects) == 2

    agent, effects, _ = runtime(
        [ModelReply(calls=(ToolRequest("publish", {}),), tokens=101)], max_tokens=100)
    assert agent.run("budget").outcome == Outcome.LIMIT_REACHED
    assert not effects

    agent, effects, _ = runtime([ModelReply(calls=(ToolRequest("publish", {}),))])
    def failed_checkpoint(record):
        raise OSError("unavailable")
    agent.checkpoint = failed_checkpoint
    assert agent.run("checkpoint").outcome == Outcome.QUARANTINED
    assert not effects

    agent, effects, _ = runtime([ModelReply(calls=(ToolRequest("publish", {}),))])
    def uncertain(call, tx):
        effects.append(tx)
        raise TimeoutError("provider result unknown")
    agent.effect_executor = uncertain
    assert agent.run("ambiguous").outcome == Outcome.QUARANTINED
    assert len(effects) == 1

    with tempfile.TemporaryDirectory() as folder:
        filename = os.path.join(folder, "journal.db")
        journal = RuntimeCheckpointStore(filename)
        agent, effects, _ = runtime([ModelReply(calls=(ToolRequest("publish", {}),))])
        agent.checkpoint = journal
        # First dispatch is recorded but the model fails in the next turn.
        assert agent.run("durable").outcome == Outcome.MODEL_ERROR
        assert len(effects) == 1
        journal.close()
        journal = RuntimeCheckpointStore(filename)
        agent2, effects2, _ = runtime([ModelReply(calls=(ToolRequest("publish", {}),))])
        agent2.checkpoint = journal
        assert agent2.run("durable").outcome == Outcome.QUARANTINED
        assert not effects2
        assert journal.state("durable")[0][3] == "completed"
        journal.close()

    agent, effects, _ = runtime([
        ModelReply(calls=(ToolRequest("publish", {}),)), ProviderFailure(429, 2)])
    assert agent.run("after-effect-429").outcome == Outcome.QUARANTINED
    assert len(effects) == 1

    agent, effects, _ = runtime([ProviderFailure(429, float("nan"))])
    assert agent.run("nonfinite-delay").outcome == Outcome.PROVIDER_ERROR
    assert not effects

    txid = "a" * 64
    assert reconcile(txid, None) == RecoveryDecision.REQUIRE_OPERATOR
    good = ProviderEvidence(txid, "provider-record-1", "committed", True, True)
    assert reconcile(txid, good) == RecoveryDecision.RECORD_SUCCESS
    denied = ProviderEvidence(txid, "provider-record-2",
                              "definitively_rejected_before_effect", True, True)
    assert reconcile(txid, denied) == RecoveryDecision.RECORD_REJECTION
    for bad in (
        ProviderEvidence(txid, "ref", "committed", False, True),
        ProviderEvidence(txid, "ref", "committed", True, False),
        ProviderEvidence("b" * 64, "ref", "committed", True, True),
        ProviderEvidence(txid, "", "committed", True, True),
        ProviderEvidence(txid, "ref", "unknown", True, True),
    ):
        assert reconcile(txid, bad) == RecoveryDecision.REQUIRE_OPERATOR
    assert normalized_native_tool_call("read", {"id": 1},
                                      approved_names=frozenset({"read"})).name == "read"
    for name, args in (("evil", {}), ("read", [1]), ("read", {"x": float("nan")})):
        try:
            normalized_native_tool_call(name, args, approved_names=frozenset({"read"}))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid native call accepted")
    called = []
    executor = VerifiedAAKExecutor(
        lambda call, tx: "signed-grant",
        lambda grant, call, tx: called.append((grant, call.name, tx)))
    executor(ToolRequest("read", {}), txid)
    assert called == [("signed-grant", "read", txid)]
    blocked = VerifiedAAKExecutor(lambda call, tx: None, lambda grant, call, tx: called.append(1))
    try:
        blocked(ToolRequest("read", {}), txid)
    except PermissionError:
        pass
    else:
        raise AssertionError("missing authorization was accepted")
    assert len(called) == 1

    agent, effects, _ = runtime([ModelReply(calls=(
        ToolRequest("publish", {"safe": 1}),
        ToolRequest("forbidden", {})))])
    assert agent.run("batch-preflight").outcome == Outcome.DENIED
    assert not effects

    agent, effects, _ = runtime([ModelReply(calls=(
        ToolRequest("publish", {"payload": "a" * 20000}),))])
    assert agent.run("oversize").outcome == Outcome.DENIED
    assert not effects

    agent, effects, _ = runtime([ModelReply(calls=(
        ToolRequest("publish", {"x": 1}),), tokens=True)])
    assert agent.run("boolean-tokens").outcome == Outcome.MODEL_ERROR
    assert not effects

    for error in (ProviderFailure(503), RuntimeError("model malformed"), ProviderFailure(429, float("nan"))):
        agent, effects, _ = runtime([
            ModelReply(calls=(ToolRequest("publish", {}),)), error])
        assert agent.run("post-effect-error").outcome == Outcome.QUARANTINED
        assert len(effects) == 1

    agent, effects, _ = runtime([RuntimeError("malformed model adapter")])
    assert agent.run("adapter").outcome == Outcome.MODEL_ERROR
    assert not effects


if __name__ == "__main__":
    verify()
    print("Agent runtime smoke and defensive checks passed")
