"""Bounded model-to-tool orchestrator. Not an authorization implementation.

The effect_executor MUST be the independently verifying AAK boundary, never a
raw provider SDK. A checkpoint writer must be durable and fail closed.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Protocol


class Outcome(str, Enum):
    COMPLETE = "complete"
    DENIED = "denied"
    PROVIDER_RETRY_LATER = "provider_retry_later"
    PROVIDER_ERROR = "provider_error"
    MODEL_ERROR = "model_error"
    LIMIT_REACHED = "limit_reached"
    QUARANTINED = "quarantined"


class ProviderFailure(Exception):
    """Raised by a MODEL adapter before any tool/effect is dispatched."""

    def __init__(self, status: int | None = None, retry_after: float | None = None):
        self.status = status
        self.retry_after = retry_after
        super().__init__(f"model provider status {status}")


@dataclass(frozen=True)
class ToolRequest:
    name: str
    arguments: Mapping[str, object]


@dataclass(frozen=True)
class ModelReply:
    text: str = ""
    calls: tuple[ToolRequest, ...] = ()
    tokens: int = 0


@dataclass(frozen=True)
class RunResult:
    outcome: Outcome
    steps: int
    tokens: int
    detail: str = ""
    next_retry_seconds: float | None = None


class ModelAdapter(Protocol):
    def complete(self, history: tuple[dict, ...]) -> ModelReply: ...


def parse_prompt_tool_call(data: str, *, max_bytes: int = 16384) -> ModelReply:
    """Strict opt-in prompt-JSON adapter; never silently substitute for native tools."""
    if len(data.encode("utf-8")) > max_bytes:
        raise ValueError("oversize tool reply")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    obj = json.loads(data, object_pairs_hook=unique_pairs,
                     parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))
    if not isinstance(obj, dict) or set(obj) not in ({"final"}, {"tool", "arguments"}):
        raise ValueError("unknown reply schema")
    if "final" in obj:
        if not isinstance(obj["final"], str):
            raise ValueError("final must be a string")
        return ModelReply(text=obj["final"])
    if not isinstance(obj["tool"], str) or not obj["tool"] or not isinstance(obj["arguments"], dict):
        raise ValueError("invalid tool call")
    return ModelReply(calls=(ToolRequest(obj["tool"], obj["arguments"]),))


def _canonical(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False)


class BoundedAgent:
    """One-run state machine. Never automatically resume an ambiguous effect.

    Model adapter selection is an explicit operator configuration. Provider rate
    limiting returns control to scheduler; tool failures are never retried here.
    """

    def __init__(
        self, model: ModelAdapter, effect_executor: Callable[[ToolRequest, str], object],
        checkpoint: Callable[[dict], None], *,
        allowed_tools: frozenset[str], max_steps: int = 8,
        max_tokens: int = 12000, max_seconds: float = 120.0,
        max_calls_per_reply: int = 4, clock: Callable[[], float] = time.monotonic,
    ):
        if not allowed_tools or max_steps < 1 or max_tokens < 1 or max_seconds <= 0 or max_calls_per_reply < 1:
            raise ValueError("invalid operator-owned limits")
        self.model, self.effect_executor, self.checkpoint = model, effect_executor, checkpoint
        self.allowed_tools = allowed_tools
        self.max_steps, self.max_tokens = max_steps, max_tokens
        self.max_seconds, self.max_calls_per_reply = max_seconds, max_calls_per_reply
        self.clock = clock

    def run(self, run_id: str, initial_history: tuple[dict, ...] = ()) -> RunResult:
        if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
            raise ValueError("invalid run_id")
        history = list(initial_history)
        start = self.clock()
        tokens = 0

        def result(kind, step, detail="", delay=None):
            return RunResult(kind, step, tokens, detail, delay)

        for step in range(1, self.max_steps + 1):
            if self.clock() - start >= self.max_seconds:
                return result(Outcome.LIMIT_REACHED, step - 1, "deadline")
            try:
                reply = self.model.complete(tuple(history))
            except ProviderFailure as exc:
                if exc.status == 429:
                    delay = exc.retry_after if exc.retry_after is not None else 1.0
                    if not isinstance(delay, (int, float)) or not 0 <= delay <= 3600:
                        return result(Outcome.PROVIDER_ERROR, step, "invalid retry-after")
                    return result(Outcome.PROVIDER_RETRY_LATER, step, "rate limited; no effect attempted", float(delay))
                return result(Outcome.PROVIDER_ERROR, step, "model provider failure")
            except Exception:
                return result(Outcome.MODEL_ERROR, step, "model adapter failure")
            if not isinstance(reply, ModelReply) or not isinstance(reply.tokens, int) or reply.tokens < 0:
                return result(Outcome.MODEL_ERROR, step, "invalid model response")
            tokens += reply.tokens
            if tokens > self.max_tokens or self.clock() - start >= self.max_seconds:
                return result(Outcome.LIMIT_REACHED, step, "budget or deadline")
            if reply.calls and (reply.text or len(reply.calls) > self.max_calls_per_reply):
                return result(Outcome.MODEL_ERROR, step, "mixed or excessive model actions")
            if not reply.calls:
                if not isinstance(reply.text, str):
                    return result(Outcome.MODEL_ERROR, step, "invalid final text")
                try:
                    self.checkpoint({"run_id": run_id, "step": step, "phase": "complete"})
                except Exception:
                    return result(Outcome.QUARANTINED, step, "checkpoint unavailable")
                return result(Outcome.COMPLETE, step, reply.text)
            for index, call in enumerate(reply.calls):
                if not isinstance(call, ToolRequest) or call.name not in self.allowed_tools:
                    return result(Outcome.DENIED, step, "unregistered tool")
                try:
                    args = _canonical(call.arguments)
                except (TypeError, ValueError, OverflowError):
                    return result(Outcome.DENIED, step, "invalid tool arguments")
                digest = hashlib.sha256((run_id + "\x00" + str(step) + "\x00" + str(index) +
                                         "\x00" + call.name + "\x00" + args).encode()).hexdigest()
                # Durable checkpoint BEFORE any potentially consequential effect.
                try:
                    self.checkpoint({"run_id": run_id, "step": step, "call": index,
                                     "phase": "pending", "transaction_id": digest})
                except Exception:
                    return result(Outcome.QUARANTINED, step, "pre-effect checkpoint unavailable")
                try:
                    output = self.effect_executor(call, digest)
                except Exception:
                    # Failure may have happened after provider commit. Never retry.
                    return result(Outcome.QUARANTINED, step, "effect outcome uncertain; reconcile externally")
                try:
                    self.checkpoint({"run_id": run_id, "step": step, "call": index,
                                     "phase": "completed", "transaction_id": digest})
                except Exception:
                    return result(Outcome.QUARANTINED, step, "completion checkpoint unavailable")
                history.append({"role": "tool", "name": call.name, "transaction_id": digest,
                                "result": str(output)[:8192]})
        return result(Outcome.LIMIT_REACHED, self.max_steps, "max model turns reached")
