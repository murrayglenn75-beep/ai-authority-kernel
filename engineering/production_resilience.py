"""Opt-in async reliability primitives for trusted callers."""
import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")

class EmptyResultError(ValueError):
    """Required retrieval returned no usable evidence."""

@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 10.0
    attempts: int = 2
    max_concurrent: int = 4
    base_delay_seconds: float = 0.05

    def __post_init__(self):
        if self.timeout_seconds <= 0 or self.attempts < 1 or self.max_concurrent < 1 or self.base_delay_seconds < 0:
            raise ValueError("Invalid execution limits")

class BoundedExecutor:
    def __init__(self, limits: Limits):
        self.limits = limits
        self._semaphore = asyncio.Semaphore(limits.max_concurrent)

    async def run(self, operation: Callable[[], Awaitable[T]], *, retryable=(TimeoutError, ConnectionError), require_result=False) -> T:
        """Retries should be enabled only for idempotent operations."""
        async with self._semaphore:
            for attempt in range(self.limits.attempts):
                try:
                    result = await asyncio.wait_for(operation(), timeout=self.limits.timeout_seconds)
                    if require_result and (result is None or result == "" or result == []):
                        raise EmptyResultError("Empty retrieval; abstain or escalate")
                    return result
                except retryable:
                    if attempt + 1 >= self.limits.attempts:
                        raise
                    await asyncio.sleep(self.limits.base_delay_seconds * (2 ** attempt))
        raise RuntimeError("Unreachable")
