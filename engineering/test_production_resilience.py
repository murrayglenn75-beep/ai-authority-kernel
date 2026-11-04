import asyncio
import unittest
from production_resilience import BoundedExecutor, EmptyResultError, Limits

class ReliabilityChecks(unittest.IsolatedAsyncioTestCase):
    async def test_success(self):
        async def operation():
            return "ok"
        self.assertEqual(await BoundedExecutor(Limits()).run(operation), "ok")

    async def test_empty_result(self):
        async def operation():
            return []
        with self.assertRaises(EmptyResultError):
            await BoundedExecutor(Limits()).run(operation, require_result=True)

    async def test_no_retry_on_denial(self):
        calls = 0
        async def operation():
            nonlocal calls
            calls += 1
            raise PermissionError("denied")
        with self.assertRaises(PermissionError):
            await BoundedExecutor(Limits()).run(operation)
        self.assertEqual(calls, 1)

    async def test_timeout(self):
        async def operation():
            await asyncio.sleep(.03)
        with self.assertRaises(TimeoutError):
            await BoundedExecutor(Limits(timeout_seconds=.001, attempts=1)).run(operation)

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            Limits(max_concurrent=0)

if __name__ == "__main__":
    unittest.main()
