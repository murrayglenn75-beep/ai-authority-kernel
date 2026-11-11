import tempfile
import unittest
from pathlib import Path
from aak.action_gateway import ToolCall
from aak.harness_lifecycle import HarnessTask, Status, advance
from aak.harness_bridge import prepare_tool_call, prepare_from_store
from aak.harness_store import DurableHarnessStore


class HarnessBridgeTests(unittest.TestCase):
    def setUp(self):
        self.running = HarnessTask('t1', 'apex', 'alice', status=Status.RUNNING, revision=1)
        self.call = ToolCall(protocol='native', call_id='c1', action='read',
                             resource='project', audience='local',
                             parameters={'path': 'README.md'})

    def prepare(self, **overrides):
        kw = dict(task=self.running, principal_id='alice',
                  expected_revision=1, call=self.call)
        kw.update(overrides)
        return prepare_tool_call(**kw)

    def test_matches_canonical_aak_hash(self):
        out = self.prepare()
        self.assertEqual(out.request_hash, self.call.request_hash)
        self.assertEqual(out.task_revision, 1)

    def test_no_grant_or_execution(self):
        out = self.prepare()
        self.assertFalse(hasattr(out, 'grant'))
        self.assertFalse(hasattr(out, 'execute'))

    def test_waiting_approval_cannot_prepare(self):
        with self.assertRaises(PermissionError):
            self.prepare(task=HarnessTask('t1', 'apex', 'alice', status=Status.WAITING_APPROVAL, revision=1))

    def test_cancelled_cannot_prepare(self):
        with self.assertRaises(PermissionError):
            self.prepare(task=HarnessTask('t1', 'apex', 'alice', status=Status.CANCELLED, revision=1))

    def test_identity_mismatch(self):
        with self.assertRaises(PermissionError):
            self.prepare(principal_id='bob')

    def test_stale_revision(self):
        with self.assertRaises(ValueError):
            self.prepare(expected_revision=0)

    def test_invalid_toolcall_type(self):
        with self.assertRaises(ValueError):
            self.prepare(call={'action': 'read'})

    def test_invalid_protocol_rejected_by_aak(self):
        bad = ToolCall(protocol='invalid', call_id='c1', action='read',
                       resource='project', audience='local', parameters={})
        with self.assertRaises(ValueError):
            self.prepare(call=bad)


    def test_persisted_state_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableHarnessStore(Path(tmp) / 'tasks.sqlite')
            store.create(HarnessTask('t1', 'apex', 'alice'))
            store.transition('t1', principal_id='alice', expected_revision=0,
                             next_status=Status.RUNNING)
            out = prepare_from_store(store=store, task_id='t1', principal_id='alice',
                                     expected_revision=1, call=self.call)
            self.assertEqual(out.request_hash, self.call.request_hash)

    def test_persisted_stale_revision_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableHarnessStore(Path(tmp) / 'tasks.sqlite')
            store.create(HarnessTask('t1', 'apex', 'alice'))
            store.transition('t1', principal_id='alice', expected_revision=0,
                             next_status=Status.RUNNING)
            with self.assertRaises(ValueError):
                prepare_from_store(store=store, task_id='t1', principal_id='alice',
                                   expected_revision=0, call=self.call)

    def test_persisted_cancelled_state_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableHarnessStore(Path(tmp) / 'tasks.sqlite')
            store.create(HarnessTask('t1', 'apex', 'alice'))
            store.transition('t1', principal_id='alice', expected_revision=0,
                             next_status=Status.CANCELLED)
            with self.assertRaises(PermissionError):
                prepare_from_store(store=store, task_id='t1', principal_id='alice',
                                   expected_revision=1, call=self.call)

    def test_persisted_cross_principal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableHarnessStore(Path(tmp) / 'tasks.sqlite')
            store.create(HarnessTask('t1', 'apex', 'alice'))
            with self.assertRaises(PermissionError):
                prepare_from_store(store=store, task_id='t1', principal_id='bob',
                                   expected_revision=0, call=self.call)


if __name__ == '__main__':
    unittest.main()
