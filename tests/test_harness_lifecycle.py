import unittest
from aak.harness_lifecycle import HarnessTask, Status, advance


class TestHarnessLifecycle(unittest.TestCase):
    def setUp(self):
        self.task = HarnessTask('task-1', 'local-harness', 'owner')

    def move(self, task, status, **kwargs):
        return advance(task, expected_revision=task.revision,
                       next_status=status, principal_id='owner', **kwargs)

    def test_normal_and_approval_flow(self):
        a = self.move(self.task, Status.RUNNING, step=True, checkpoint='cp-1')
        b = self.move(a, Status.WAITING_APPROVAL)
        c = self.move(b, Status.RUNNING)
        d = self.move(c, Status.COMPLETED)
        self.assertEqual((d.revision, d.steps, d.checkpoint), (4, 1, 'cp-1'))

    def test_no_execution_authority(self):
        self.assertFalse(hasattr(self.task, 'execute'))
        self.assertFalse(hasattr(self.task, 'authorization_grant'))

    def test_terminal_replay_denied(self):
        a = self.move(self.task, Status.CANCELLED)
        with self.assertRaises(ValueError):
            self.move(a, Status.RUNNING)

    def test_stale_revision_denied(self):
        with self.assertRaises(ValueError):
            advance(self.task, expected_revision=9, next_status=Status.RUNNING, principal_id='owner')

    def test_cross_principal_denied(self):
        with self.assertRaises(PermissionError):
            advance(self.task, expected_revision=0, next_status=Status.RUNNING, principal_id='other')

    def test_budget_denied(self):
        with self.assertRaises(ValueError):
            self.move(self.task, Status.RUNNING, step=True, max_steps=0)

    def test_invalid_status_denied(self):
        with self.assertRaises(ValueError):
            advance(self.task, expected_revision=0, next_status='running', principal_id='owner')

    def test_step_disallowed_outside_running(self):
        with self.assertRaises(ValueError):
            self.move(self.task, Status.CANCELLED, step=True)

    def test_invalid_identifier_denied(self):
        with self.assertRaises(ValueError):
            HarnessTask('task\n1', 'h', 'owner')

    def test_waiting_cannot_finish_without_resume(self):
        a = self.move(self.task, Status.RUNNING)
        b = self.move(a, Status.WAITING_APPROVAL)
        with self.assertRaises(ValueError):
            self.move(b, Status.COMPLETED)


if __name__ == '__main__':
    unittest.main()
