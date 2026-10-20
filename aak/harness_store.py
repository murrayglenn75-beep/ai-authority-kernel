"""Durable fail-closed SQLite lifecycle storage. Never authorizes tool execution."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from .harness_lifecycle import HarnessTask, Status, advance

class DurableHarnessStore:
    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise ValueError("durable path required")
        self.path = str(path)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS harness_tasks (
                task_id TEXT PRIMARY KEY, harness_id TEXT NOT NULL,
                principal_id TEXT NOT NULL, status TEXT NOT NULL,
                revision INTEGER NOT NULL, steps INTEGER NOT NULL,
                checkpoint TEXT)""")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            yield db
        finally:
            db.close()

    @staticmethod
    def _task(row):
        try:
            return HarnessTask(row[0], row[1], row[2], Status(row[3]), row[4], row[5], row[6])
        except (TypeError, ValueError, IndexError) as exc:
            raise ValueError("corrupt harness task record") from exc

    def create(self, task: HarnessTask):
        if (not isinstance(task, HarnessTask) or task.status is not Status.CREATED
                or task.revision != 0 or task.steps != 0 or task.checkpoint is not None):
            raise ValueError("task must be newly created")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO harness_tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (task.task_id, task.harness_id, task.principal_id,
                            task.status.value, task.revision, task.steps, task.checkpoint))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def load(self, task_id: str, principal_id: str) -> HarnessTask:
        with self._connect() as db:
            row = db.execute("SELECT * FROM harness_tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError("unknown task")
        task = self._task(row)
        if task.principal_id != principal_id:
            raise PermissionError("principal mismatch")
        return task

    def transition(self, task_id: str, *, principal_id: str, expected_revision: int,
                   next_status: Status, step: bool = False,
                   checkpoint: str | None = None, max_steps: int = 64) -> HarnessTask:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM harness_tasks WHERE task_id = ?", (task_id,)).fetchone()
                if row is None:
                    raise KeyError("unknown task")
                task = self._task(row)
                updated = advance(task, principal_id=principal_id,
                                  expected_revision=expected_revision,
                                  next_status=next_status, step=step,
                                  checkpoint=checkpoint, max_steps=max_steps)
                result = db.execute("""UPDATE harness_tasks SET status = ?, revision = ?,
                    steps = ?, checkpoint = ? WHERE task_id = ? AND revision = ?""",
                    (updated.status.value, updated.revision, updated.steps,
                     updated.checkpoint, task_id, task.revision))
                if result.rowcount != 1:
                    raise ValueError("concurrent modification")
                db.commit()
                return updated
            except BaseException:
                db.rollback()
                raise
