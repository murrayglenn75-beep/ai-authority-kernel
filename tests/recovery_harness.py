"""Independent multi-process recovery *model*, not integration with AAK production services.

Run: python tests/recovery_harness.py
SQLite simulates durable command state and a persistent idempotent mock provider.
"""
import multiprocessing as mp
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

def dbopen(path):
    c=sqlite3.connect(path,timeout=10,isolation_level=None)
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def setup(path):
    c=dbopen(path)
    try:
        c.executescript("""CREATE TABLE commands(id TEXT PRIMARY KEY,payload TEXT NOT NULL,state TEXT NOT NULL,epoch INTEGER NOT NULL);
CREATE TABLE effects(id TEXT PRIMARY KEY,payload TEXT NOT NULL);""")
    finally:
        c.close()

def row(path,sql):
    c=dbopen(path)
    try: return c.execute(sql).fetchone()
    finally: c.close()

def submit(path,tx,payload):
    c=dbopen(path)
    try:
        c.execute("BEGIN IMMEDIATE")
        old=c.execute("SELECT payload FROM commands WHERE id=?",(tx,)).fetchone()
        if old and old[0]!=payload: raise ValueError("idempotency-conflict")
        if not old: c.execute("INSERT INTO commands VALUES (?,?,?,0)",(tx,payload,"PREPARED"))
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally: c.close()

def lease(path,tx):
    c=dbopen(path)
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute("UPDATE commands SET epoch=epoch+1 WHERE id=? AND state NOT IN ('COMMITTED','REJECTED')",(tx,))
        epoch=c.execute("SELECT epoch FROM commands WHERE id=?",(tx,)).fetchone()[0]
        c.commit()
        return epoch
    finally: c.close()

def transition(path,tx,epoch,state):
    c=dbopen(path)
    try:
        c.execute("BEGIN IMMEDIATE")
        changed=c.execute("UPDATE commands SET state=? WHERE id=? AND epoch=? AND state NOT IN ('COMMITTED','REJECTED')",(state,tx,epoch)).rowcount
        c.commit()
        return bool(changed)
    finally: c.close()

def effect(path,tx,payload,drop=False):
    c=dbopen(path)
    try:
        c.execute("BEGIN IMMEDIATE")
        old=c.execute("SELECT payload FROM effects WHERE id=?",(tx,)).fetchone()
        if old and old[0]!=payload: raise ValueError("provider-idempotency-conflict")
        c.execute("INSERT OR IGNORE INTO effects VALUES (?,?)",(tx,payload))
        c.commit()
    finally: c.close()
    if drop: os._exit(23)

def worker(path,tx,payload,epoch):
    if transition(path,tx,epoch,"SUBMITTED"):
        effect(path,tx,payload,drop=True)

def reconcile(path,tx,epoch):
    c=dbopen(path)
    try:
        expected=c.execute("SELECT payload FROM commands WHERE id=?",(tx,)).fetchone()
        found=c.execute("SELECT payload FROM effects WHERE id=?",(tx,)).fetchone()
    finally: c.close()
    if not found: return transition(path,tx,epoch,"RECONCILIATION_REQUIRED")
    if not expected or found[0]!=expected[0]: raise ValueError("provider-mismatch")
    return transition(path,tx,epoch,"COMMITTED")

class RecoveryModelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.temp.name)/"recovery.sqlite")
        setup(self.path)
    def tearDown(self): self.temp.cleanup()

    def test_commit_then_lost_ack_crash_and_reconcile(self):
        submit(self.path,"tx1","payload")
        epoch=lease(self.path,"tx1")
        p=mp.Process(target=worker,args=(self.path,"tx1","payload",epoch))
        p.start()
        p.join(10)
        if p.is_alive():
            p.terminate()
            p.join()
            self.fail("worker timeout")
        self.assertEqual(p.exitcode,23)
        self.assertEqual(row(self.path,"SELECT count(*) FROM effects")[0],1)
        self.assertTrue(reconcile(self.path,"tx1",epoch))
        self.assertEqual(row(self.path,"SELECT state FROM commands")[0],"COMMITTED")

    def test_conflicting_replay_denied(self):
        submit(self.path,"tx2","original")
        with self.assertRaisesRegex(ValueError,"idempotency-conflict"):
            submit(self.path,"tx2","modified")

    def test_old_epoch_cannot_commit(self):
        submit(self.path,"tx3","payload")
        old=lease(self.path,"tx3")
        new=lease(self.path,"tx3")
        self.assertFalse(transition(self.path,"tx3",old,"SUBMITTED"))
        self.assertTrue(transition(self.path,"tx3",new,"SUBMITTED"))

    def test_unknown_provider_outcome_remains_unresolved(self):
        submit(self.path,"tx4","payload")
        epoch=lease(self.path,"tx4")
        self.assertTrue(reconcile(self.path,"tx4",epoch))
        self.assertEqual(row(self.path,"SELECT state FROM commands")[0],"RECONCILIATION_REQUIRED")

    def test_mock_provider_deduplicates(self):
        submit(self.path,"tx5","payload")
        effect(self.path,"tx5","payload")
        effect(self.path,"tx5","payload")
        self.assertEqual(row(self.path,"SELECT count(*) FROM effects")[0],1)
        with self.assertRaisesRegex(ValueError,"provider-idempotency-conflict"):
            effect(self.path,"tx5","changed")

if __name__=="__main__":
    unittest.main(verbosity=2)
