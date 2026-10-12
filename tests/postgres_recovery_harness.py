"""PostgreSQL process-crash recovery *test model* with a durable mock provider.

Requires PostgreSQL and psycopg; run on a disposable database ONLY.
Not wired to the production AAK broker or FORGE services.
"""
import multiprocessing
import os
import unittest
import uuid

import psycopg

DSN=os.environ.get("AAK_RECOVERY_TEST_DSN")
if not DSN:
    raise SystemExit("AAK_RECOVERY_TEST_DSN required (disposable PostgreSQL database)")

def connect():
    return psycopg.connect(DSN,autocommit=False)

def init(prefix):
    with connect() as c:
        c.execute(f"CREATE TABLE {prefix}_commands (id TEXT PRIMARY KEY,payload TEXT NOT NULL,epoch BIGINT NOT NULL DEFAULT 0,state TEXT NOT NULL)")
        c.execute(f"CREATE TABLE {prefix}_provider (id TEXT PRIMARY KEY,payload TEXT NOT NULL)")
        c.commit()

def clean(prefix):
    with connect() as c:
        c.execute(f"DROP TABLE IF EXISTS {prefix}_provider")
        c.execute(f"DROP TABLE IF EXISTS {prefix}_commands")
        c.commit()

def prepare(prefix,tx,payload):
    with connect() as c:
        c.execute(f"INSERT INTO {prefix}_commands(id,payload,state) VALUES(%s,%s,'PREPARED') ON CONFLICT (id) DO NOTHING",(tx,payload))
        value=c.execute(f"SELECT payload FROM {prefix}_commands WHERE id=%s",(tx,)).fetchone()[0]
        if value!=payload: raise ValueError("idempotency-conflict")
        c.commit()

def lease(prefix,tx):
    with connect() as c:
        value=c.execute(f"UPDATE {prefix}_commands SET epoch=epoch+1 WHERE id=%s AND state NOT IN ('COMMITTED','REJECTED') RETURNING epoch",(tx,)).fetchone()
        c.commit()
        return value[0] if value else None

def transition(prefix,tx,epoch,state):
    with connect() as c:
        result=c.execute(f"UPDATE {prefix}_commands SET state=%s WHERE id=%s AND epoch=%s AND state NOT IN ('COMMITTED','REJECTED') RETURNING id",(state,tx,epoch)).fetchone()
        c.commit()
        return result is not None

def provider(prefix,tx,payload,crash=False):
    with connect() as c:
        c.execute(f"INSERT INTO {prefix}_provider VALUES(%s,%s) ON CONFLICT (id) DO NOTHING",(tx,payload))
        row=c.execute(f"SELECT payload FROM {prefix}_provider WHERE id=%s",(tx,)).fetchone()
        if row[0]!=payload: raise ValueError("provider-conflict")
        c.commit()
    if crash: os._exit(23)

def count(prefix):
    with connect() as c: return c.execute(f"SELECT count(*) FROM {prefix}_provider").fetchone()[0]

def state(prefix,tx):
    with connect() as c: return c.execute(f"SELECT state FROM {prefix}_commands WHERE id=%s",(tx,)).fetchone()[0]

def crashed_worker(prefix,tx,payload,epoch):
    if transition(prefix,tx,epoch,'SUBMITTED'):
        provider(prefix,tx,payload,crash=True)

def reconcile(prefix,tx,epoch):
    with connect() as c:
        command=c.execute(f"SELECT payload FROM {prefix}_commands WHERE id=%s",(tx,)).fetchone()
        effect=c.execute(f"SELECT payload FROM {prefix}_provider WHERE id=%s",(tx,)).fetchone()
    if effect is None:
        return transition(prefix,tx,epoch,'RECONCILIATION_REQUIRED')
    if not command or effect[0]!=command[0]: raise ValueError("provider-mismatch")
    return transition(prefix,tx,epoch,'COMMITTED')

class PostgreSQLRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prefix='aaktest_'+uuid.uuid4().hex[:14]
        init(cls.prefix)
    @classmethod
    def tearDownClass(cls): clean(cls.prefix)

    def test_01_commit_then_crash_and_reconcile(self):
        tx='pg-1'
        prepare(self.prefix,tx,'payload')
        epoch=lease(self.prefix,tx)
        p=multiprocessing.Process(target=crashed_worker,args=(self.prefix,tx,'payload',epoch))
        p.start()
        p.join(10)
        if p.is_alive():
            p.terminate()
            p.join()
            self.fail('worker hung')
        self.assertEqual(p.exitcode,23)
        self.assertEqual(count(self.prefix),1)
        self.assertTrue(reconcile(self.prefix,tx,epoch))
        self.assertEqual(state(self.prefix,tx),'COMMITTED')

    def test_02_replay_conflict(self):
        prepare(self.prefix,'pg-2','payload')
        with self.assertRaisesRegex(ValueError,'idempotency-conflict'):
            prepare(self.prefix,'pg-2','different')

    def test_03_fence_old_worker(self):
        prepare(self.prefix,'pg-3','payload')
        old=lease(self.prefix,'pg-3')
        new=lease(self.prefix,'pg-3')
        self.assertFalse(transition(self.prefix,'pg-3',old,'SUBMITTED'))
        self.assertTrue(transition(self.prefix,'pg-3',new,'SUBMITTED'))

    def test_04_unknown_remains_unresolved(self):
        prepare(self.prefix,'pg-4','payload')
        epoch=lease(self.prefix,'pg-4')
        self.assertTrue(reconcile(self.prefix,'pg-4',epoch))
        self.assertEqual(state(self.prefix,'pg-4'),'RECONCILIATION_REQUIRED')

    def test_05_provider_deduplication(self):
        provider(self.prefix,'pg-5','payload')
        provider(self.prefix,'pg-5','payload')
        with self.assertRaisesRegex(ValueError,'provider-conflict'):
            provider(self.prefix,'pg-5','different')

if __name__=='__main__':
    unittest.main(verbosity=2)
