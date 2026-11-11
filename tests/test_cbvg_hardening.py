import tempfile
import unittest
from dataclasses import replace
from cbvg import CognitiveValidationGate, Evidence, Suite, REQUIRED, SQLiteNonceStore, fixture_signature
from cbvg_paired import PairedResult, assess_paired

KEY=b'test-fixture-only'
def signed(**kwargs):
    e=Evidence('candidate','baseline',tuple(Suite(name,40,30) for name in sorted(REQUIRED)), 'verifier','unique',**kwargs)
    return replace(e,signature=fixture_signature(e,KEY))

class HardeningTests(unittest.TestCase):
    def test_durable_replay_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=tmp+'/receipts.sqlite3'
            first=CognitiveValidationGate({'verifier':KEY},nonce_store=SQLiteNonceStore(path))
            self.assertTrue(first.admit(signed())[0])
            second=CognitiveValidationGate({'verifier':KEY},nonce_store=SQLiteNonceStore(path))
            self.assertFalse(second.admit(signed())[0])
    def test_missing_digests_fail_closed(self):
        gate=CognitiveValidationGate({'verifier':KEY},require_digests=True)
        self.assertFalse(gate.admit(signed())[0])
    def test_valid_digest_binding(self):
        hashvalue='a'*64
        gate=CognitiveValidationGate({'verifier':KEY},require_digests=True)
        e=signed(dataset_digest=hashvalue,scorer_digest=hashvalue,candidate_digest=hashvalue,baseline_digest=hashvalue)
        self.assertTrue(gate.admit(e)[0])
    def test_zero_passes_rejected_across_all_suites(self):
        gate=CognitiveValidationGate({'verifier':KEY})
        e=signed(); suites=tuple(replace(s,passed=0) for s in e.suites)
        e=replace(e,suites=suites)
        e=replace(e,signature=fixture_signature(e,KEY))
        self.assertFalse(gate.admit(e)[0])
    def test_oversized_suite_rejected(self):
        gate=CognitiveValidationGate({'verifier':KEY})
        e=signed(); suites=(replace(e.suites[0],samples=100001),)+e.suites[1:]
        e=replace(e,suites=suites); e=replace(e,signature=fixture_signature(e,KEY))
        self.assertFalse(gate.admit(e)[0])
    def test_paired_large_bound(self):
        with self.assertRaises(ValueError):
            assess_paired(tuple(PairedResult(str(i),False,True) for i in range(100001)))
    def test_low_candidate_score_rejected(self):
        gate=CognitiveValidationGate({'verifier':KEY},min_pass_rate=.9)
        self.assertFalse(gate.admit(signed())[0])

if __name__=='__main__':
    unittest.main()
