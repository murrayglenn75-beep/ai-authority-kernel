import unittest
from dataclasses import replace
from cbvg import Suite, Evidence, CognitiveValidationGate, REQUIRED, fixture_signature

SECRET = b"fixture-only"
def valid():
    e = Evidence("candidate", "baseline", tuple(Suite(n, 40, 30) for n in sorted(REQUIRED)), "verifier", "nonce")
    return replace(e, signature=fixture_signature(e, SECRET))

def resign(e):
    return replace(e, signature=fixture_signature(e, SECRET))

class Tests(unittest.TestCase):
    def setUp(self):
        self.gate = CognitiveValidationGate({"verifier": SECRET})
    def test_admits_receipt_not_release(self):
        self.assertEqual(self.gate.admit(valid()), (True, ("receipt_admitted_not_release_authorization",)))
    def test_replay(self):
        e=valid(); self.gate.admit(e); self.assertFalse(self.gate.admit(e)[0])
    def test_tamper(self):
        self.assertFalse(self.gate.admit(replace(valid(), candidate="evil"))[0])
    def test_unknown_verifier(self):
        self.assertFalse(self.gate.admit(replace(valid(), reviewer="agent"))[0])
    def test_missing_suite(self):
        e=valid(); self.assertFalse(self.gate.admit(resign(replace(e,suites=e.suites[:-1])))[0])
    def test_safety_violation(self):
        e=valid(); s=replace(e.suites[0],violations=1)
        self.assertFalse(self.gate.admit(resign(replace(e,suites=(s,)+e.suites[1:])))[0])
    def test_insufficient_samples(self):
        e=valid(); s=replace(e.suites[0],samples=4,passed=4)
        self.assertFalse(self.gate.admit(resign(replace(e,suites=(s,)+e.suites[1:])))[0])
    def test_invalid_version(self):
        e=valid(); self.assertFalse(self.gate.admit(resign(replace(e,candidate=e.baseline)))[0])
    def test_weak_blind_result(self):
        e=valid(); i=next(i for i,s in enumerate(e.suites) if s.name=="blind_interview")
        ss=list(e.suites); ss[i]=replace(ss[i],passed=10)
        self.assertFalse(self.gate.admit(resign(replace(e,suites=tuple(ss))))[0])

if __name__ == "__main__":
    unittest.main()
