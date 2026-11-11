import unittest
from aak import Ed25519Signer
from aak.canonical import canonical_bytes
from aak.crypto import b64encode
from aak.provider_reconciliation import VerifiedProviderReconciliation
from aak.reliability_contract import RecoveryDecision


class ProviderReceiptVerification(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer.generate()
        self.reconciler = VerifiedProviderReconciliation({
            self.signer.key_id: Ed25519Signer.verifier(self.signer.public_key_bytes)})
        self.claim = {"transaction_id":"tx-a", "request_hash":"sha256-request-a",
                      "provider_reference":"provider-123", "state":"committed",
                      "provider_key_id":self.signer.key_id}

    def sign(self, claim):
        return {**claim, "signature": b64encode(self.signer.sign(canonical_bytes(claim)))}

    def test_valid_signed_receipt_can_classify_success(self):
        self.assertEqual(self.reconciler.classify("tx-a", "sha256-request-a",
                         self.sign(self.claim)), RecoveryDecision.RECORD_SUCCESS)

    def test_valid_definitive_rejection(self):
        claim = {**self.claim, "state":"definitively_rejected_before_effect"}
        self.assertEqual(self.reconciler.classify("tx-a", "sha256-request-a",
                         self.sign(claim)), RecoveryDecision.RECORD_REJECTION)

    def test_tampering_unknown_keys_and_mismatched_request_fail_closed(self):
        receipt = self.sign(self.claim)
        mutations = [
            {**receipt, "state":"definitively_rejected_before_effect"},
            {**receipt, "transaction_id":"tx-b"},
            {**receipt, "provider_reference":"forged"},
            {**receipt, "provider_key_id":"other"},
            {**receipt, "signature":"bad"},
            {**receipt, "debug":"injected"},
            {**receipt, "request_hash":"wrong"},
        ]
        for candidate in mutations:
            with self.subTest(candidate=candidate):
                self.assertEqual(self.reconciler.classify(
                    "tx-a", "sha256-request-a", candidate), RecoveryDecision.REQUIRE_OPERATOR)
        self.assertEqual(self.reconciler.classify(
            "tx-b", "sha256-request-a", receipt), RecoveryDecision.REQUIRE_OPERATOR)
        self.assertEqual(self.reconciler.classify(
            "tx-a", "sha256-request-b", receipt), RecoveryDecision.REQUIRE_OPERATOR)
        self.assertEqual(self.reconciler.classify(
            "tx-a", "sha256-request-a", None), RecoveryDecision.REQUIRE_OPERATOR)
        self.assertEqual(self.reconciler.classify(
            "tx-a", "sha256-request-a", {**self.sign({**self.claim, "state":"unknown"})}),
            RecoveryDecision.REQUIRE_OPERATOR)


if __name__ == "__main__":
    unittest.main()
