"""Strict verification of independent provider reconciliation receipts.

Only an operator-registered provider verification key may attest an outcome.
No model-provided booleans, text or callback return alone settles an effect.
This module classifies evidence only; it NEVER retries or dispatches effects.
"""
from __future__ import annotations
import hmac
from typing import Mapping
from .canonical import canonical_bytes
from .crypto import b64decode
from .reliability_contract import RecoveryDecision


class VerifiedProviderReconciliation:
    def __init__(self, verifiers: Mapping[str, object]):
        if not verifiers:
            raise ValueError("trusted provider receipt verifiers required")
        self.verifiers = dict(verifiers)

    def classify(self, transaction_id: str, request_hash: str,
                 receipt: object) -> RecoveryDecision:
        if (not isinstance(transaction_id, str) or not transaction_id
                or not isinstance(request_hash, str) or not request_hash):
            raise ValueError("invalid reconciliation query")
        fields = {"transaction_id", "request_hash", "provider_reference",
                  "state", "provider_key_id", "signature"}
        if not isinstance(receipt, dict) or set(receipt) != fields:
            return RecoveryDecision.REQUIRE_OPERATOR
        if any(not isinstance(receipt[k], str) or not receipt[k]
               for k in fields):
            return RecoveryDecision.REQUIRE_OPERATOR
        if (not hmac.compare_digest(transaction_id, receipt["transaction_id"])
                or not hmac.compare_digest(request_hash, receipt["request_hash"])):
            return RecoveryDecision.REQUIRE_OPERATOR
        verifier = self.verifiers.get(receipt["provider_key_id"])
        if verifier is None:
            return RecoveryDecision.REQUIRE_OPERATOR
        claim = {k: v for k, v in receipt.items() if k != "signature"}
        try:
            authenticated = verifier.verify(
                canonical_bytes(claim), b64decode(receipt["signature"]))
        except Exception:
            return RecoveryDecision.REQUIRE_OPERATOR
        if authenticated is not True:
            return RecoveryDecision.REQUIRE_OPERATOR
        if receipt["state"] == "committed":
            return RecoveryDecision.RECORD_SUCCESS
        if receipt["state"] == "definitively_rejected_before_effect":
            return RecoveryDecision.RECORD_REJECTION
        return RecoveryDecision.REQUIRE_OPERATOR
