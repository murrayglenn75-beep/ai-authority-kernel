import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aak import (
    AuthorizedExecutor, EgressGuard, OIDCWorkloadVerifier, OPAClient,
    PostgresAuthorityStore, StagingBoundaryError,
)
from aak.crypto import b64encode


def jwt(private_key, kid, payload):
    header = b64encode(json.dumps({"alg": "EdDSA", "kid": kid, "typ": "JWT"}, separators=(",", ":"), sort_keys=True).encode())
    body = b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    message = f"{header}.{body}".encode()
    return f"{header}.{body}.{b64encode(private_key.sign(message))}"


class StagingBoundaryTests(unittest.TestCase):
    def test_opa_allows_only_exact_strict_response(self):
        response = {"result": {
            "allow": True, "decision_id": "d-1", "policy_version": "sha256:p1",
            "maximum_effect": {"records_written": 1}, "approval_refs": ["approval-1"],
        }}
        client = OPAClient("https://opa.internal/v1/data/aak/authorize", lambda *_: response)
        decision = client.decide({"action": "ticket.close"})
        self.assertEqual(decision.maximum_effect, {"records_written": 1})

    def test_opa_denial_outage_and_extra_fields_fail_closed(self):
        cases = (
            lambda *_: {"result": {"allow": False, "decision_id": "d", "policy_version": "1", "maximum_effect": {"calls": 0}, "approval_refs": []}},
            lambda *_: {"result": {"allow": True, "decision_id": "d", "policy_version": "1", "maximum_effect": {"calls": 1}, "approval_refs": [], "debug": "leak"}},
            lambda *_: (_ for _ in ()).throw(TimeoutError()),
        )
        for transport in cases:
            with self.subTest(transport=transport):
                with self.assertRaises(StagingBoundaryError):
                    OPAClient("https://opa.internal/v1/data/aak/authorize", transport).decide({"a": 1})

    def test_opa_requires_https_and_bounded_timeout(self):
        for endpoint, timeout in (("http://opa/v1/data/aak", 1), ("https://user@opa/v1/data/aak", 1), ("https://opa/v1/data/aak", 11)):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(StagingBoundaryError):
                    OPAClient(endpoint, lambda *_: {}, timeout=timeout)

    def identity_fixture(self):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes_raw()
        verifier = OIDCWorkloadVerifier(
            issuer="https://identity.internal", audience="aak-resource",
            public_keys={"key-1": public}, maximum_lifetime=60,
        )
        payload = {
            "iss": "https://identity.internal", "sub": "spiffe://example.org/agent/support",
            "aud": "aak-resource", "iat": 100, "nbf": 100, "exp": 130,
            "jti": "token-1", "cnf": {"x5t#S256": "cert-fingerprint"},
        }
        return key, verifier, payload

    def test_oidc_identity_is_signature_audience_certificate_and_replay_bound(self):
        key, verifier, payload = self.identity_fixture()
        token = jwt(key, "key-1", payload)
        claims = verifier.verify(token, certificate_fingerprint="cert-fingerprint", now=101)
        self.assertEqual(claims.subject, "spiffe://example.org/agent/support")
        with self.assertRaisesRegex(StagingBoundaryError, "identity_replay"):
            verifier.verify(token, certificate_fingerprint="cert-fingerprint", now=101)

    def test_oidc_substitutions_fail_closed(self):
        mutations = (
            ("aud", "other"), ("iss", "https://evil.invalid"),
            ("exp", 500), ("cnf", {"x5t#S256": "other-cert"}),
        )
        for field, value in mutations:
            key, verifier, payload = self.identity_fixture()
            payload[field] = value
            with self.subTest(field=field):
                with self.assertRaises(StagingBoundaryError):
                    verifier.verify(jwt(key, "key-1", payload), certificate_fingerprint="cert-fingerprint", now=101)

    def test_oidc_algorithm_and_unknown_key_confusion_fail_closed(self):
        key, verifier, payload = self.identity_fixture()
        for kid in ("missing", ""):
            with self.subTest(kid=kid):
                with self.assertRaises(StagingBoundaryError):
                    verifier.verify(jwt(key, kid, payload), certificate_fingerprint="cert-fingerprint", now=101)

    def test_oidc_duplicate_claims_fail_closed(self):
        key, verifier, _ = self.identity_fixture()
        header = b64encode(b'{"alg":"EdDSA","kid":"key-1","typ":"JWT"}')
        body = b64encode(
            b'{"iss":"https://identity.internal","iss":"https://evil.invalid",'
            b'"sub":"spiffe://example.org/agent/support","aud":"aak-resource",'
            b'"iat":100,"nbf":100,"exp":130,"jti":"token-1",'
            b'"cnf":{"x5t#S256":"cert-fingerprint"}}'
        )
        message = f"{header}.{body}".encode()
        token = f"{header}.{body}.{b64encode(key.sign(message))}"
        with self.assertRaisesRegex(StagingBoundaryError, "duplicate_identity_claim"):
            verifier.verify(token, certificate_fingerprint="cert-fingerprint", now=101)

    def test_egress_guard_matches_origin_not_host_suffix_or_userinfo(self):
        guard = EgressGuard(("https://api.example.com",))
        self.assertEqual(guard.authorize("https://api.example.com/v1/tickets"), "https://api.example.com")
        for destination in (
            "https://api.example.com.evil.invalid/v1", "https://evil.invalid/api.example.com",
            "https://user@api.example.com/v1", "http://api.example.com/v1",
        ):
            with self.subTest(destination=destination):
                with self.assertRaises(StagingBoundaryError):
                    guard.authorize(destination)

    def test_credentials_are_requested_only_after_egress_authorization(self):
        class Broker:
            def __init__(self): self.calls = 0
            def credential_for(self, **_): self.calls += 1; return "scoped-token"

        broker = Broker()
        executor = AuthorizedExecutor(EgressGuard(("https://api.example.com",)), broker)
        with self.assertRaisesRegex(StagingBoundaryError, "egress_denied"):
            executor.prepare(destination="https://evil.invalid", audience="api", action_claim={"a": 1})
        self.assertEqual(broker.calls, 0)
        self.assertEqual(executor.prepare(destination="https://api.example.com/v1", audience="api", action_claim={"a": 1})[1], "scoped-token")
        self.assertEqual(broker.calls, 1)

    def test_postgres_rejection_rolls_back_nonce_and_budget_transaction(self):
        class Transaction:
            def __init__(self, connection): self.connection = connection
            def __enter__(self): return self
            def __exit__(self, kind, *_):
                self.connection.rolled_back = kind is not None
                return False

        class Cursor:
            def __init__(self): self.sql = ""
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def execute(self, sql, _params=None): self.sql = sql
            def fetchone(self):
                if "aak_revoked_nonces" in self.sql: return None
                if "aak_used_nonces" in self.sql: return ("nonce",)
                if "SELECT amount" in self.sql: return (5,)
                return None

        class Connection:
            def __init__(self): self.rolled_back = False
            def transaction(self): return Transaction(self)
            def cursor(self): return Cursor()
            def close(self): pass

        connection = Connection()
        store = PostgresAuthorityStore("postgresql://test", connect=lambda _dsn: connection)
        self.assertEqual(
            store.consume("nonce", {"user:calls": 1}, {"user:calls": 0}, 100, strict_integer=True),
            (False, "budget_exceeded:user:calls"),
        )
        self.assertTrue(connection.rolled_back)


if __name__ == "__main__":
    unittest.main()
