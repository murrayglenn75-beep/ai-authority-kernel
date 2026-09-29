"""Deterministic synthetic attack gate for distributed staging adapters."""

import json
import os
from dataclasses import asdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aak import EgressGuard, OIDCWorkloadVerifier, OPAClient, StagingBoundaryError
from aak.crypto import b64encode


def token(key, kid, payload, *, alg="EdDSA"):
    header = b64encode(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":"), sort_keys=True).encode())
    body = b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    message = f"{header}.{body}".encode()
    return f"{header}.{body}.{b64encode(key.sign(message))}"


def main():
    attempts = int(os.getenv("AAK_STAGING_ATTEMPTS", "100000"))
    if attempts < 1 or attempts > 2_000_000:
        raise SystemExit("AAK_STAGING_ATTEMPTS must be 1..2000000")
    key = Ed25519PrivateKey.generate()
    verifier = OIDCWorkloadVerifier(
        issuer="https://identity.internal", audience="resource",
        public_keys={"k1": key.public_key().public_bytes_raw()}, maximum_lifetime=60,
    )
    base = {"iss": "https://identity.internal", "sub": "spiffe://aak/agent", "aud": "resource",
            "iat": 100, "nbf": 100, "exp": 130, "jti": "valid",
            "cnf": {"x5t#S256": "cert"}}
    valid = token(key, "k1", base)
    claims = verifier.verify(valid, certificate_fingerprint="cert", now=101)
    if asdict(claims)["subject"] != "spiffe://aak/agent":
        raise SystemExit("valid identity control failed")

    bad_tokens = []
    for field, value in (("aud", "other"), ("iss", "https://evil.invalid"),
                         ("exp", 1000), ("cnf", {"x5t#S256": "other"})):
        changed = dict(base)
        changed[field] = value
        bad_tokens.append(token(key, "k1", changed))
    bad_tokens.extend((token(key, "unknown", base), token(key, "k1", base, alg="none"), valid))

    good_opa = {"result": {"allow": True, "decision_id": "d", "policy_version": "v1",
                            "maximum_effect": {"calls": 1}, "approval_refs": []}}
    if OPAClient("https://opa.internal/v1/data/aak/authority/decision", lambda *_: good_opa).decide({"a": 1}).decision_id != "d":
        raise SystemExit("valid OPA control failed")
    bad_opa = (
        {"result": {**good_opa["result"], "allow": False}},
        {"result": {**good_opa["result"], "extra": True}},
        {"result": {**good_opa["result"], "maximum_effect": {"calls": -1}}},
        {}, {"result": None},
    )
    guard = EgressGuard(("https://api.example.com",))
    if guard.authorize("https://api.example.com/v1") != "https://api.example.com":
        raise SystemExit("valid egress control failed")
    bad_destinations = ("http://api.example.com", "https://api.example.com.evil.invalid",
                        "https://user@api.example.com", "https://evil.invalid")

    unauthorized = crashes = 0
    for index in range(attempts):
        boundary = index % 3
        try:
            if boundary == 0:
                verifier.verify(bad_tokens[index % len(bad_tokens)], certificate_fingerprint="cert", now=101)
            elif boundary == 1:
                response = bad_opa[index % len(bad_opa)]
                OPAClient("https://opa.internal/v1/data/aak/authority/decision", lambda *_, r=response: r).decide({"a": 1})
            else:
                guard.authorize(bad_destinations[index % len(bad_destinations)])
            unauthorized += 1
        except StagingBoundaryError:
            pass
        except Exception:
            crashes += 1
    print(json.dumps({"attempts": attempts, "unauthorized_acceptances": unauthorized,
                      "crashes": crashes, "valid_controls": 3}, sort_keys=True))
    if unauthorized or crashes:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
