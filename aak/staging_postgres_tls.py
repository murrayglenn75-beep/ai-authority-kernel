"""Fail-closed validation for production-style PostgreSQL TLS connection settings.

The staging harness deliberately uses plain disposable PostgreSQL and must not
invoke this validator. This does not configure server-side TLS or RBAC.
"""
from urllib.parse import urlsplit, parse_qs

def require_verified_postgres_tls(dsn: str) -> str:
    if not isinstance(dsn, str) or not dsn:
        raise ValueError("postgres_dsn_missing")
    try:
        parts = urlsplit(dsn)
        qs = parse_qs(parts.query, keep_blank_values=True)
    except ValueError as exc:
        raise ValueError("postgres_dsn_invalid") from exc
    if parts.scheme not in {"postgresql", "postgres"} or not parts.hostname:
        raise ValueError("postgres_dsn_invalid")
    if qs.get("sslmode") != ["verify-full"]:
        raise ValueError("postgres_tls_must_verify_full")
    if len(qs.get("sslrootcert", [])) != 1 or not qs["sslrootcert"][0].startswith("/"):
        raise ValueError("postgres_tls_trust_root_required")
    if "sslcert" in qs and ("sslkey" not in qs or len(qs["sslkey"]) != 1):
        raise ValueError("postgres_client_key_required")
    if parts.username in (None, "", "postgres"):
        raise ValueError("dedicated_non_admin_db_role_required")
    return dsn
