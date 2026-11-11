"""Fail-closed approval preflight; this does not issue or authenticate approvals."""
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

class InvalidPolicy(ValueError):
    pass

class DuplicateKeyError(InvalidPolicy):
    pass

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKeyError(f"duplicate key: {key}")
            result[key] = value
        return result
    def bad_constant(value):
        raise InvalidPolicy(f"invalid JSON constant: {value}")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=bad_constant, parse_float=Decimal)
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidPolicy("invalid JSON document") from exc

def _utc(value):
    if not isinstance(value, str):
        raise InvalidPolicy("timestamp missing")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidPolicy("invalid timestamp") from exc
    if timestamp.tzinfo is None:
        raise InvalidPolicy("timestamp must include timezone")
    return timestamp.astimezone(timezone.utc)

def _money(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise InvalidPolicy("budget must be a decimal amount")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise InvalidPolicy("invalid budget") from exc
    if not result.is_finite() or result < 0:
        raise InvalidPolicy("budget must be finite and nonnegative")
    return result

def preflight(approval, request, *, verified_approval_ids, now):
    """Return (passed, errors). IDs must come from an independent verifier.

    This is a constraint checker, NOT an authorization decision. AAK must still
    authenticate actor and capability, enforce policy, and verify actual effects.
    """
    if not isinstance(approval, dict) or not isinstance(request, dict):
        return False, ["invalid input"]
    if not isinstance(verified_approval_ids, (set, frozenset)):
        return False, ["independent approval set missing"]
    errors = []
    expected = {"approval_id", "principal", "action", "resource", "expires_at",
                "max_cost", "max_uses", "used"}
    if set(approval) != expected:
        errors.append("approval schema mismatch")
    for key in ("approval_id", "principal", "action", "resource"):
        if not isinstance(approval.get(key), str) or not approval[key].strip():
            errors.append(f"{key}: invalid")
    if approval.get("approval_id") not in verified_approval_ids:
        errors.append("approval not independently verified")
    for key in ("principal", "action", "resource"):
        if request.get(key) != approval.get(key) or not isinstance(request.get(key), str):
            errors.append(f"{key}: binding mismatch")
    try:
        current = now if isinstance(now, datetime) else _utc(now)
        if current.tzinfo is None:
            raise InvalidPolicy("current time must be timezone aware")
        if _utc(approval.get("expires_at")) <= current.astimezone(timezone.utc):
            errors.append("approval expired")
    except InvalidPolicy as exc:
        errors.append(str(exc))
    for key in ("max_uses", "used"):
        if type(approval.get(key)) is not int or approval[key] < 0:
            errors.append(f"{key}: invalid")
    if type(approval.get("max_uses")) is int and type(approval.get("used")) is int:
        if approval["max_uses"] < 1 or approval["used"] >= approval["max_uses"]:
            errors.append("use budget exhausted")
    try:
        if _money(request.get("estimated_cost")) > _money(approval.get("max_cost")):
            errors.append("cost budget exceeded")
    except InvalidPolicy as exc:
        errors.append(str(exc))
    if request.get("is_publication") is True:
        errors.append("publishing requires a separate pre-effect release gate")
    return not errors, errors
