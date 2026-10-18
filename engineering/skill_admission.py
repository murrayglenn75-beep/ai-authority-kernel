"""Fail-closed skill manifest admission; does not execute or install skills."""
import hashlib
import re
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")
PERMISSIONS = frozenset(("read_workspace","write_workspace","network","execute_tests"))

def approval_fingerprint(manifest):
    """Stable digest of the exact skill identity, payload pin and permissions."""
    import json
    if not isinstance(manifest, dict):
        return None
    fields = ("name", "source", "revision", "sha256", "permissions")
    if any(key not in manifest for key in fields):
        return None
    try:
        payload = {key: manifest[key] for key in fields}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    except (TypeError, ValueError):
        return None

def inspect_skill(manifest, content, trusted_approvals=frozenset()):
    if not isinstance(manifest, dict):
        return ["invalid manifest"]
    errors = []
    name = manifest.get("name")
    if not isinstance(name,str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}",name):
        errors.append("invalid name")
    pin = manifest.get("sha256")
    if not isinstance(pin,str) or not SHA256.fullmatch(pin):
        errors.append("invalid digest pin")
    elif not isinstance(content,bytes) or hashlib.sha256(content).hexdigest()!=pin:
        errors.append("digest mismatch")
    rev=manifest.get("revision")
    if not isinstance(rev,str) or not REV.fullmatch(rev):
        errors.append("immutable commit revision required")
    source=manifest.get("source")
    if not isinstance(source,str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",source):
        errors.append("invalid source")
    perms=manifest.get("permissions")
    if not isinstance(perms,list) or any(not isinstance(p,str) or p not in PERMISSIONS for p in perms) or (all(isinstance(p,str) for p in perms) and len(perms)!=len(set(perms))):
        errors.append("invalid permissions")
    approval=manifest.get("approval_id")
    digest = approval_fingerprint(manifest)
    if (not isinstance(approval, str) or not isinstance(trusted_approvals, dict)
            or not isinstance(digest, str) or trusted_approvals.get(approval) != digest):
        errors.append("approval not independently verified for this exact skill")
    return errors
