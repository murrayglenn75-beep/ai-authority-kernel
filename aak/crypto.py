import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value: str) -> bytes:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64encode(raw) != value:
        raise ValueError("noncanonical_base64")
    return raw


class CapabilitySigner(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True)
class HMACSigner:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise ValueError("signing key must be at least 32 bytes")

    @property
    def key_id(self) -> str:
        return "hmac:" + hashlib.sha256(self.key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self.key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey | None, public_key: Ed25519PublicKey) -> None:
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        private = Ed25519PrivateKey.generate()
        return cls(private, private.public_key())

    @classmethod
    def verifier(cls, public_key_bytes: bytes) -> "Ed25519Signer":
        return cls(None, Ed25519PublicKey.from_public_bytes(public_key_bytes))

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return "ed25519:" + hashlib.sha256(self.public_key_bytes).hexdigest()

    def sign(self, message: bytes) -> bytes:
        if self._private_key is None:
            raise PermissionError("verifier has no private key")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except Exception:
            return False
