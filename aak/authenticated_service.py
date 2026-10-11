"""Authenticated, replay-protected envelope for isolated AAK service transports.

The transport must additionally supply TLS and channel binding in production.
The caller cannot choose peer identity through unauthenticated headers.
"""
from __future__ import annotations
import sqlite3
import threading
from collections.abc import Mapping
from .canonical import canonical_bytes
from .crypto import b64encode, b64decode
from .distributed import DistributedBoundaryError

class ServiceReplayLedger:
    def __init__(self, path):
        if not path or path == ":memory:":
            raise ValueError("persistent replay store required")
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS service_nonces (peer TEXT NOT NULL,nonce TEXT NOT NULL, PRIMARY KEY(peer,nonce))")
        self.lock = threading.RLock()

    def accept(self, peer, nonce):
        with self.lock:
            try:
                self.db.execute("INSERT INTO service_nonces(peer,nonce) VALUES(?,?)", (peer,nonce))
                return True
            except sqlite3.IntegrityError:
                return False

    def close(self):
        self.db.close()


def sign_service_request(signer, peer, destination, path, payload, now, nonce):
    if not all(isinstance(x, str) and x for x in (peer,destination,path,nonce)):
        raise ValueError("invalid service identity")
    if type(now) is not int or not isinstance(payload, Mapping):
        raise ValueError("invalid service request")
    claim = {"peer":peer,"destination":destination,"path":path,
             "payload":dict(payload),"timestamp":now,"nonce":nonce,
             "key_id":signer.key_id}
    return {**claim,"signature":b64encode(signer.sign(canonical_bytes(claim)))}


class AuthenticatedServiceDispatch:
    def __init__(self, *, destination, trusted_peers, ledger, max_age=30):
        if (not destination or not trusted_peers or not ledger
                or type(max_age) is not int or not 1 <= max_age <= 300):
            raise ValueError("invalid service security configuration")
        self.destination = destination
        self.trusted_peers = dict(trusted_peers)
        self.ledger = ledger
        self.max_age = max_age

    def verify(self, message, *, now):
        fields = {"peer","destination","path","payload","timestamp","nonce","key_id","signature"}
        if not isinstance(message, Mapping) or set(message) != fields:
            raise DistributedBoundaryError("service_invalid_signed_request")
        peer = message["peer"]
        verifier = self.trusted_peers.get(peer) if isinstance(peer,str) else None
        if (verifier is None or not all(isinstance(message[k],str) and message[k]
              for k in ("destination","path","nonce","key_id","signature"))
                or not isinstance(message["payload"], Mapping)
                or type(message["timestamp"]) is not int or type(now) is not int
                or abs(now-message["timestamp"]) > self.max_age
                or message["destination"] != self.destination
                or message["key_id"] != verifier.key_id):
            raise DistributedBoundaryError("service_identity_or_freshness_denied")
        claim = {key: message[key] for key in fields if key != "signature"}
        try:
            valid = verifier.verify(canonical_bytes(claim), b64decode(message["signature"]))
        except Exception:
            valid = False
        if not valid:
            raise DistributedBoundaryError("service_signature_denied")
        if not self.ledger.accept(peer, message["nonce"]):
            raise DistributedBoundaryError("service_replay_denied")
        return peer, message["path"], dict(message["payload"])

    def handle(self, message, *, now, endpoint):
        peer, path, payload = self.verify(message, now=now)
        return endpoint.handle(path, payload, peer_identity=peer)
