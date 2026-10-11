import os
import tempfile
import unittest
from aak import Ed25519Signer, DistributedBoundaryError
from aak.authenticated_service import (ServiceReplayLedger,
    AuthenticatedServiceDispatch, sign_service_request)

class EchoEndpoint:
    def __init__(self):
        self.called = 0
    def handle(self, path, payload, *, peer_identity):
        self.called += 1
        return {"path":path,"payload":payload,"peer":peer_identity}

class AuthenticatedTransportTests(unittest.TestCase):
    def test_signed_identity_replay_and_target_isolation(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=ServiceReplayLedger(os.path.join(d,"nonce.db"))
            signer=Ed25519Signer.generate()
            verifier=Ed25519Signer.verifier(signer.public_key_bytes)
            gateway=AuthenticatedServiceDispatch(destination="broker",
                trusted_peers={"resource":verifier},ledger=ledger)
            endpoint=EchoEndpoint()
            msg=sign_service_request(signer,"resource","broker",
                "/v1/actions",{"x":1},100,"nonce-1")
            self.assertEqual(gateway.handle(msg,now=101,endpoint=endpoint)["peer"],"resource")
            self.assertEqual(endpoint.called,1)
            for bad in [
                msg,
                {**msg,"peer":"admin"},
                {**msg,"destination":"audit"},
                {**msg,"payload":{"x":2}},
                {**msg,"signature":"junk"},
            ]:
                with self.assertRaises(DistributedBoundaryError):
                    gateway.handle(bad,now=101,endpoint=endpoint)
            self.assertEqual(endpoint.called,1)
            old=sign_service_request(signer,"resource","broker",
                "/v1/actions",{"x":1},1,"nonce-2")
            with self.assertRaises(DistributedBoundaryError):
                gateway.handle(old,now=101,endpoint=endpoint)
            ledger.close()
            new=ServiceReplayLedger(os.path.join(d,"nonce.db"))
            restarted=AuthenticatedServiceDispatch(destination="broker",
                trusted_peers={"resource":verifier},ledger=new)
            with self.assertRaises(DistributedBoundaryError):
                restarted.handle(msg,now=101,endpoint=endpoint)
            new.close()

if __name__=="__main__":
    unittest.main()
