import os
import threading
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

    def test_competing_verifiers_only_one_accepts_same_signed_nonce(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "shared-nonce.db")
            a, b = ServiceReplayLedger(path), ServiceReplayLedger(path)
            signer = Ed25519Signer.generate()
            verifier = Ed25519Signer.verifier(signer.public_key_bytes)
            services = [AuthenticatedServiceDispatch(
                destination="broker", trusted_peers={"resource":verifier},
                ledger=ledger) for ledger in (a,b)]
            signed = sign_service_request(signer,"resource","broker",
                "/v1/actions",{"request":"once"},100,"simultaneous")
            barrier = threading.Barrier(2)
            accepted, denied = [], []
            def run(service):
                try:
                    barrier.wait(timeout=5)
                    accepted.append(service.verify(signed,now=101))
                except DistributedBoundaryError:
                    denied.append(1)
            threads = [threading.Thread(target=run,args=(s,)) for s in services]
            for worker in threads: worker.start()
            for worker in threads: worker.join(timeout=10)
            self.assertTrue(all(not worker.is_alive() for worker in threads))
            self.assertEqual(len(accepted),1)
            self.assertEqual(len(denied),1)
            a.close()
            b.close()

    def test_service_request_bounds_fail_closed_before_effect(self):
        from aak.authenticated_service import MAX_SERVICE_CLAIM_BYTES
        with tempfile.TemporaryDirectory() as d:
            ledger=ServiceReplayLedger(os.path.join(d,"bounds.db"))
            signer=Ed25519Signer.generate()
            dispatch=AuthenticatedServiceDispatch(
                destination="broker",
                trusted_peers={"resource":Ed25519Signer.verifier(signer.public_key_bytes)},
                ledger=ledger)
            try:
                with self.assertRaises(ValueError):
                    sign_service_request(signer,"resource","broker","/v1/test",
                                         {"data":"x"*MAX_SERVICE_CLAIM_BYTES},100,"big")
                with self.assertRaises(ValueError):
                    sign_service_request(signer,"resource","broker","/v1/test",
                                         {},100,"n"*129)
                signed=sign_service_request(signer,"resource","broker","/v1/test",
                                            {"ok":1},100,"bounded")
                forged={**signed,"payload":{"data":"x"*MAX_SERVICE_CLAIM_BYTES}}
                with self.assertRaisesRegex(DistributedBoundaryError,"service_request_too_large"):
                    dispatch.verify(forged,now=100)
                with self.assertRaisesRegex(DistributedBoundaryError,"service_identity_or_freshness_denied"):
                    dispatch.verify({**signed,"nonce":"n"*129},now=100)
                self.assertEqual(dispatch.verify(signed,now=100)[0],"resource")
            finally:
                ledger.close()

    def test_replay_database_failure_denies_valid_signed_request(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=ServiceReplayLedger(os.path.join(d,"outage.db"))
            signer=Ed25519Signer.generate()
            boundary=AuthenticatedServiceDispatch(
                destination="broker",
                trusted_peers={"resource":Ed25519Signer.verifier(signer.public_key_bytes)},
                ledger=ledger)
            signed=sign_service_request(signer,"resource","broker",
                "/execute",{"operation":"test"},100,"outage-nonce")
            ledger.close()
            endpoint=EchoEndpoint()
            with self.assertRaisesRegex(DistributedBoundaryError,
                                        "service_replay_store_unavailable"):
                boundary.handle(signed,now=100,endpoint=endpoint)
            self.assertEqual(endpoint.called,0)

if __name__=="__main__":
    unittest.main()
