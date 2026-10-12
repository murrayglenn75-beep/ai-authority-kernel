"""Signed HTTP transport to the actual AAK verifying effect broker.

CI runs with disposable PostgreSQL and a fake provider. Demonstrates real
grant, manifest, signed audit receipt and broker dispatch over a TCP socket.
This is NOT a credentialed deployment or independent-host test.
"""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from aak import (ActionEnvelopeVerifier, ToolManifestVerifier, Ed25519Signer,
    VerifyingEffectBroker, InputPolicy, DurableAuditAnchor, SQLiteBrokerReplayStore,
    GatewayGrant, ToolCall, AuditReceipt)
from aak.canonical import digest
from aak.authenticated_service import (AuthenticatedServiceDispatch,
    sign_service_request)
from aak.postgres_service_replay import PostgresServiceReplayLedger
from aak.postgres_fencing import PostgresFencingStore
from test_distributed import DistributedServiceTests, valid_close


@unittest.skipUnless(os.getenv("AAK_TEST_POSTGRES_DSN"), "disposable PostgreSQL required")
class SignedRealBrokerTCPTest(unittest.TestCase):
    def test_signed_tcp_delivery_to_verifying_broker_and_stale_fence(self):
        fixture=DistributedServiceTests(methodName=
            "test_exact_grant_executes_once_without_exposing_credential")
        fixture.setUp()
        dsn=os.environ["AAK_TEST_POSTGRES_DSN"]
        fence=PostgresFencingStore(dsn)
        fence.initialize()
        service_replay=PostgresServiceReplayLedger(dsn)
        service_replay.initialize()
        client_key=Ed25519Signer.generate()
        peer_auth=AuthenticatedServiceDispatch(
            destination="broker",trusted_peers={
                "resource":Ed25519Signer.verifier(client_key.public_key_bytes)},
            ledger=service_replay)
        token=fence.acquire("real-broker-tcp","worker-old",10)
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            audit=DurableAuditAnchor(Path(directory)/"audit.db",fixture.audit_key,
                                     anchor_id=fixture.audit_id)
            broker_replay=SQLiteBrokerReplayStore(Path(directory)/"broker.db")
            verifier=ActionEnvelopeVerifier(
                Ed25519Signer.verifier(fixture.envelope_key.public_key_bytes),
                ToolManifestVerifier(Ed25519Signer.verifier(
                    fixture.manifest_key.public_key_bytes)),
                expected_audience="crm-api")
            active={"owner":"worker-old","token":token}
            def enforce(grant,now):
                fence.dispatch_once("real-broker-tcp",active["owner"],
                                    active["token"],grant.envelope.transaction_id,
                                    request_hash=grant.call.request_hash)
            broker=VerifyingEffectBroker(
                verifier=verifier,provider=lambda **kwargs:
                    calls.append(kwargs) or {"provider_reference":"fake"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=fixture.audit_id,
                audit_verifiers={fixture.audit_key.key_id:
                    Ed25519Signer.verifier(fixture.audit_key.public_key_bytes)},
                replay_store=broker_replay,
                input_policies={"crm.ticket.update":InputPolicy(
                    fixture.manifest.input_schema_hash,valid_close)},
                dispatch_fence=enforce)
            action_hash=digest(fixture.grant.envelope.claim())
            event={"type":"action_authorized",
                   "envelope_id":fixture.grant.envelope.envelope_id,
                   "transaction_id":fixture.grant.envelope.transaction_id,
                   "request_hash":fixture.grant.call.request_hash,
                   "agent_identity":fixture.grant.envelope.agent_identity,
                   "policy_decision_id":fixture.grant.envelope.policy_decision_id,
                   "action_hash":action_hash}
            receipt=audit.append(event)
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_POST(self):
                    status=403
                    try:
                        size=int(self.headers.get("Content-Length","0"))
                        if size<=0 or size>32768: raise ValueError("bad body")
                        signed=json.loads(self.rfile.read(size))
                        peer,path,payload=peer_auth.verify(signed,now=102)
                        if peer!="resource" or path!="/execute" or set(payload)!={"grant","call"}:
                            raise ValueError("wrong route")
                        grant=GatewayGrant.from_wire(payload["grant"])
                        call=ToolCall.from_wire(payload["call"])
                        broker.execute(origin="https://crm.example",audience="crm-api",
                                       action_hash=action_hash,call=call,grant=grant,
                                       now=102,authorization_event=event,
                                       authorization_receipt=receipt)
                        status=200
                    except Exception:
                        status=403
                    self.send_response(status)
                    self.send_header("Content-Length","0")
                    self.end_headers()
            server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            def deliver(nonce):
                wire={"grant":fixture.grant.to_wire(),"call":fixture.grant.call.to_wire()}
                msg=sign_service_request(client_key,"resource","broker","/execute",
                                         wire,102,nonce)
                req=Request(f"http://127.0.0.1:{server.server_port}/",
                            data=json.dumps(msg).encode(),method="POST")
                try:
                    with urlopen(req,timeout=4) as response: return response.status
                except HTTPError as exc: return exc.code
            try:
                # Force old worker expiry before any provider call.
                with fence.db.transaction():
                    fence.db.execute("UPDATE aak_worker_leases SET expires_at="
                        "clock_timestamp()-interval '1 second' WHERE run_id=%s",
                        ("real-broker-tcp",))
                replacement=PostgresFencingStore(dsn)
                try:
                    new_token=replacement.acquire("real-broker-tcp","worker-new",30)
                    self.assertGreater(new_token,token)
                    self.assertEqual(deliver("stale-delivery"),403)
                    self.assertEqual(calls,[])
                    active.update(owner="worker-new",token=new_token)
                    self.assertEqual(deliver("current-delivery"),200)
                    self.assertEqual(len(calls),1)
                    self.assertEqual(deliver("replayed-delivery"),403)
                    self.assertEqual(len(calls),1)
                finally:
                    replacement.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                broker_replay.close()
                audit.close()
                service_replay.close()
                fence.close()

if __name__=="__main__":
    unittest.main()
