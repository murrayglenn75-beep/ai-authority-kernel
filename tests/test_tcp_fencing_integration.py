"""Loopback TCP cross-process broker fence demonstration (CI-only).

Uses HTTP only on 127.0.0.1, not suitable for public deployment.
Real workload identity is the signed message; a trusted broker config holds
the worker-to-lease mapping. Provider is a local counter, not an external API.
"""
import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from aak.postgres_fencing import PostgresFencingStore
from aak.postgres_service_replay import PostgresServiceReplayLedger
from aak.authenticated_service import AuthenticatedServiceDispatch, sign_service_request
from aak import Ed25519Signer


@unittest.skipUnless(os.getenv("AAK_TEST_POSTGRES_DSN"), "test PostgreSQL required")
class RealTransportBoundaryTests(unittest.TestCase):
    def test_signed_tcp_worker_takeover_and_stale_worker_denial(self):
        dsn = os.environ["AAK_TEST_POSTGRES_DSN"]
        fence = PostgresFencingStore(dsn)
        fence.initialize()
        ledger = PostgresServiceReplayLedger(dsn)
        ledger.initialize()
        signer = Ed25519Signer.generate()
        verifier = Ed25519Signer.verifier(signer.public_key_bytes)
        guard = AuthenticatedServiceDispatch(
            destination="broker", trusted_peers={"worker-A":verifier,"worker-B":verifier},
            ledger=ledger)
        first = fence.acquire("tcp-isolation-run","worker-A",30)
        self.assertEqual(first,1)
        calls=[]
        current = {"worker-A":first}
        class BrokerHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                try:
                    length=int(self.headers.get("Content-Length","0"))
                    if length <= 0 or length > 32768:
                        raise ValueError("invalid body")
                    payload=json.loads(self.rfile.read(length))
                    peer,path,body=guard.verify(payload,now=101)
                    if path != "/execute" or set(body) != {"transaction"}:
                        raise ValueError("invalid operation")
                    transaction=body["transaction"]
                    if not isinstance(transaction,str) or not transaction:
                        raise ValueError("invalid transaction")
                    fence.dispatch_once("tcp-isolation-run",peer,
                        current.get(peer,-1),transaction)
                    calls.append(transaction)
                    response={"status":"accepted"}
                    status=200
                except Exception:
                    status=403
                    response={"status":"denied"}
                out=json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(out)))
                self.end_headers()
                self.wfile.write(out)
        server=ThreadingHTTPServer(("127.0.0.1",0),BrokerHandler)
        t=threading.Thread(target=server.serve_forever,daemon=True)
        t.start()
        def send(peer,nonce,transaction):
            message=sign_service_request(signer,peer,"broker","/execute",
                {"transaction":transaction},101,nonce)
            raw=json.dumps(message).encode()
            request=Request(f"http://127.0.0.1:{server.server_port}/",
                data=raw,headers={"Content-Type":"application/json"},method="POST")
            try:
                with urlopen(request,timeout=5) as response:
                    return response.status
            except Exception as exc:
                from urllib.error import HTTPError
                if isinstance(exc,HTTPError):
                    return exc.code
                raise
        try:
            self.assertEqual(send("worker-A","n1","effect-1"),200)
            # Expire the old lease in trusted database, then transfer ownership.
            with fence.db.transaction():
                fence.db.execute("UPDATE aak_worker_leases SET expires_at="
                    "clock_timestamp()-interval '1 second' WHERE run_id=%s",
                    ("tcp-isolation-run",))
            replacement=PostgresFencingStore(dsn)
            try:
                second=replacement.acquire("tcp-isolation-run","worker-B",30)
                self.assertEqual(second,2)
                current["worker-B"]=second
                self.assertEqual(send("worker-A","n2","effect-stale"),403)
                self.assertEqual(send("worker-B","n3","effect-2"),200)
                self.assertEqual(send("worker-B","n3","effect-2"),403)
                self.assertEqual(calls,["effect-1","effect-2"])
            finally:
                replacement.close()
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=5)
            ledger.close()
            fence.close()


if __name__ == "__main__":
    unittest.main()
