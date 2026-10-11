"""Isolated container worker/broker service acceptance harness (staging only).

Uses signed per-worker messages and PostgreSQL coordination. The broker
authenticates the caller and checks the worker lease before simulated effects.
Never expose this HTTP-only harness to external networks.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from aak.postgres_fencing import PostgresFencingStore
from aak.postgres_service_replay import PostgresServiceReplayLedger
from aak.authenticated_service import AuthenticatedServiceDispatch, sign_service_request
from aak import Ed25519Signer

DSN=os.environ["AAK_TEST_POSTGRES_DSN"]

def post(url, message):
    raw=json.dumps(message).encode()
    req=Request(url,data=raw,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urlopen(req,timeout=5) as r: return r.status
    except HTTPError as exc:
        return exc.code

def broker():
    fence=PostgresFencingStore(DSN)
    ledger=PostgresServiceReplayLedger(DSN)
    fence.initialize()
    ledger.initialize()
    from aak.crypto import b64decode
    keys={identity:Ed25519Signer.verifier(b64decode(os.environ["AAK_PUBLIC_"+identity[-1]]))
          for identity in ("worker-A","worker-B")}
    auth=AuthenticatedServiceDispatch(destination="broker",trusted_peers=keys,ledger=ledger)
    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            try:
                length=int(self.headers.get("Content-Length","0"))
                if not 0<length<=32768: raise ValueError("invalid size")
                msg=json.loads(self.rfile.read(length))
                peer,path,data=auth.verify(msg,now=100)
                if path!="/execute" or set(data)!={"tx","token"}: raise ValueError("invalid request")
                token=data["token"]
                if type(token) is not int or token<1: raise ValueError("invalid token")
                fence.dispatch_once("container-run",peer,token,data["tx"])
                code=200
            except Exception:
                code=403
            self.send_response(code)
            self.send_header("Content-Length","0")
            self.end_headers()
    server=ThreadingHTTPServer(("0.0.0.0",8080),Endpoint)
    server.serve_forever()

def worker(identity,token,tx):
    from aak.crypto import b64decode
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aak.crypto import Ed25519Signer
    private=Ed25519PrivateKey.from_private_bytes(b64decode(os.environ["AAK_PRIVATE"]))
    signer=Ed25519Signer(private,private.public_key())
    signed=sign_service_request(signer,identity,"broker","/execute",
                                {"tx":tx,"token":token},100,tx)
    return post("http://broker:8080/",signed)

def orchestrate():
    from subprocess import run
    from aak.crypto import b64encode
    a,b=Ed25519Signer.generate(),Ed25519Signer.generate()
    fence=PostgresFencingStore(DSN)
    fence.initialize()
    token_a=fence.acquire("container-run","worker-A",30)
    env=os.environ.copy()
    env["AAK_PUBLIC_A"]=b64encode(a.public_key_bytes)
    env["AAK_PUBLIC_B"]=b64encode(b.public_key_bytes)
    # Both workers communicate with broker over the compose service network.
    # Broker is started with public keys injected into its environment.
    print(json.dumps({"public_A":env["AAK_PUBLIC_A"],"public_B":env["AAK_PUBLIC_B"],
                      "token_a":token_a}))
    fence.close()

if __name__=="__main__":
    {"broker":broker,"orchestrate":orchestrate}[sys.argv[1]]()
