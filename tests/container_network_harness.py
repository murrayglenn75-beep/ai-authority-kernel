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

DSN=os.environ.get("AAK_TEST_POSTGRES_DSN", "")

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
    import subprocess
    import time
    import uuid
    from aak.crypto import b64encode
    from cryptography.hazmat.primitives import serialization
    suffix=uuid.uuid4().hex[:10]
    network="aak-proof-"+suffix
    db_name="aak-db-"+suffix
    broker_name="aak-broker-"+suffix
    image=os.environ.get("AAK_STAGING_IMAGE","aak-proof:ci")
    a,b=Ed25519Signer.generate(),Ed25519Signer.generate()
    keys={"worker-A":a,"worker-B":b}
    def docker(*args,check=True):
        return subprocess.run(["docker",*args],check=check,text=True,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    docker("network","create",network)
    try:
        docker("run","-d","--name",db_name,"--network",network,
               "-e","POSTGRES_USER=aaktest","-e","POSTGRES_PASSWORD=local_ci_only",
               "-e","POSTGRES_DB=aaktest","postgres:16")
        dsn="postgresql://aaktest:local_ci_only@"+db_name+":5432/aaktest"
        for _ in range(35):
            probe=docker("exec",db_name,"pg_isready","-U","aaktest","-d","aaktest",check=False)
            if probe.returncode==0: break
            time.sleep(0.3)
        else: raise RuntimeError("postgres not ready")
        docker("run","-d","--name",broker_name,"--network",network,"--network-alias","broker",
               "-e","AAK_TEST_POSTGRES_DSN="+dsn,
               "-e","AAK_PUBLIC_A="+b64encode(a.public_key_bytes),
               "-e","AAK_PUBLIC_B="+b64encode(b.public_key_bytes),
               image,"broker")
        def worker(identity,token,tx):
            signer=keys[identity]
            # Ed25519 raw private bytes are available only to the worker container.
            from cryptography.hazmat.primitives import serialization
            raw=signer._private_key.private_bytes(
                serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
            result=docker("run","--rm","--network",network,
                "-e","AAK_TEST_POSTGRES_DSN="+dsn,
                "-e","AAK_PRIVATE="+b64encode(raw),
                image,"worker",identity,str(token),tx,check=False)
            if result.returncode not in (0,3):
                raise RuntimeError("worker failed: "+result.stderr[-500:])
            return result.returncode
        for _ in range(30):
            # Check the broker actually accepts connections before dispatching.
            probe=docker("exec",broker_name,"python","-c",
                "import socket;socket.create_connection(('127.0.0.1',8080),1).close()",
                check=False)
            if probe.returncode==0: break
            time.sleep(0.2)
        else: raise RuntimeError("broker not ready")
        # The coordinator uses a separate container and a shared database.
        def claim(owner,expire=False):
            result=docker("run","--rm","--network",network,
                "-e","AAK_TEST_POSTGRES_DSN="+dsn,image,
                "claim",owner,"expire" if expire else "new")
            return int(result.stdout.strip())
        old=claim("worker-A")
        assert worker("worker-A",old,"tx-first")==0
        new=claim("worker-B",expire=True)
        assert new>old
        assert worker("worker-A",old,"tx-stale")==3
        # Inject a real Docker network disconnection for the obsolete worker.
        # The broker and PostgreSQL remain reachable to other containers.
        isolation_name="aak-isolated-"+suffix
        try:
            docker("run","-d","--name",isolation_name,"--network",network,
                "-e","AAK_TEST_POSTGRES_DSN="+dsn,
                "-e","AAK_PRIVATE="+b64encode(a._private_key.private_bytes(
                    serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                    serialization.NoEncryption())),
                "--entrypoint","sleep",image,"120",check=True)
            docker("network","disconnect","-f",network,isolation_name)
            isolated=docker("exec",isolation_name,"python","-c",
                "import socket;socket.create_connection(('broker',8080),2)",check=False)
            assert isolated.returncode != 0, "isolated worker could still reach broker"
            # Isolation must not affect the authority check for a new owner.
            assert worker("worker-B",new,"tx-second")==0
        finally:
            docker("rm","-f",isolation_name,check=False)
        assert worker("worker-B",new,"tx-second")==3
        print("container_network_proof=passed stale_worker=denied replay=denied")
    finally:
        docker("rm","-f",broker_name,check=False)
        docker("rm","-f",db_name,check=False)
        docker("network","rm",network,check=False)

def claim(owner,mode):
    fence=PostgresFencingStore(DSN)
    fence.initialize()
    if mode=="expire":
        with fence.db.transaction():
            fence.db.execute("UPDATE aak_worker_leases SET expires_at="
                "clock_timestamp()-interval '1 second' WHERE run_id='container-run'")
    token=fence.acquire("container-run",owner,30)
    print(token,flush=True)
    fence.close()

if __name__=="__main__":
    op=sys.argv[1]
    if op=="broker": broker()
    elif op=="worker":
        code=worker(sys.argv[2],int(sys.argv[3]),sys.argv[4])
        sys.exit(0 if code==200 else 3 if code==403 else 5)
    elif op=="claim": claim(sys.argv[2],sys.argv[3])
    elif op=="orchestrate": orchestrate()
    else: raise ValueError("invalid command")
