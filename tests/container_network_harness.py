"""Isolated container worker/broker service acceptance harness (staging only).

Uses signed per-worker messages and PostgreSQL coordination. The broker
authenticates the caller and checks the worker lease before simulated effects.
Never expose this HTTP-only harness to external networks.
"""
import json
import os
import sys
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from aak.postgres_fencing import PostgresFencingStore
from aak.postgres_service_replay import PostgresServiceReplayLedger
from aak.authenticated_service import AuthenticatedServiceDispatch, sign_service_request
from aak import (Ed25519Signer, ActionEnvelopeVerifier, ToolManifestVerifier, VerifyingEffectBroker, InputPolicy, SQLiteBrokerReplayStore, EffectBrokerEndpoint)
from aak.canonical import digest
from aak.crypto import b64decode, b64encode
from test_distributed import DistributedServiceTests, valid_close, jwt
from aak import AuthenticatedGatewayContext
from pathlib import Path
from tempfile import TemporaryDirectory
from http.server import HTTPServer

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
    keys={identity:Ed25519Signer.verifier(b64decode(os.environ["AAK_PUBLIC_"+identity[-1]]))
          for identity in ("worker-A","worker-B")}
    auth=AuthenticatedServiceDispatch(destination="broker",trusted_peers=keys,ledger=ledger)
    verifier=ActionEnvelopeVerifier(
        Ed25519Signer.verifier(b64decode(os.environ["AAK_ENVELOPE_PUBLIC"])),
        ToolManifestVerifier(Ed25519Signer.verifier(b64decode(os.environ["AAK_MANIFEST_PUBLIC"]))),
        expected_audience="crm-api")
    audit_key=Ed25519Signer.verifier(b64decode(os.environ["AAK_AUDIT_PUBLIC"]))
    directory=TemporaryDirectory()
    replay=SQLiteBrokerReplayStore(Path(directory.name)/"replay.db")
    calls=[]
    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            code=403
            try:
                length=int(self.headers.get("Content-Length","0"))
                if not 0<length<=32768: raise ValueError("invalid size")
                msg=json.loads(self.rfile.read(length))
                peer,path,data=auth.verify(msg,now=102)
                subject=self.connection.getpeercert().get("subject",())
                names=[v for group in subject for k,v in group if k=="commonName"]
                if names!=[peer]: raise ValueError("certificate identity mismatch")
                if set(data)!={"operation","lease_token"}: raise ValueError("invalid operation")
                token=data["lease_token"]
                if type(token) is not int or token<1: raise ValueError("invalid token")
                db=PostgresFencingStore(DSN)
                try:
                    core=VerifyingEffectBroker(
                        verifier=verifier,
                        provider=lambda **kw: calls.append(kw) or {"provider_reference":"test-only"},
                        allowed_origins=("https://crm.example",),
                        audit_anchor_id="aak-test-audit",
                        audit_verifiers={audit_key.key_id:audit_key},
                        replay_store=replay,
                        input_policies={"crm.ticket.update":InputPolicy(
                            os.environ["AAK_SCHEMA_HASH"],valid_close)},
                        dispatch_fence=db.broker_fence(run_id="container-run",owner=peer,token=token))
                    endpoint=EffectBrokerEndpoint(core,allowed_peers=frozenset(keys),clock=lambda:102)
                    outcome=endpoint.handle(path,data["operation"],peer_identity=peer)
                    if outcome["status"]=="succeeded": code=200
                finally:
                    db.close()
            except Exception:
                code=403
            self.send_response(code)
            self.send_header("Content-Length","0")
            self.end_headers()
    try:
        server=HTTPServer(("0.0.0.0",8080),Endpoint)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("/tls/server.crt","/tls/server.key")
        tls.load_verify_locations(cafile="/tls/ca.crt")
        tls.verify_mode=ssl.CERT_REQUIRED
        server.socket=tls.wrap_socket(server.socket,server_side=True)
        server.serve_forever()
    finally:
        replay.close()
        directory.cleanup()
        ledger.close()
        fence.close()

def worker(identity,token,tx):
    from aak.crypto import b64decode
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aak.crypto import Ed25519Signer
    private=Ed25519PrivateKey.from_private_bytes(b64decode(os.environ["AAK_PRIVATE"]))
    signer=Ed25519Signer(private,private.public_key())
    signed=sign_service_request(signer,identity,"broker","/v1/effects/execute",
                                {"operation":json.loads(os.environ["AAK_OPERATION"]),
                                 "lease_token":token},102,tx)
    context=ssl.create_default_context(cafile="/tls/ca.crt")
    context.load_cert_chain("/tls/client.crt","/tls/client.key")
    data=json.dumps(signed).encode()
    request=Request("https://broker:8080/",data=data,
                    headers={"Content-Type":"application/json"},method="POST")
    try:
        with urlopen(request,timeout=5,context=context) as response:
            return response.status
    except HTTPError as exc:
        return exc.code

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
    fixture=DistributedServiceTests(methodName="test_exact_grant_executes_once_without_exposing_credential")
    fixture.setUp()
    temporary=TemporaryDirectory()
    from aak import DurableAuditAnchor
    anchor=DurableAuditAnchor(Path(temporary.name)/"audit.db",fixture.audit_key,anchor_id=fixture.audit_id)
    a,b=Ed25519Signer.generate(),Ed25519Signer.generate()
    keys={"worker-A":a,"worker-B":b}
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=15)
    certs=Path(temporary.name)/"tls"
    certs.mkdir()
    openssl("req","-x509","-newkey","rsa:2048","-sha256","-nodes",
            "-subj","/CN=AAK CI Test CA","-days","1",
            "-keyout",str(certs/"ca.key"),"-out",str(certs/"ca.crt"))
    for cn,stub in (("broker","server"),("worker-A","A"),("worker-B","B")):
        openssl("req","-newkey","rsa:2048","-nodes","-subj","/CN="+cn,
                "-keyout",str(certs/(stub+".key")),
                "-out",str(certs/(stub+".csr")))
        ext=certs/(stub+".ext")
        ext.write_text(("subjectAltName=DNS:broker\nextendedKeyUsage=serverAuth\n"
                        if cn=="broker" else "extendedKeyUsage=clientAuth\n"))
        openssl("x509","-req","-in",str(certs/(stub+".csr")),
                "-CA",str(certs/"ca.crt"),"-CAkey",str(certs/"ca.key"),
                "-CAcreateserial","-out",str(certs/(stub+".crt")),
                "-days","1","-sha256","-extfile",str(ext))
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
               "-e","AAK_ENVELOPE_PUBLIC="+b64encode(fixture.envelope_key.public_key_bytes),
               "-e","AAK_MANIFEST_PUBLIC="+b64encode(fixture.manifest_key.public_key_bytes),
               "-e","AAK_AUDIT_PUBLIC="+b64encode(fixture.audit_key.public_key_bytes),
               "-e","AAK_SCHEMA_HASH="+fixture.manifest.input_schema_hash,
               "-v",str(certs/"ca.crt")+":/tls/ca.crt:ro",
               "-v",str(certs/"server.crt")+":/tls/server.crt:ro",
               "-v",str(certs/"server.key")+":/tls/server.key:ro",
               image,"broker")
        operations={}
        def operation(tx):
            if tx in operations: return operations[tx]
            identity_payload={"iss":"https://identity.internal",
                "sub":"spiffe://aak/agent/support","aud":"resource-verifier",
                "iat":100,"nbf":100,"exp":130,"jti":"token-"+tx,
                "cnf":{"x5t#S256":"cert-1"}}
            context=AuthenticatedGatewayContext("user:glenn","close resolved ticket",
                jwt(fixture.identity_key,identity_payload),"cert-1")
            grant=fixture.gateway.authorize_mcp({**fixture.request,"id":tx},context,now=101)
            action_hash=digest(grant.envelope.claim())
            event={"type":"action_authorized","envelope_id":grant.envelope.envelope_id,
                   "transaction_id":grant.envelope.transaction_id,
                   "request_hash":grant.call.request_hash,
                   "agent_identity":grant.envelope.agent_identity,
                   "policy_decision_id":grant.envelope.policy_decision_id,
                   "action_hash":action_hash}
            receipt=anchor.append(event)
            operations[tx]={"origin":"https://crm.example","audience":"crm-api",
                    "action_hash":action_hash,"call":grant.call.to_wire(),"grant":grant.to_wire(),
                    "authorization_event":event,"authorization_receipt":receipt.to_wire()}
            return operations[tx]
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
                "-e","AAK_OPERATION="+json.dumps(operation(tx)),
                "-v",str(certs/"ca.crt")+":/tls/ca.crt:ro",
                "-v",str(certs/(identity[-1]+".crt"))+":/tls/client.crt:ro",
                "-v",str(certs/(identity[-1]+".key"))+":/tls/client.key:ro",
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
        anchor.close()
        temporary.cleanup()

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
