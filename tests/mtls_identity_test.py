"""Local mutual-TLS identity test using synthetic certificates."""

import http.client
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Handler(BaseHTTPRequestHandler):
    identities = []

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        certificate = self.connection.getpeercert()
        common_name = next(value for group in certificate["subject"] for key, value in group if key == "commonName")
        self.identities.append(common_name)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(common_name.encode())


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    server_key, server_csr, server_cert = root / "server.key", root / "server.csr", root / "server.crt"
    client_key, client_csr, client_cert = root / "client.key", root / "client.csr", root / "client.crt"
    attacker_key, attacker_cert = root / "attacker.key", root / "attacker.crt"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=AAK Test CA", "-keyout", str(ca_key), "-out", str(ca_cert))
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(server_key), "-out", str(server_csr))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert))
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=executor-mtls", "-keyout", str(client_key), "-out", str(client_csr))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(client_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(client_cert))
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=attacker", "-keyout", str(attacker_key), "-out", str(attacker_cert))

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(server_cert, server_key)
    server_context.load_verify_locations(ca_cert)
    server_context.verify_mode = ssl.CERT_REQUIRED
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def connect(cert=None, key=None):
        context = ssl.create_default_context(cafile=ca_cert)
        context.check_hostname = False
        if cert:
            context.load_cert_chain(cert, key)
        connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=context, timeout=3)
        connection.request("GET", "/identity")
        response = connection.getresponse()
        body = response.read().decode()
        connection.close()
        return response.status, body

    try:
        assert connect(client_cert, client_key) == (200, "executor-mtls")
        for cert, key in ((None, None), (attacker_cert, attacker_key)):
            try:
                connect(cert, key)
            except (ssl.SSLError, ConnectionError, OSError):
                pass
            else:
                raise AssertionError("untrusted TLS client reached the service")
        assert Handler.identities == ["executor-mtls"]
        print("mtls_attempts=3 trusted_accepted=1 untrusted_rejected=2 crashes=0")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
