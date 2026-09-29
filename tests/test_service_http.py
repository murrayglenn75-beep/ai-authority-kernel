import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from aak import (
    AuditServiceEndpoint, DistributedBoundaryError, DurableAuditAnchor,
    Ed25519Signer, MTLSJSONClient, MTLSServiceHost, RemoteAuditAnchor,
    strict_json_loads,
)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class ServiceHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.root = root
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=AAK Test CA", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        cls._certificate("server", "DNS:localhost,URI:spiffe://aak/audit")
        cls._certificate("resource", "URI:spiffe://aak/resource")
        cls._certificate("evil", "URI:spiffe://aak/evil")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def _certificate(cls, name, san):
        root = cls.root
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
            "-keyout", str(root / f"{name}.key"), "-out", str(root / f"{name}.csr"))
        (root / f"{name}.ext").write_text(f"subjectAltName={san}\nextendedKeyUsage=clientAuth,serverAuth\n"
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n")
        run("openssl", "x509", "-req", "-days", "1", "-in", str(root / f"{name}.csr"),
            "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
            "-extfile", str(root / f"{name}.ext"), "-out", str(root / f"{name}.crt"))

    def test_duplicate_json_fields_fail_closed(self):
        with self.assertRaisesRegex(DistributedBoundaryError, "duplicate_service_field"):
            strict_json_loads(b'{"event":{},"event":{}}')

    def test_client_rejects_ambiguous_or_credentialed_service_urls(self):
        root = self.root
        for url in (
            "http://localhost:8443", "https://user@localhost:8443",
            "https://localhost:8443/base", "https://localhost:8443?target=other",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                ValueError, "invalid_service_client_configuration",
            ):
                MTLSJSONClient(
                    url, ca_file=str(root / "ca.crt"),
                    certificate_file=str(root / "resource.crt"),
                    private_key_file=str(root / "resource.key"),
                )

    def test_service_host_rejects_unsafe_capacity_configuration(self):
        root = self.root
        anchor = DurableAuditAnchor(":memory:", Ed25519Signer.generate(), anchor_id="http-test")
        self.addCleanup(anchor.close)
        endpoint = AuditServiceEndpoint(
            anchor,
            allowed_peers=frozenset({"spiffe://aak/resource"}),
        )
        for workers, timeout in ((0, 1), (257, 1), (1, 0), (1, 31)):
            with self.subTest(workers=workers, timeout=timeout), self.assertRaisesRegex(
                ValueError, "invalid_service_capacity_configuration",
            ):
                MTLSServiceHost(
                    endpoint, host="127.0.0.1", port=0,
                    ca_file=str(root / "ca.crt"), certificate_file=str(root / "server.crt"),
                    private_key_file=str(root / "server.key"), maximum_workers=workers,
                    connection_timeout=timeout,
                )

    def test_live_mtls_audit_service_accepts_only_allowed_workload(self):
        root = self.root
        with tempfile.TemporaryDirectory() as directory:
            events = []
            anchor = DurableAuditAnchor(
                Path(directory) / "audit.db", Ed25519Signer.generate(), anchor_id="http-test",
            )
            endpoint = AuditServiceEndpoint(
                anchor,
                allowed_peers=frozenset({"spiffe://aak/resource"}),
            )
            host = MTLSServiceHost(
                endpoint, host="127.0.0.1", port=0, ca_file=str(root / "ca.crt"),
                certificate_file=str(root / "server.crt"), private_key_file=str(root / "server.key"),
                event_sink=events.append,
            )
            thread = threading.Thread(target=host.serve_forever, daemon=True)
            thread.start()
            port = host.address[1]
            try:
                remote = RemoteAuditAnchor(MTLSJSONClient(
                    f"https://localhost:{port}", ca_file=str(root / "ca.crt"),
                    certificate_file=str(root / "resource.crt"), private_key_file=str(root / "resource.key"),
                ))
                self.assertEqual(remote.append({"type": "live-test"}).sequence, 1)
                denied = RemoteAuditAnchor(MTLSJSONClient(
                    f"https://localhost:{port}", ca_file=str(root / "ca.crt"),
                    certificate_file=str(root / "evil.crt"), private_key_file=str(root / "evil.key"),
                ))
                with self.assertRaises(DistributedBoundaryError):
                    denied.append({"type": "forbidden"})
                self.assertTrue(any(event["outcome"] == "denied" for event in events))
            finally:
                host.close()
                thread.join(timeout=2)
                anchor.close()


if __name__ == "__main__":
    unittest.main()
