import unittest
from aak.staging_postgres_tls import require_verified_postgres_tls

BASE="postgresql://aak_broker@db.internal:5432/aak_stage"

class StagingPostgresTLSChecks(unittest.TestCase):
    def test_verified_tls_required(self):
        for dsn in [BASE, BASE+"?sslmode=require", BASE+"?sslmode=verify-ca",
                    BASE+"?sslmode=verify-full", BASE+"?sslmode=disable"]:
            with self.subTest(dsn=dsn), self.assertRaises(ValueError):
                require_verified_postgres_tls(dsn)

    def test_non_admin_account(self):
        with self.assertRaisesRegex(ValueError,"dedicated_non_admin"):
            require_verified_postgres_tls(
                "postgresql://postgres@db.internal/aak?sslmode=verify-full&sslrootcert=/tls/ca.crt")

    def test_strict_staging_configuration(self):
        dsn=BASE+"?sslmode=verify-full&sslrootcert=/tls/ca.crt"
        self.assertEqual(require_verified_postgres_tls(dsn),dsn)

    def test_client_cert_needs_key(self):
        with self.assertRaisesRegex(ValueError,"postgres_client_key"):
            require_verified_postgres_tls(
                BASE+"?sslmode=verify-full&sslrootcert=/tls/ca.crt&sslcert=/tls/client.crt")

if __name__=="__main__":
    unittest.main()
