# AAK v1.6.0-rc1 Windows test-repair patch

This package is a patched **release candidate**, not a production certification.

Changes:
- Explicit ownership and close-before-temp-directory-removal for SQLite audit and broker fixtures in distributed and service API tests. No test assertions or security checks removed.
- HTTP service tests close their audit anchors after server shutdown.
- OpenSSL-generated *test-only* CA uses explicit critical CA/basic constraints and keyCertSign/cRLSign key usage. Issued test certificates use CA:FALSE and digital signature/key encipherment. TLS validation remains enabled.
- Git Bash setup prefers Python 3.12 when installed. Run from the `aak` directory.

Verification performed in the build environment: `python -W error::ResourceWarning -m unittest discover -s tests -q` — 218 tests passed. This environment is Linux/Python 3.13; Windows/Python 3.12 and the full extended campaigns have **not** been verified here. The SQLite lifetime fix needs your Windows run as final validation.

On Windows Git Bash, extract zip and run:

```bash
cd ~/Downloads/AAK-v1.6.0-patched/aak
py -3.12 --version
# If an old .venv exists from a different version, rename it first.
./setup-gitbash.sh
./run-tests-gitbash.sh
# After basic tests pass: ./run-tests-gitbash.sh --full
```

Do not commit `.venv`, keys, databases, or test-generated files.

- Follow-up HTTP event ordering: record each request outcome before sending its response, preventing the requesting test client from observing the response before its in-process security event has been appended. This closes an observed Windows scheduling race in the mTLS denial test; access checks and TLS verification are unchanged.
