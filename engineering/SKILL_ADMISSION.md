# Trusted skills admission prototype (not an installer)
The registry inspects the skill payload against a SHA-256 pin, an immutable GitHub commit ID, a permission allowlist, and an **independently verified approval set provided by a trusted caller**. It defaults to denying absent approvals.
Only trusted server-side code may supply approvals. Do not obtain trusted approvals from untrusted skill manifests or agent prompts. GitHub URL and commit strings here are only syntactic checks, not proof that a commit belongs to the referenced repository. Fetching artifacts, verifying provenance, scanning nested files and scripts, sandbox execution, and enforcement at the actual tool boundary remain separate requirements.
Run: `python -m unittest discover -s engineering -p 'test_*.py' -q`.
Initial skill candidates (not installed): debugging; regression-test generation; independent review; defensive security review; evidence-backed release verification.
