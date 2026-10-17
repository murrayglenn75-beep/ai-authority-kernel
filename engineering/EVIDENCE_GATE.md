# Murray Method evidence preflight v0.1
Six-stage check: **Define → Plan → Test first → Execute → Verify → Release**.
This preflight validates only the supplied evidence manifest's schema and declared statuses. It does **not** confirm that CI actually ran, that its referenced artifacts are authentic, that reviewers approved, or that deployed behavior is safe. Never describe a passed preflight as production certification.

Run: `python engineering/evidence_gate.py path/to/evidence.json`

Manifest structure: `{"commit_sha":"<commit>","approved":true,"approval_evidence":"<review URL>","define":{"status":"passed","evidence":"<link>"},"plan":{"status":"passed","evidence":"<link>"},"test_first":{"status":"passed","evidence":"<link>"},"execute":{"status":"passed","evidence":"<link>"},"verify":{"status":"passed","evidence":"<link>"},"release":{"status":"passed","evidence":"<link>"}}`.

**Promotion rule:** an independent trusted CI system must match evidence to the actual target commit and workflow run, check immutable artifacts and approval provenance, then enforce branch/deployment protection. This checker is a documentation and preflight tool only.
