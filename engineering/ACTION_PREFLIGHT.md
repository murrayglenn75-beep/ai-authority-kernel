# Expiring approval and action-budget preflight

Opt-in deterministic helper: `engineering/action_preflight.py`. Run `cd engineering && python -m unittest -v test_action_preflight.py`.

**Security scope:** strict JSON rejects duplicate keys and nonstandard constants. `preflight` checks exact action, resource and principal binding; expiry; use count; estimated cost and a verified approval-ID set passed by a trusted caller. All publication requests are blocked pending a distinct release policy gate. The helper never issues tokens, executes tools, obtains credentials or authenticates the approval itself.

**Critical integration requirements:** Do not let an LLM provide the `verified_approval_ids` list or decide `now`. Binding the ID alone does not authenticate or cryptographically bind the contents of an approval; existing independent AAK policies and signed/action-bound capabilities remain mandatory. Use budgets must be atomically consumed by the authority service to prevent concurrent replay. Estimated cost is not an enforced spend cap until actual cost accounting is integrated. Tool calls need pre-execution control and post-effect receipts. Publishing requires an external pre-publication authorization gate; post-publication checks cannot undo an exposure.

Prototype local isolated test run: 14/14 passed on 2026-11-11. Repository CI and actual runtime integration are not yet verified.
