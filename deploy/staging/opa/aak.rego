package aak.authority

import rego.v1

default allow := false

registered_actions := {
  "crm.ticket.update": {"risk": "medium", "records_written": 1},
}

allow if {
  input.schema_version == 1
  input.human_principal != ""
  input.agent_identity != ""
  input.purpose != ""
  registered_actions[input.action]
  input.resource == "tenant/acme/ticket"
  input.audience == "crm-api"
}

decision := {
  "allow": allow,
  "decision_id": sprintf("opa-%s", [input.request_hash]),
  "policy_version": "aak-staging-1",
  "maximum_effect": {"records_written": registered_actions[input.action].records_written},
  "approval_refs": [],
} if allow

decision := {
  "allow": false,
  "decision_id": sprintf("opa-deny-%s", [object.get(input, "request_hash", "missing")]),
  "policy_version": "aak-staging-1",
  "maximum_effect": {"records_written": 0},
  "approval_refs": [],
} if not allow
