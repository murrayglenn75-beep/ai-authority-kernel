from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Rule:
    action: str
    resource_prefix: str
    principals: frozenset[str]
    max_effect: dict[str, float] = field(default_factory=dict)
    required_approvals: int = 0
    authorized_approvers: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Policy:
    version: str
    rules: tuple[Rule, ...]
    hard_denies: frozenset[str] = frozenset()

    def evaluate(self, proposal: Any) -> tuple[bool, str, Rule | None]:
        if proposal.action in self.hard_denies:
            return False, "hard_deny", None
        for rule in self.rules:
            if (
                proposal.action == rule.action
                and proposal.resource.startswith(rule.resource_prefix)
                and proposal.principal_id in rule.principals
            ):
                for key, requested in proposal.maximum_effect.items():
                    if requested < 0 or requested > rule.max_effect.get(key, 0):
                        return False, f"effect_limit:{key}", rule
                unique_approvals = set(proposal.approvals)
                if proposal.principal_id in unique_approvals:
                    return False, "self_approval", rule
                if not unique_approvals.issubset(rule.authorized_approvers):
                    return False, "unauthorized_approver", rule
                if len(unique_approvals) < rule.required_approvals:
                    return False, "insufficient_independent_approvals", rule
                return True, "allowed", rule
        return False, "no_matching_rule", None
