from dataclasses import dataclass
import math
from typing import Any, Callable


Validator = Callable[[str, dict[str, Any]], bool]
EffectDeriver = Callable[[str, dict[str, Any]], dict[str, float]]
Handler = Callable[[str, dict[str, Any]], Any]


@dataclass(frozen=True)
class ToolContract:
    """Trusted adapter registered by application code, never by the model."""

    action: str
    validate: Validator
    derive_effect: EffectDeriver
    handler: Handler

    def assessed_effect(self, resource: str, parameters: dict[str, Any]) -> dict[str, float]:
        if not self.validate(resource, parameters):
            raise ValueError("tool_contract_validation_failed")
        effect = self.derive_effect(resource, parameters)
        if (
            not isinstance(effect, dict)
            or not effect
            or any(
                not isinstance(k, str)
                or isinstance(v, bool)
                or not isinstance(v, (int, float))
                or not math.isfinite(float(v))
                or v < 0
                for k, v in effect.items()
            )
        ):
            raise ValueError("invalid_derived_effect")
        return {key: float(value) for key, value in effect.items()}
