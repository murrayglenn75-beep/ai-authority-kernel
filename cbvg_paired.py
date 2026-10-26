"""Paired held-out outcome evaluator. Never confers execution authority."""
from dataclasses import dataclass
from math import comb

@dataclass(frozen=True)
class PairedResult:
    task_id: str
    baseline_passed: bool
    candidate_passed: bool

@dataclass(frozen=True)
class PairedAssessment:
    admitted: bool
    reason: str
    samples: int
    wins: int
    losses: int
    ties: int
    improvement: float
    one_sided_p: float

def assess_paired(results: tuple[PairedResult, ...], *, min_samples: int = 30,
                  min_relative_gain: float = 0.05, alpha: float = 0.05) -> PairedAssessment:
    """Exploratory paired exact discordance test; not release authorization.

    Independent test provenance, preregistration, multiple-comparison control,
    artifact binding and AAK grants must be enforced outside this function.
    """
    if min_samples < 1 or not 0 < alpha < 1 or not 0 < min_relative_gain <= 1:
        raise ValueError("invalid assessment configuration")
    if any(type(r.baseline_passed) is not bool or type(r.candidate_passed) is not bool
           or not isinstance(r.task_id, str) or not r.task_id.strip() for r in results):
        return PairedAssessment(False, "malformed_task", len(results), 0, 0, 0, 0.0, 1.0)
    ids = [r.task_id for r in results]
    if len(ids) != len(set(ids)):
        return PairedAssessment(False, "duplicate_task", len(results), 0, 0, 0, 0.0, 1.0)
    n = len(results)
    if n < min_samples:
        return PairedAssessment(False, "insufficient_samples", n, 0, 0, 0, 0.0, 1.0)
    wins = sum(r.candidate_passed and not r.baseline_passed for r in results)
    losses = sum(r.baseline_passed and not r.candidate_passed for r in results)
    baseline = sum(r.baseline_passed for r in results)
    candidate = sum(r.candidate_passed for r in results)
    ties = n - wins - losses
    improvement = (candidate - baseline) / n
    discordant = wins + losses
    p = (sum(comb(discordant, k) for k in range(wins, discordant + 1)) / (2 ** discordant)
         if discordant else 1.0)
    if improvement < min_relative_gain:
        reason = "insufficient_gain"
    elif p > alpha:
        reason = "insufficient_statistical_evidence"
    else:
        reason = "statistically_supported_not_release_authorization"
    return PairedAssessment(reason.startswith("statistically_supported"), reason,
                            n, wins, losses, ties, improvement, p)
