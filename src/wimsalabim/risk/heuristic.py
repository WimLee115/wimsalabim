"""HeuristicRiskEngine — transparent, rule-based, audit-friendly.

No black box. No fake training-samples. Every point in the score is
attributable to a registered rule with id, severity, CWE, and rationale.

Grading is **severity-aware**: any unmitigated ``critical`` rule pulls the
final grade to D-or-worse, even if the raw point sum would land in C-band.
This reflects how rational operators actually treat criticals.
"""

from __future__ import annotations

from collections import Counter

from wimsalabim.core.schema import (
    AnalyzerResult,
    Grade,
    RiskAssessment,
    RuleHit,
    Severity,
)
from wimsalabim.risk.rules import RULE_REGISTRY, Rule

# ── Score thresholds → grade ────────────────────────────────────────────
# Sorted descending; first threshold whose score is met wins.
_GRADE_TABLE: tuple[tuple[float, Grade], ...] = (
    (70.0, "F"),
    (50.0, "D"),
    (30.0, "C"),
    (15.0, "B"),
    (0.0, "A"),
)
# Critical findings force the grade no higher than this (unless score >= 70).
_CRITICAL_GRADE_FLOOR: Grade = "D"


def _score_to_grade(score: float, hits: list[RuleHit]) -> Grade:
    has_critical = any(h.severity == "critical" for h in hits)
    base: Grade = next(g for threshold, g in _GRADE_TABLE if score >= threshold)
    if has_critical and base in ("A", "B", "C"):
        return _CRITICAL_GRADE_FLOOR
    return base


class HeuristicRiskEngine:
    """Run all registered rules; collect hits; sum into a score."""

    name = "rules"

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else RULE_REGISTRY

    def assess(self, analyzers: dict[str, AnalyzerResult]) -> RiskAssessment:
        hits: list[RuleHit] = []
        score = 0.0

        for rule in self._rules:
            if rule.predicate(analyzers):
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        points=rule.points,
                        rationale=rule.rationale_fn(analyzers),
                        cwe=rule.cwe,
                    )
                )
                score += rule.points

        score = min(score, 100.0)
        grade = _score_to_grade(score, hits)

        sev_counts: Counter[Severity] = Counter(h.severity for h in hits)
        summary = _summary(score, grade, hits)

        return RiskAssessment(
            engine="rules",
            overall_score=score,
            grade=grade,
            rules_fired=hits,
            summary=summary,
            severity_counts=dict(sev_counts),
        )


def _summary(score: float, grade: Grade, hits: list[RuleHit]) -> str:
    if not hits:
        return f"Clean: no rules fired. Score {score:.1f}/100, grade {grade}."
    crit = sum(1 for h in hits if h.severity == "critical")
    high = sum(1 for h in hits if h.severity == "high")
    parts = [f"Grade {grade} ({score:.1f}/100)"]
    if crit:
        parts.append(f"{crit} critical")
    if high:
        parts.append(f"{high} high")
    parts.append(f"{len(hits)} rule(s) fired total.")
    return " — ".join(parts)


__all__ = ["HeuristicRiskEngine"]
