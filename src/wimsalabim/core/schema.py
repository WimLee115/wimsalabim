"""Canonical schemas — every analyzer, every report, every finding lives here.

Pydantic v2, frozen-by-default. A report once produced is immutable; that
is what lets us hash it, sign it, and timestamp it (see ``crypto`` /
``timestamps`` modules).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ─── Type aliases ────────────────────────────────────────────────────────
Grade = Literal["A", "B", "C", "D", "F", "N/A"]
Severity = Literal["critical", "high", "medium", "low", "info"]
LegalClass = Literal["passive", "active", "intrusive"]
"""``passive``  — only public data (DNS, WHOIS, CT, Wayback, single GET).
``active``   — direct network probes against target (port-scan, dir-scan).
``intrusive``— anything that may alter or stress target state.

The Authorization Gate (``core.authorization``) consults this label to
decide whether the analyzer is allowed to run against a given target.
"""

ScoreFloat = Annotated[float, Field(ge=0.0, le=100.0)]
SchemaVersion = Literal["wimsalabim/2.0"]


# ─── Provenance ──────────────────────────────────────────────────────────
class Source(BaseModel):
    """Where did this observation come from?

    Required on every Finding. No claim without a source; no source
    without a timestamp; no timestamp without a hash where applicable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(
        description="Origin kind: 'http', 'dns', 'tls', 'ct_log', 'whois', 'wayback', ..."
    )
    target: str = Field(description="The probed target (host, URL, IP, domain).")
    timestamp: datetime = Field(description="When the observation was recorded (UTC).")
    body_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 of raw response body, when applicable.",
    )
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


# ─── Findings & rules ────────────────────────────────────────────────────
class Finding(BaseModel):
    """One concrete observation an analyzer wants to report.

    Findings carry CWE/CVSS where applicable so we can emit SARIF and
    CycloneDX VEX cleanly downstream.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(description="Stable id within analyzer scope, e.g. 'tls.cert.expiring'.")
    title: str
    description: str
    severity: Severity
    source: Source
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    cvss_vector: str | None = Field(default=None, description="CVSS v4.0 vector if applicable.")
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


class RuleHit(BaseModel):
    """One rule the HeuristicRiskEngine fired.

    Every point added to the overall score is traceable to a rule_id that
    is registered in ``risk.rules`` with a human-readable rationale.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    rule_name: str
    severity: Severity
    points: float = Field(ge=0.0)
    rationale: str
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")


# ─── Reports ─────────────────────────────────────────────────────────────
class BaseReport(BaseModel):
    """The contract every analyzer satisfies."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    analyzer: str
    target: str
    started_at: datetime
    duration_ms: float = Field(ge=0.0)
    grade: Grade = "N/A"
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)


class AnalyzerResult(BaseModel):
    """Wraps an analyzer outcome with status — never raise across the boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    legal_class: LegalClass
    status: Literal["ok", "skipped", "denied", "error"]
    report: BaseReport | None = None
    skip_reason: str | None = None
    error_kind: str | None = None
    error_message: str | None = None


class RiskAssessment(BaseModel):
    """The top-level risk verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine: Literal["rules", "ml"] = "rules"
    overall_score: ScoreFloat
    grade: Grade
    rules_fired: list[RuleHit]
    summary: str
    severity_counts: dict[Severity, int] = Field(default_factory=dict)


class Authorization(BaseModel):
    """Proof that operator may scan target — verified by the gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str
    mode: Literal["self_owned", "dns_txt", "well_known", "bug_bounty"]
    evidence: str
    verified_at: datetime


class ScanReport(BaseModel):
    """The full, signable, OTS-anchorable result of one scan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: SchemaVersion = "wimsalabim/2.0"
    tool_version: str
    target: str
    started_at: datetime
    duration_ms: float = Field(ge=0.0)
    config_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    authorization: Authorization | None = None
    analyzers: dict[str, AnalyzerResult]
    risk: RiskAssessment | None = None
    signature: str | None = Field(
        default=None,
        description=(
            "Ed25519 signature over canonical JSON (RFC 8785) of this report "
            "with 'signature' and 'ots_proof_path' fields removed."
        ),
    )
    signing_pubkey: str | None = None
    ots_proof_path: str | None = None


__all__ = [
    "AnalyzerResult",
    "Authorization",
    "BaseReport",
    "Finding",
    "Grade",
    "LegalClass",
    "RiskAssessment",
    "RuleHit",
    "ScanReport",
    "SchemaVersion",
    "ScoreFloat",
    "Severity",
    "Source",
]
