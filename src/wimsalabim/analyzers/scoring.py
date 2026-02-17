"""Aggregate security scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CategoryScore:
    name: str
    score: int
    max_score: int
    grade: str
    weight: float
    issues: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> float:
        return (self.score / self.max_score * 100) if self.max_score > 0 else 0


@dataclass
class ScoringReport:
    target: str
    categories: list[CategoryScore] = field(default_factory=list)
    overall_score: float = 0.0
    overall_grade: str = "N/A"
    risk_level: str = "Unknown"
    total_issues: int = 0
    critical_issues: int = 0
    summary: str = ""

    @property
    def grade_color(self) -> str:
        return {
            "A": "green", "B": "blue", "C": "yellow",
            "D": "dark_orange", "F": "red", "N/A": "dim",
        }.get(self.overall_grade, "white")


CATEGORY_WEIGHTS = {
    "TLS/SSL": 0.20,
    "HTTP Headers": 0.15,
    "DNS": 0.10,
    "Email Security": 0.10,
    "Ports": 0.15,
    "CORS": 0.10,
    "Cookies": 0.05,
    "WAF": 0.05,
    "Cloud": 0.05,
    "ML Risk": 0.05,
}


def calculate_scores(
    tls_grade: str = "N/A",
    tls_issues: list[str] | None = None,
    headers_grade: str = "N/A",
    headers_issues: list[str] | None = None,
    dns_issues: list[str] | None = None,
    email_grade: str = "N/A",
    email_issues: list[str] | None = None,
    ports_open: int = 0,
    ports_risky: int = 0,
    cors_issues: list[str] | None = None,
    cookie_issues: list[str] | None = None,
    waf_detected: bool = False,
    cloud_issues: list[str] | None = None,
    ml_risk_score: float = 0.0,
) -> ScoringReport:
    report = ScoringReport(target="aggregate")
    all_issues: list[str] = []

    def _grade_to_score(grade: str) -> int:
        return {"A": 95, "B": 80, "C": 60, "D": 40, "F": 15, "N/A": 0}.get(grade, 0)

    tls_score = _grade_to_score(tls_grade)
    report.categories.append(CategoryScore(
        name="TLS/SSL", score=tls_score, max_score=100,
        grade=tls_grade, weight=CATEGORY_WEIGHTS["TLS/SSL"],
        issues=tls_issues or [],
    ))
    all_issues.extend(tls_issues or [])

    headers_score = _grade_to_score(headers_grade)
    report.categories.append(CategoryScore(
        name="HTTP Headers", score=headers_score, max_score=100,
        grade=headers_grade, weight=CATEGORY_WEIGHTS["HTTP Headers"],
        issues=headers_issues or [],
    ))
    all_issues.extend(headers_issues or [])

    dns_score = 90 if not dns_issues else max(30, 90 - len(dns_issues or []) * 20)
    dns_grade = _score_to_grade(dns_score)
    report.categories.append(CategoryScore(
        name="DNS", score=dns_score, max_score=100,
        grade=dns_grade, weight=CATEGORY_WEIGHTS["DNS"],
        issues=dns_issues or [],
    ))
    all_issues.extend(dns_issues or [])

    email_score = _grade_to_score(email_grade)
    report.categories.append(CategoryScore(
        name="Email Security", score=email_score, max_score=100,
        grade=email_grade, weight=CATEGORY_WEIGHTS["Email Security"],
        issues=email_issues or [],
    ))
    all_issues.extend(email_issues or [])

    port_issues = []
    if ports_risky > 0:
        port_issues.append(f"{ports_risky} risky ports open")
    if ports_open > 10:
        port_issues.append(f"High number of open ports: {ports_open}")
    port_score = max(0, 100 - ports_risky * 20 - max(0, ports_open - 5) * 5)
    report.categories.append(CategoryScore(
        name="Ports", score=port_score, max_score=100,
        grade=_score_to_grade(port_score), weight=CATEGORY_WEIGHTS["Ports"],
        issues=port_issues,
    ))
    all_issues.extend(port_issues)

    cors_score = 90 if not cors_issues else max(20, 90 - len(cors_issues or []) * 25)
    report.categories.append(CategoryScore(
        name="CORS", score=cors_score, max_score=100,
        grade=_score_to_grade(cors_score), weight=CATEGORY_WEIGHTS["CORS"],
        issues=cors_issues or [],
    ))
    all_issues.extend(cors_issues or [])

    cookie_score = 90 if not cookie_issues else max(20, 90 - len(cookie_issues or []) * 15)
    report.categories.append(CategoryScore(
        name="Cookies", score=cookie_score, max_score=100,
        grade=_score_to_grade(cookie_score), weight=CATEGORY_WEIGHTS["Cookies"],
        issues=cookie_issues or [],
    ))
    all_issues.extend(cookie_issues or [])

    waf_score = 90 if waf_detected else 40
    waf_issues_list = [] if waf_detected else ["No WAF detected"]
    report.categories.append(CategoryScore(
        name="WAF", score=waf_score, max_score=100,
        grade=_score_to_grade(waf_score), weight=CATEGORY_WEIGHTS["WAF"],
        issues=waf_issues_list,
    ))
    if not waf_detected:
        all_issues.append("No WAF detected")

    cloud_score = 90 if not cloud_issues else max(30, 90 - len(cloud_issues or []) * 20)
    report.categories.append(CategoryScore(
        name="Cloud", score=cloud_score, max_score=100,
        grade=_score_to_grade(cloud_score), weight=CATEGORY_WEIGHTS["Cloud"],
        issues=cloud_issues or [],
    ))
    all_issues.extend(cloud_issues or [])

    ml_score = max(0, 100 - int(ml_risk_score * 100))
    report.categories.append(CategoryScore(
        name="ML Risk", score=ml_score, max_score=100,
        grade=_score_to_grade(ml_score), weight=CATEGORY_WEIGHTS["ML Risk"],
        issues=[f"ML risk score: {ml_risk_score:.2f}"] if ml_risk_score > 0.3 else [],
    ))

    weighted_total = sum(c.score * c.weight for c in report.categories)
    weight_sum = sum(c.weight for c in report.categories)
    report.overall_score = round(weighted_total / weight_sum, 1) if weight_sum > 0 else 0
    report.overall_grade = _score_to_grade(report.overall_score)
    report.total_issues = len(all_issues)
    report.critical_issues = sum(1 for i in all_issues if any(
        w in i.lower() for w in ("expired", "dangerous", "critical", "risky")
    ))

    if report.overall_score >= 85:
        report.risk_level = "Low"
    elif report.overall_score >= 65:
        report.risk_level = "Medium"
    elif report.overall_score >= 40:
        report.risk_level = "High"
    else:
        report.risk_level = "Critical"

    return report


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
