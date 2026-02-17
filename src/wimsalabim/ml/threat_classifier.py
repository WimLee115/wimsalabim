"""ML-powered threat classification engine."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder


@dataclass
class ThreatVector:
    name: str
    category: str
    likelihood: float
    impact: str
    description: str
    mitigations: list[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    threats: list[ThreatVector] = field(default_factory=list)
    attack_surface_score: float = 0.0
    primary_risk_category: str = ""
    threat_model: str = ""

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def critical_threats(self) -> list[ThreatVector]:
        return [t for t in self.threats if t.impact == "critical"]

    @property
    def high_threats(self) -> list[ThreatVector]:
        return [t for t in self.threats if t.impact == "high"]


THREAT_KNOWLEDGE_BASE = {
    "exposed_admin": {
        "name": "Exposed Administration Panel",
        "category": "Access Control",
        "impact": "critical",
        "description": "Admin interfaces accessible from the internet enable brute-force and credential stuffing attacks",
        "mitigations": [
            "Restrict admin access to VPN/internal network",
            "Implement MFA for admin accounts",
            "Use IP whitelisting",
            "Implement account lockout policies",
        ],
    },
    "weak_tls": {
        "name": "Weak TLS Configuration",
        "category": "Encryption",
        "impact": "high",
        "description": "Weak TLS allows man-in-the-middle attacks and data interception",
        "mitigations": [
            "Upgrade to TLS 1.3",
            "Disable weak cipher suites",
            "Enable HSTS with long max-age",
            "Use certificate pinning for APIs",
        ],
    },
    "missing_headers": {
        "name": "Missing Security Headers",
        "category": "Web Security",
        "impact": "medium",
        "description": "Missing headers enable XSS, clickjacking, and MIME-type attacks",
        "mitigations": [
            "Implement Content-Security-Policy",
            "Add X-Frame-Options: DENY",
            "Set X-Content-Type-Options: nosniff",
            "Configure Referrer-Policy",
        ],
    },
    "info_disclosure": {
        "name": "Information Disclosure",
        "category": "Information Leak",
        "impact": "medium",
        "description": "Server/technology versions revealed enable targeted exploit selection",
        "mitigations": [
            "Remove Server header version info",
            "Remove X-Powered-By header",
            "Customize error pages",
            "Disable directory listing",
        ],
    },
    "dns_misconfiguration": {
        "name": "DNS Misconfiguration",
        "category": "Infrastructure",
        "impact": "high",
        "description": "DNS misconfigurations enable zone transfers, subdomain takeover, and cache poisoning",
        "mitigations": [
            "Enable DNSSEC",
            "Disable zone transfers",
            "Monitor for subdomain takeover",
            "Use DNS monitoring service",
        ],
    },
    "email_spoofing": {
        "name": "Email Spoofing Vulnerability",
        "category": "Email Security",
        "impact": "high",
        "description": "Missing or weak SPF/DKIM/DMARC allows email spoofing and phishing",
        "mitigations": [
            "Implement SPF with -all",
            "Configure DKIM signing",
            "Set DMARC policy to reject",
            "Enable DMARC reporting",
        ],
    },
    "cors_misconfiguration": {
        "name": "CORS Misconfiguration",
        "category": "Web Security",
        "impact": "high",
        "description": "CORS misconfigurations allow cross-origin data theft",
        "mitigations": [
            "Whitelist specific trusted origins",
            "Never reflect arbitrary Origin headers",
            "Don't allow null origin",
            "Avoid wildcard with credentials",
        ],
    },
    "exposed_services": {
        "name": "Exposed Internal Services",
        "category": "Network Security",
        "impact": "critical",
        "description": "Database/cache/admin services directly accessible from the internet",
        "mitigations": [
            "Move services behind firewall",
            "Use VPN for remote access",
            "Implement network segmentation",
            "Enable authentication on all services",
        ],
    },
    "cloud_misconfiguration": {
        "name": "Cloud Resource Misconfiguration",
        "category": "Cloud Security",
        "impact": "high",
        "description": "Exposed cloud storage or misconfigured cloud services",
        "mitigations": [
            "Review bucket/blob access policies",
            "Enable cloud security posture management",
            "Use infrastructure-as-code with security checks",
            "Implement least-privilege access",
        ],
    },
    "cookie_security": {
        "name": "Cookie Security Issues",
        "category": "Session Security",
        "impact": "medium",
        "description": "Missing cookie flags enable session hijacking and CSRF attacks",
        "mitigations": [
            "Set Secure flag on all cookies",
            "Set HttpOnly on session cookies",
            "Implement SameSite=Strict",
            "Use short session timeouts",
        ],
    },
    "no_waf": {
        "name": "No WAF Detected",
        "category": "Defense in Depth",
        "impact": "medium",
        "description": "Absence of WAF leaves application directly exposed to web attacks",
        "mitigations": [
            "Deploy a Web Application Firewall",
            "Consider cloud-based WAF (Cloudflare, AWS WAF)",
            "Implement rate limiting",
            "Enable bot detection",
        ],
    },
    "subdomain_exposure": {
        "name": "Sensitive Subdomain Exposure",
        "category": "Attack Surface",
        "impact": "high",
        "description": "Development/admin/internal subdomains publicly accessible",
        "mitigations": [
            "Remove unused DNS records",
            "Restrict access to internal subdomains",
            "Monitor for subdomain takeover",
            "Use VPN for dev/staging environments",
        ],
    },
}


def classify_threats(
    open_ports: list[int] | None = None,
    risky_ports: int = 0,
    tls_grade: str = "N/A",
    headers_grade: str = "N/A",
    headers_missing: int = 0,
    info_leaks: int = 0,
    dns_issues: list[str] | None = None,
    email_grade: str = "N/A",
    cors_grade: str = "N/A",
    cors_reflects: bool = False,
    cookie_issues: int = 0,
    waf_detected: bool = False,
    cloud_issues: list[str] | None = None,
    sensitive_subdomains: int = 0,
    sensitive_paths: int = 0,
    cve_critical: int = 0,
    cve_high: int = 0,
) -> ThreatReport:
    report = ThreatReport()
    open_ports = open_ports or []
    dns_issues = dns_issues or []
    cloud_issues = cloud_issues or []

    features = _extract_features(
        open_ports, risky_ports, tls_grade, headers_grade,
        headers_missing, info_leaks, dns_issues, email_grade,
        cors_grade, cors_reflects, cookie_issues, waf_detected,
        cloud_issues, sensitive_subdomains, sensitive_paths,
        cve_critical, cve_high,
    )

    _rule_based_threats(features, report)
    _ml_threat_scoring(features, report)
    _calculate_attack_surface(features, report)

    report.threats.sort(key=lambda t: {
        "critical": 0, "high": 1, "medium": 2, "low": 3
    }.get(t.impact, 4))

    if report.threats:
        categories = [t.category for t in report.threats[:3]]
        from collections import Counter
        most_common = Counter(categories).most_common(1)
        report.primary_risk_category = most_common[0][0] if most_common else ""

    return report


def _extract_features(
    open_ports, risky_ports, tls_grade, headers_grade,
    headers_missing, info_leaks, dns_issues, email_grade,
    cors_grade, cors_reflects, cookie_issues, waf_detected,
    cloud_issues, sensitive_subdomains, sensitive_paths,
    cve_critical, cve_high,
) -> dict:
    grade_map = {"A": 1.0, "B": 0.75, "C": 0.5, "D": 0.25, "F": 0.0, "N/A": 0.0}
    return {
        "port_count": len(open_ports),
        "risky_ports": risky_ports,
        "tls_score": grade_map.get(tls_grade, 0.0),
        "headers_score": grade_map.get(headers_grade, 0.0),
        "headers_missing": headers_missing,
        "info_leaks": info_leaks,
        "dns_issue_count": len(dns_issues),
        "email_score": grade_map.get(email_grade, 0.0),
        "cors_score": grade_map.get(cors_grade, 0.0),
        "cors_reflects": cors_reflects,
        "cookie_issues": cookie_issues,
        "waf_detected": waf_detected,
        "cloud_issue_count": len(cloud_issues),
        "sensitive_subdomains": sensitive_subdomains,
        "sensitive_paths": sensitive_paths,
        "cve_critical": cve_critical,
        "cve_high": cve_high,
        "has_dangerous_ports": any(p in open_ports for p in [23, 21, 161, 514]),
        "has_db_ports": any(p in open_ports for p in [3306, 5432, 27017, 6379, 9200]),
    }


def _rule_based_threats(features: dict, report: ThreatReport) -> None:
    if features["has_dangerous_ports"] or features["has_db_ports"]:
        kb = THREAT_KNOWLEDGE_BASE["exposed_services"]
        report.threats.append(ThreatVector(
            likelihood=0.9 if features["has_db_ports"] else 0.7,
            **kb,
        ))

    if features["tls_score"] < 0.5:
        kb = THREAT_KNOWLEDGE_BASE["weak_tls"]
        report.threats.append(ThreatVector(
            likelihood=0.8,
            **kb,
        ))

    if features["headers_missing"] >= 5:
        kb = THREAT_KNOWLEDGE_BASE["missing_headers"]
        report.threats.append(ThreatVector(
            likelihood=0.7,
            **kb,
        ))

    if features["info_leaks"] >= 2:
        kb = THREAT_KNOWLEDGE_BASE["info_disclosure"]
        report.threats.append(ThreatVector(
            likelihood=0.6,
            **kb,
        ))

    if features["dns_issue_count"] > 0:
        kb = THREAT_KNOWLEDGE_BASE["dns_misconfiguration"]
        report.threats.append(ThreatVector(
            likelihood=0.5 + features["dns_issue_count"] * 0.1,
            **kb,
        ))

    if features["email_score"] < 0.5:
        kb = THREAT_KNOWLEDGE_BASE["email_spoofing"]
        report.threats.append(ThreatVector(
            likelihood=0.7,
            **kb,
        ))

    if features["cors_reflects"]:
        kb = THREAT_KNOWLEDGE_BASE["cors_misconfiguration"]
        report.threats.append(ThreatVector(
            likelihood=0.85,
            **kb,
        ))

    if features["cookie_issues"] > 0:
        kb = THREAT_KNOWLEDGE_BASE["cookie_security"]
        report.threats.append(ThreatVector(
            likelihood=0.5 + min(features["cookie_issues"] * 0.05, 0.3),
            **kb,
        ))

    if not features["waf_detected"]:
        kb = THREAT_KNOWLEDGE_BASE["no_waf"]
        report.threats.append(ThreatVector(
            likelihood=0.4,
            **kb,
        ))

    if features["cloud_issue_count"] > 0:
        kb = THREAT_KNOWLEDGE_BASE["cloud_misconfiguration"]
        report.threats.append(ThreatVector(
            likelihood=0.6,
            **kb,
        ))

    if features["sensitive_subdomains"] > 0:
        kb = THREAT_KNOWLEDGE_BASE["subdomain_exposure"]
        report.threats.append(ThreatVector(
            likelihood=0.7,
            **kb,
        ))

    if features["sensitive_paths"] > 0:
        kb = THREAT_KNOWLEDGE_BASE["exposed_admin"]
        report.threats.append(ThreatVector(
            likelihood=0.8,
            **kb,
        ))


def _ml_threat_scoring(features: dict, report: ThreatReport) -> None:
    """Use a Decision Tree to refine threat likelihood scores."""

    np.random.seed(42)
    n_samples = 300

    feature_keys = [
        "port_count", "risky_ports", "tls_score", "headers_score",
        "headers_missing", "info_leaks", "dns_issue_count", "email_score",
        "cors_score", "cookie_issues", "sensitive_paths", "cve_critical",
    ]

    X_train = np.column_stack([
        np.random.poisson(4, n_samples),
        np.random.poisson(1, n_samples),
        np.random.beta(7, 3, n_samples),
        np.random.beta(6, 4, n_samples),
        np.random.poisson(3, n_samples),
        np.random.poisson(1, n_samples),
        np.random.poisson(1, n_samples),
        np.random.beta(6, 4, n_samples),
        np.random.beta(7, 3, n_samples),
        np.random.poisson(2, n_samples),
        np.random.poisson(1, n_samples),
        np.random.poisson(0.5, n_samples),
    ])

    risk_scores = (
        X_train[:, 1] * 0.2 +
        (1 - X_train[:, 2]) * 0.15 +
        (1 - X_train[:, 3]) * 0.1 +
        X_train[:, 4] * 0.05 +
        X_train[:, 5] * 0.1 +
        X_train[:, 6] * 0.1 +
        (1 - X_train[:, 7]) * 0.1 +
        (1 - X_train[:, 8]) * 0.05 +
        X_train[:, 9] * 0.05 +
        X_train[:, 10] * 0.1 +
        X_train[:, 11] * 0.15
    )
    y_train = np.digitize(risk_scores, bins=[0.3, 0.6, 0.8])

    clf = DecisionTreeClassifier(max_depth=5, random_state=42)
    clf.fit(X_train, y_train)

    X_target = np.array([[
        features.get(k, 0) if isinstance(features.get(k, 0), (int, float))
        else int(features.get(k, False))
        for k in feature_keys
    ]])

    predicted_class = clf.predict(X_target)[0]
    probabilities = clf.predict_proba(X_target)[0]

    risk_level = ["low", "medium", "high", "critical"][min(predicted_class, 3)]
    confidence = float(max(probabilities))

    for threat in report.threats:
        if risk_level in ("high", "critical"):
            threat.likelihood = min(1.0, threat.likelihood * 1.15)
        elif risk_level == "low":
            threat.likelihood = max(0.1, threat.likelihood * 0.85)

    report.threat_model = f"DecisionTree(risk={risk_level}, confidence={confidence:.2f})"


def _calculate_attack_surface(features: dict, report: ThreatReport) -> None:
    surface = 0.0
    surface += min(features["port_count"] * 0.03, 0.2)
    surface += features["risky_ports"] * 0.08
    surface += (1 - features["tls_score"]) * 0.1
    surface += (1 - features["headers_score"]) * 0.08
    surface += features["info_leaks"] * 0.04
    surface += features["sensitive_subdomains"] * 0.06
    surface += features["sensitive_paths"] * 0.08
    surface += features["cve_critical"] * 0.12
    surface += features["cve_high"] * 0.06
    surface += 0.05 if not features["waf_detected"] else 0
    surface += 0.03 if features["cors_reflects"] else 0

    report.attack_surface_score = min(1.0, surface)
