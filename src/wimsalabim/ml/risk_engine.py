"""AI-driven risk assessment and recommendation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestRegressor
from sklearn.preprocessing import StandardScaler


@dataclass
class RiskAssessment:
    overall_risk: float = 0.0
    risk_label: str = ""
    confidence: float = 0.0
    risk_breakdown: dict[str, float] = field(default_factory=dict)
    recommendations: list[Recommendation] = field(default_factory=list)
    executive_summary: str = ""
    technical_summary: str = ""
    model_info: dict = field(default_factory=dict)


@dataclass
class Recommendation:
    priority: int
    title: str
    description: str
    category: str
    effort: str
    impact: str


def assess_risk(
    port_count: int = 0,
    risky_ports: int = 0,
    tls_grade: str = "N/A",
    tls_issues: list[str] | None = None,
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
    subdomain_count: int = 0,
    sensitive_subdomains: int = 0,
    sensitive_paths: int = 0,
    cve_critical: int = 0,
    cve_high: int = 0,
    cve_total: int = 0,
    cert_days_left: int = 365,
    domain_age_days: int = 365,
    anomaly_score: float = 0.0,
    attack_surface: float = 0.0,
) -> RiskAssessment:
    assessment = RiskAssessment()
    tls_issues = tls_issues or []
    dns_issues = dns_issues or []
    cloud_issues = cloud_issues or []

    grade_map = {"A": 1.0, "B": 0.75, "C": 0.5, "D": 0.25, "F": 0.0, "N/A": 0.0}

    features = {
        "port_count": port_count,
        "risky_ports": risky_ports,
        "tls_score": grade_map.get(tls_grade, 0.0),
        "tls_issue_count": len(tls_issues),
        "headers_score": grade_map.get(headers_grade, 0.0),
        "headers_missing": headers_missing,
        "info_leaks": info_leaks,
        "dns_issue_count": len(dns_issues),
        "email_score": grade_map.get(email_grade, 0.0),
        "cors_score": grade_map.get(cors_grade, 0.0),
        "cors_reflects": int(cors_reflects),
        "cookie_issues": cookie_issues,
        "waf_detected": int(waf_detected),
        "cloud_issue_count": len(cloud_issues),
        "subdomain_count": subdomain_count,
        "sensitive_subdomains": sensitive_subdomains,
        "sensitive_paths": sensitive_paths,
        "cve_critical": cve_critical,
        "cve_high": cve_high,
        "cve_total": cve_total,
        "cert_freshness": min(cert_days_left, 365) / 365.0,
        "domain_maturity": min(domain_age_days, 3650) / 3650.0,
        "anomaly_score": anomaly_score,
        "attack_surface": attack_surface,
    }

    risk_score, confidence, model_info = _ml_risk_prediction(features)
    assessment.overall_risk = risk_score
    assessment.confidence = confidence
    assessment.model_info = model_info

    if risk_score >= 0.8:
        assessment.risk_label = "CRITICAL"
    elif risk_score >= 0.6:
        assessment.risk_label = "HIGH"
    elif risk_score >= 0.4:
        assessment.risk_label = "MEDIUM"
    elif risk_score >= 0.2:
        assessment.risk_label = "LOW"
    else:
        assessment.risk_label = "MINIMAL"

    assessment.risk_breakdown = _compute_breakdown(features)
    assessment.recommendations = _generate_recommendations(features)
    assessment.executive_summary = _generate_executive_summary(assessment, features)
    assessment.technical_summary = _generate_technical_summary(assessment, features)

    return assessment


def _ml_risk_prediction(features: dict) -> tuple[float, float, dict]:
    """Ensemble ML prediction using GradientBoosting + RandomForest."""

    feature_keys = sorted(features.keys())
    X_target = np.array([[features[k] for k in feature_keys]])

    np.random.seed(42)
    n_samples = 500

    X_train = _generate_training_data(n_samples, feature_keys)
    y_train_reg = _compute_risk_labels(X_train, feature_keys)
    y_train_cls = np.digitize(y_train_reg, bins=[0.2, 0.4, 0.6, 0.8])

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_target_scaled = scaler.transform(X_target)

    gb_model = GradientBoostingClassifier(
        n_estimators=50, max_depth=4, random_state=42,
    )
    gb_model.fit(X_train_scaled, y_train_cls)
    gb_pred = gb_model.predict(X_target_scaled)[0]
    gb_proba = gb_model.predict_proba(X_target_scaled)[0]
    gb_confidence = float(max(gb_proba))

    rf_model = RandomForestRegressor(
        n_estimators=50, max_depth=5, random_state=42,
    )
    rf_model.fit(X_train_scaled, y_train_reg)
    rf_pred = float(rf_model.predict(X_target_scaled)[0])

    gb_risk = gb_pred / 4.0
    ensemble_risk = 0.6 * rf_pred + 0.4 * gb_risk
    ensemble_risk = max(0.0, min(1.0, ensemble_risk))

    ensemble_confidence = gb_confidence * 0.7 + 0.3

    model_info = {
        "ensemble": "GradientBoosting + RandomForest",
        "gb_class": int(gb_pred),
        "gb_confidence": round(gb_confidence, 3),
        "rf_score": round(rf_pred, 3),
        "final_score": round(ensemble_risk, 3),
        "training_samples": n_samples,
    }

    return ensemble_risk, ensemble_confidence, model_info


def _generate_training_data(n_samples: int, feature_keys: list[str]) -> np.ndarray:
    distributions = {
        "anomaly_score": lambda n: np.random.beta(2, 8, n),
        "attack_surface": lambda n: np.random.beta(2, 5, n),
        "cert_freshness": lambda n: np.random.beta(8, 2, n),
        "cloud_issue_count": lambda n: np.random.poisson(0.5, n).astype(float),
        "cookie_issues": lambda n: np.random.poisson(2, n).astype(float),
        "cors_reflects": lambda n: np.random.binomial(1, 0.1, n).astype(float),
        "cors_score": lambda n: np.random.beta(7, 3, n),
        "cve_critical": lambda n: np.random.poisson(0.3, n).astype(float),
        "cve_high": lambda n: np.random.poisson(0.8, n).astype(float),
        "cve_total": lambda n: np.random.poisson(3, n).astype(float),
        "dns_issue_count": lambda n: np.random.poisson(1, n).astype(float),
        "domain_maturity": lambda n: np.random.beta(8, 2, n),
        "email_score": lambda n: np.random.beta(5, 4, n),
        "headers_missing": lambda n: np.random.poisson(3, n).astype(float),
        "headers_score": lambda n: np.random.beta(6, 4, n),
        "info_leaks": lambda n: np.random.poisson(1, n).astype(float),
        "port_count": lambda n: np.random.poisson(4, n).astype(float),
        "risky_ports": lambda n: np.random.poisson(1, n).astype(float),
        "sensitive_paths": lambda n: np.random.poisson(1, n).astype(float),
        "sensitive_subdomains": lambda n: np.random.poisson(0.5, n).astype(float),
        "subdomain_count": lambda n: np.random.poisson(5, n).astype(float),
        "tls_issue_count": lambda n: np.random.poisson(1, n).astype(float),
        "tls_score": lambda n: np.random.beta(7, 3, n),
        "waf_detected": lambda n: np.random.binomial(1, 0.4, n).astype(float),
    }

    columns = []
    for key in feature_keys:
        if key in distributions:
            columns.append(distributions[key](n_samples))
        else:
            columns.append(np.random.uniform(0, 1, n_samples))

    return np.column_stack(columns)


def _compute_risk_labels(X: np.ndarray, feature_keys: list[str]) -> np.ndarray:
    idx = {k: i for i, k in enumerate(feature_keys)}
    risk = np.zeros(X.shape[0])

    w = {
        "risky_ports": 0.12, "tls_score": -0.15, "headers_score": -0.10,
        "info_leaks": 0.06, "dns_issue_count": 0.08, "email_score": -0.08,
        "cors_reflects": 0.10, "cookie_issues": 0.05, "waf_detected": -0.05,
        "sensitive_paths": 0.10, "cve_critical": 0.15, "cve_high": 0.08,
        "anomaly_score": 0.08, "attack_surface": 0.12,
        "cert_freshness": -0.05, "domain_maturity": -0.03,
    }

    for feature, weight in w.items():
        if feature in idx:
            risk += X[:, idx[feature]] * weight

    risk += 0.3
    return np.clip(risk, 0, 1)


def _compute_breakdown(features: dict) -> dict[str, float]:
    breakdown = {}

    breakdown["Network Exposure"] = min(1.0,
        features["risky_ports"] * 0.2 + features["port_count"] * 0.02
    )
    breakdown["Encryption"] = 1.0 - features["tls_score"]
    breakdown["Web Security"] = 1.0 - features["headers_score"]
    breakdown["Email Security"] = 1.0 - features["email_score"]
    breakdown["DNS Security"] = min(1.0, features["dns_issue_count"] * 0.25)
    breakdown["Known Vulnerabilities"] = min(1.0,
        features["cve_critical"] * 0.3 + features["cve_high"] * 0.15
    )
    breakdown["Information Leakage"] = min(1.0, features["info_leaks"] * 0.2)
    breakdown["Cloud Security"] = min(1.0, features["cloud_issue_count"] * 0.25)

    return {k: round(v, 3) for k, v in sorted(
        breakdown.items(), key=lambda x: x[1], reverse=True
    )}


def _generate_recommendations(features: dict) -> list[Recommendation]:
    recs = []
    priority = 1

    if features["cve_critical"] > 0:
        recs.append(Recommendation(
            priority=priority,
            title="Patch Critical Vulnerabilities",
            description=f"{features['cve_critical']} critical CVEs detected. Update affected software immediately.",
            category="Vulnerability Management",
            effort="medium",
            impact="critical",
        ))
        priority += 1

    if features["tls_score"] < 0.5:
        recs.append(Recommendation(
            priority=priority,
            title="Upgrade TLS Configuration",
            description="TLS configuration is weak. Enable TLS 1.3, disable weak ciphers, and ensure certificate validity.",
            category="Encryption",
            effort="low",
            impact="high",
        ))
        priority += 1

    if features["risky_ports"] > 0:
        recs.append(Recommendation(
            priority=priority,
            title="Restrict Exposed Services",
            description=f"{features['risky_ports']} risky ports are open. Move services behind a firewall or VPN.",
            category="Network Security",
            effort="medium",
            impact="critical",
        ))
        priority += 1

    if features["headers_missing"] >= 4:
        recs.append(Recommendation(
            priority=priority,
            title="Implement Security Headers",
            description=f"{features['headers_missing']} security headers are missing. Add CSP, HSTS, X-Frame-Options at minimum.",
            category="Web Security",
            effort="low",
            impact="medium",
        ))
        priority += 1

    if features["email_score"] < 0.5:
        recs.append(Recommendation(
            priority=priority,
            title="Configure Email Authentication",
            description="Email security is weak. Implement SPF (-all), DKIM, and DMARC (reject policy).",
            category="Email Security",
            effort="low",
            impact="high",
        ))
        priority += 1

    if features["cors_reflects"]:
        recs.append(Recommendation(
            priority=priority,
            title="Fix CORS Misconfiguration",
            description="CORS reflects arbitrary origins. Whitelist specific trusted domains only.",
            category="Web Security",
            effort="low",
            impact="high",
        ))
        priority += 1

    if features["sensitive_paths"] > 0:
        recs.append(Recommendation(
            priority=priority,
            title="Remove Exposed Sensitive Paths",
            description=f"{features['sensitive_paths']} sensitive paths are accessible. Block or remove these endpoints.",
            category="Access Control",
            effort="low",
            impact="high",
        ))
        priority += 1

    if not features["waf_detected"]:
        recs.append(Recommendation(
            priority=priority,
            title="Deploy Web Application Firewall",
            description="No WAF detected. Consider Cloudflare, AWS WAF, or ModSecurity for additional protection.",
            category="Defense in Depth",
            effort="medium",
            impact="medium",
        ))
        priority += 1

    if features["info_leaks"] >= 2:
        recs.append(Recommendation(
            priority=priority,
            title="Reduce Information Disclosure",
            description=f"{features['info_leaks']} server information headers are leaking. Remove Server, X-Powered-By headers.",
            category="Information Security",
            effort="low",
            impact="medium",
        ))
        priority += 1

    if features["sensitive_subdomains"] > 0:
        recs.append(Recommendation(
            priority=priority,
            title="Secure Sensitive Subdomains",
            description=f"{features['sensitive_subdomains']} sensitive subdomains are exposed. Restrict or remove them.",
            category="Attack Surface",
            effort="medium",
            impact="high",
        ))
        priority += 1

    return recs


def _generate_executive_summary(assessment: RiskAssessment, features: dict) -> str:
    risk = assessment.risk_label
    score = assessment.overall_risk
    rec_count = len(assessment.recommendations)

    parts = [
        f"Overall security risk: {risk} ({score:.0%}).",
    ]

    critical_areas = [k for k, v in assessment.risk_breakdown.items() if v > 0.5]
    if critical_areas:
        parts.append(f"Primary concerns: {', '.join(critical_areas[:3])}.")

    if rec_count > 0:
        parts.append(f"{rec_count} remediation actions recommended.")

    if features["cve_critical"] > 0:
        parts.append(f"URGENT: {features['cve_critical']} critical vulnerabilities require immediate attention.")

    return " ".join(parts)


def _generate_technical_summary(assessment: RiskAssessment, features: dict) -> str:
    parts = [
        f"Risk Score: {assessment.overall_risk:.3f} | Label: {assessment.risk_label} | Confidence: {assessment.confidence:.1%}",
        f"Model: {assessment.model_info.get('ensemble', 'N/A')}",
        f"Attack Surface: {features.get('attack_surface', 0):.3f}",
        f"Ports: {features['port_count']} open ({features['risky_ports']} risky)",
        f"TLS: {features['tls_score']:.0%} | Headers: {features['headers_score']:.0%} | Email: {features['email_score']:.0%}",
        f"CVEs: {features['cve_total']} total ({features['cve_critical']} critical, {features['cve_high']} high)",
    ]
    return " | ".join(parts)
