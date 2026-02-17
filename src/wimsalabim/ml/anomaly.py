"""ML-powered anomaly detection for network scan results."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class Anomaly:
    category: str
    description: str
    severity: str
    score: float
    details: dict = field(default_factory=dict)


@dataclass
class AnomalyReport:
    anomalies: list[Anomaly] = field(default_factory=list)
    total_features_analyzed: int = 0
    anomaly_score: float = 0.0

    @property
    def anomaly_count(self) -> int:
        return len(self.anomalies)

    @property
    def has_critical(self) -> bool:
        return any(a.severity == "critical" for a in self.anomalies)


NORMAL_PORT_PROFILES = {
    "web_server": [80, 443],
    "mail_server": [25, 110, 143, 465, 587, 993, 995],
    "database_server": [3306, 5432, 27017, 6379],
    "standard_web": [22, 80, 443],
    "corporate": [22, 25, 80, 110, 143, 443, 993, 995],
}

UNUSUAL_PORT_COMBOS = [
    ({3306, 27017}, "Multiple database types exposed simultaneously"),
    ({21, 23}, "Legacy insecure protocols (FTP + Telnet)"),
    ({6379, 9200}, "Unprotected data stores (Redis + Elasticsearch)"),
    ({5900, 3389}, "Multiple remote access protocols"),
    ({8080, 8443, 9090}, "Multiple management/proxy interfaces"),
    ({111, 2049}, "NFS services exposed"),
    ({135, 139, 445}, "Windows SMB stack exposed"),
    ({161, 162}, "SNMP services exposed"),
]


def detect_anomalies(
    open_ports: list[int],
    tls_score: float = 1.0,
    headers_score: float = 1.0,
    dns_record_count: int = 0,
    subdomain_count: int = 0,
    tech_count: int = 0,
    cookie_count: int = 0,
    info_leak_count: int = 0,
    days_until_cert_expiry: int = 365,
    domain_age_days: int = 365,
) -> AnomalyReport:
    report = AnomalyReport()

    _detect_port_anomalies(open_ports, report)
    _detect_config_anomalies(
        tls_score, headers_score, dns_record_count,
        cookie_count, info_leak_count, days_until_cert_expiry,
        domain_age_days, report,
    )
    _ml_anomaly_detection(
        open_ports, tls_score, headers_score, dns_record_count,
        subdomain_count, tech_count, cookie_count, info_leak_count,
        days_until_cert_expiry, domain_age_days, report,
    )

    if report.anomalies:
        scores = [a.score for a in report.anomalies]
        report.anomaly_score = max(scores)

    return report


def _detect_port_anomalies(open_ports: list[int], report: AnomalyReport) -> None:
    port_set = set(open_ports)

    for combo, description in UNUSUAL_PORT_COMBOS:
        if combo.issubset(port_set):
            report.anomalies.append(Anomaly(
                category="Port Configuration",
                description=description,
                severity="high",
                score=0.7,
                details={"ports": sorted(combo)},
            ))

    if len(open_ports) > 15:
        report.anomalies.append(Anomaly(
            category="Port Configuration",
            description=f"Unusually high number of open ports ({len(open_ports)})",
            severity="high",
            score=0.8,
            details={"open_count": len(open_ports)},
        ))

    high_ports = [p for p in open_ports if p > 10000]
    if len(high_ports) > 3:
        report.anomalies.append(Anomaly(
            category="Port Configuration",
            description=f"Multiple high-numbered ports open ({len(high_ports)})",
            severity="medium",
            score=0.5,
            details={"high_ports": high_ports},
        ))

    matched_profiles = []
    for profile_name, profile_ports in NORMAL_PORT_PROFILES.items():
        overlap = port_set.intersection(profile_ports)
        if len(overlap) >= len(profile_ports) * 0.5:
            matched_profiles.append(profile_name)

    if not matched_profiles and len(open_ports) > 3:
        report.anomalies.append(Anomaly(
            category="Port Configuration",
            description="Port configuration doesn't match any standard profile",
            severity="medium",
            score=0.4,
            details={"open_ports": open_ports},
        ))


def _detect_config_anomalies(
    tls_score: float,
    headers_score: float,
    dns_record_count: int,
    cookie_count: int,
    info_leak_count: int,
    days_until_cert_expiry: int,
    domain_age_days: int,
    report: AnomalyReport,
) -> None:
    if tls_score < 0.4 and headers_score < 0.4:
        report.anomalies.append(Anomaly(
            category="Security Configuration",
            description="Both TLS and HTTP headers have poor security scores",
            severity="critical",
            score=0.9,
            details={"tls_score": tls_score, "headers_score": headers_score},
        ))

    if info_leak_count >= 3:
        report.anomalies.append(Anomaly(
            category="Information Disclosure",
            description=f"Excessive information leakage ({info_leak_count} headers)",
            severity="high",
            score=0.7,
            details={"leak_count": info_leak_count},
        ))

    if 0 < days_until_cert_expiry < 14:
        report.anomalies.append(Anomaly(
            category="Certificate",
            description=f"Certificate expiring very soon ({days_until_cert_expiry} days)",
            severity="critical",
            score=0.85,
            details={"days_left": days_until_cert_expiry},
        ))

    if 0 < domain_age_days < 30:
        report.anomalies.append(Anomaly(
            category="Domain",
            description=f"Very new domain ({domain_age_days} days old)",
            severity="medium",
            score=0.6,
            details={"age_days": domain_age_days},
        ))

    if cookie_count > 15:
        report.anomalies.append(Anomaly(
            category="Privacy",
            description=f"Excessive number of cookies ({cookie_count})",
            severity="medium",
            score=0.5,
            details={"cookie_count": cookie_count},
        ))


def _ml_anomaly_detection(
    open_ports: list[int],
    tls_score: float,
    headers_score: float,
    dns_record_count: int,
    subdomain_count: int,
    tech_count: int,
    cookie_count: int,
    info_leak_count: int,
    days_until_cert_expiry: int,
    domain_age_days: int,
    report: AnomalyReport,
) -> None:
    """Use Isolation Forest to detect statistical anomalies."""

    target_features = np.array([[
        len(open_ports),
        tls_score,
        headers_score,
        dns_record_count,
        subdomain_count,
        tech_count,
        cookie_count,
        info_leak_count,
        min(days_until_cert_expiry, 730) / 730.0,
        min(domain_age_days, 3650) / 3650.0,
    ]])

    np.random.seed(42)
    n_samples = 200
    normal_data = np.column_stack([
        np.random.poisson(4, n_samples),                    # open ports
        np.random.beta(8, 2, n_samples),                    # tls score
        np.random.beta(6, 3, n_samples),                    # headers score
        np.random.poisson(8, n_samples),                    # dns records
        np.random.poisson(5, n_samples),                    # subdomains
        np.random.poisson(6, n_samples),                    # tech count
        np.random.poisson(5, n_samples),                    # cookies
        np.random.poisson(1, n_samples),                    # info leaks
        np.random.beta(8, 2, n_samples),                    # cert freshness
        np.random.beta(9, 1, n_samples),                    # domain maturity
    ])

    combined = np.vstack([normal_data, target_features])

    scaler = StandardScaler()
    scaled = scaler.fit_transform(combined)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
    )
    model.fit(scaled)

    target_scaled = scaled[-1:].reshape(1, -1)
    prediction = model.predict(target_scaled)[0]
    anomaly_score_raw = model.decision_function(target_scaled)[0]

    anomaly_score = max(0.0, min(1.0, 0.5 - anomaly_score_raw))

    report.total_features_analyzed = target_features.shape[1]

    if prediction == -1:
        report.anomalies.append(Anomaly(
            category="ML Detection",
            description="Statistical anomaly detected in overall security profile",
            severity="high" if anomaly_score > 0.7 else "medium",
            score=anomaly_score,
            details={
                "isolation_score": round(float(anomaly_score_raw), 4),
                "normalized_score": round(anomaly_score, 4),
                "features_analyzed": target_features.shape[1],
                "model": "IsolationForest",
            },
        ))
