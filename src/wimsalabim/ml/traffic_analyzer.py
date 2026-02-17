"""ML-powered traffic pattern analysis and threat intelligence. rootmap:WimLee115"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier


@dataclass
class TrafficPattern:
    name: str
    description: str
    confidence: float = 0.0
    risk: str = "info"


@dataclass
class ThreatIntel:
    category: str
    description: str
    severity: str
    confidence: float
    source: str = "ml_model"
    indicators: list[str] = field(default_factory=list)


@dataclass
class TrafficAnalysisReport:
    patterns: list[TrafficPattern] = field(default_factory=list)
    threat_intel: list[ThreatIntel] = field(default_factory=list)
    cluster_profile: str = ""
    cluster_label: str = ""
    behavioral_risk: float = 0.0
    intelligence_score: float = 0.0
    model_info: dict = field(default_factory=dict)

    @property
    def pattern_count(self) -> int:
        return len(self.patterns)

    @property
    def threat_count(self) -> int:
        return len(self.threat_intel)


def analyze_traffic_patterns(
    open_ports: list[int] | None = None,
    latency_samples: list[float] | None = None,
    jitter_ms: float = 0.0,
    packet_loss_pct: float = 0.0,
    tls_handshake_ms: float = 0.0,
    bandwidth_mbps: float = 0.0,
    http_status: int = 200,
    response_time_ms: float = 0.0,
    tech_count: int = 0,
    cookie_count: int = 0,
    header_count: int = 0,
    subdomain_count: int = 0,
    cve_count: int = 0,
    waf_detected: bool = False,
) -> TrafficAnalysisReport:
    report = TrafficAnalysisReport()

    features = _build_feature_vector(
        open_ports or [], latency_samples or [], jitter_ms,
        packet_loss_pct, tls_handshake_ms, bandwidth_mbps,
        http_status, response_time_ms, tech_count, cookie_count,
        header_count, subdomain_count, cve_count, waf_detected,
    )

    _cluster_analysis(features, report)
    _pattern_detection(features, report)
    _threat_intelligence(features, report)
    _behavioral_scoring(features, report)

    return report


def _build_feature_vector(
    open_ports, latency_samples, jitter_ms, packet_loss_pct,
    tls_handshake_ms, bandwidth_mbps, http_status, response_time_ms,
    tech_count, cookie_count, header_count, subdomain_count,
    cve_count, waf_detected,
) -> dict:
    avg_latency = np.mean(latency_samples) if latency_samples else 0
    latency_var = np.var(latency_samples) if len(latency_samples) > 1 else 0

    return {
        "port_count": len(open_ports),
        "high_ports": sum(1 for p in open_ports if p > 10000),
        "service_ports": sum(1 for p in open_ports if p < 1024),
        "avg_latency": float(avg_latency),
        "latency_variance": float(latency_var),
        "jitter": jitter_ms,
        "packet_loss": packet_loss_pct,
        "tls_handshake": tls_handshake_ms,
        "bandwidth": bandwidth_mbps,
        "http_status": http_status,
        "response_time": response_time_ms,
        "tech_count": tech_count,
        "cookie_count": cookie_count,
        "header_count": header_count,
        "subdomain_count": subdomain_count,
        "cve_count": cve_count,
        "waf": int(waf_detected),
    }


def _cluster_analysis(features: dict, report: TrafficAnalysisReport) -> None:
    """Use K-Means to classify the target's profile against known archetypes."""
    np.random.seed(42)

    archetypes = {
        "secure_enterprise": [3, 0, 3, 30, 5, 2, 0, 80, 50, 200, 50, 8, 3, 8, 5, 0, 1],
        "standard_web": [3, 0, 2, 50, 20, 5, 0, 100, 30, 200, 100, 6, 5, 5, 3, 0, 0],
        "vulnerable_target": [10, 3, 7, 80, 50, 15, 2, 200, 10, 200, 200, 10, 8, 3, 10, 5, 0],
        "minimal_service": [1, 0, 1, 20, 2, 1, 0, 60, 100, 200, 30, 2, 0, 2, 0, 0, 0],
        "cloud_hosted": [2, 0, 2, 15, 3, 1, 0, 40, 80, 200, 20, 5, 3, 7, 8, 0, 1],
    }

    keys = sorted(features.keys())
    target_vec = np.array([[features[k] for k in keys]])

    all_data = []
    labels = []
    for name, vec in archetypes.items():
        for _ in range(20):
            noise = np.random.normal(0, 0.1, len(vec)) * np.array(vec)
            all_data.append(np.array(vec) + noise)
            labels.append(name)

    X = np.array(all_data)

    kmeans = KMeans(n_clusters=5, random_state=42, n_init=10)
    kmeans.fit(X)

    target_padded = np.zeros((1, X.shape[1]))
    min_len = min(target_vec.shape[1], X.shape[1])
    target_padded[0, :min_len] = target_vec[0, :min_len]

    cluster = kmeans.predict(target_padded)[0]

    archetype_clusters = {}
    for i, label in enumerate(labels):
        c = kmeans.predict(X[i:i+1])[0]
        archetype_clusters.setdefault(c, []).append(label)

    cluster_labels = archetype_clusters.get(cluster, ["unknown"])
    from collections import Counter
    most_common = Counter(cluster_labels).most_common(1)
    profile = most_common[0][0] if most_common else "unknown"

    report.cluster_profile = profile
    report.cluster_label = profile.replace("_", " ").title()
    report.model_info["clustering"] = {
        "algorithm": "KMeans",
        "n_clusters": 5,
        "assigned_cluster": int(cluster),
        "profile": profile,
    }


def _pattern_detection(features: dict, report: TrafficAnalysisReport) -> None:
    """Detect notable traffic patterns."""

    if features["avg_latency"] > 0 and features["latency_variance"] > features["avg_latency"] * 2:
        report.patterns.append(TrafficPattern(
            name="Latency Spike Pattern",
            description="High variance in latency indicates intermittent network issues or DDoS mitigation",
            confidence=0.8,
            risk="medium",
        ))

    if features["packet_loss"] > 0 and features["jitter"] > 20:
        report.patterns.append(TrafficPattern(
            name="Network Degradation Pattern",
            description="Combined packet loss and jitter indicate network path issues",
            confidence=0.85,
            risk="high",
        ))

    if features["tls_handshake"] > 300:
        report.patterns.append(TrafficPattern(
            name="Slow Crypto Handshake",
            description="TLS handshake exceeds 300ms, may indicate server load or weak hardware",
            confidence=0.7,
            risk="medium",
        ))

    if features["port_count"] > 8 and not features["waf"]:
        report.patterns.append(TrafficPattern(
            name="Wide Attack Surface",
            description="Many open ports without WAF protection increases exposure",
            confidence=0.9,
            risk="high",
        ))

    if features["subdomain_count"] > 50:
        report.patterns.append(TrafficPattern(
            name="Subdomain Sprawl",
            description="Large number of subdomains increases monitoring complexity and takeover risk",
            confidence=0.75,
            risk="medium",
        ))

    if features["response_time"] > 500:
        report.patterns.append(TrafficPattern(
            name="High Response Latency",
            description="Server response time exceeds 500ms, possible performance bottleneck",
            confidence=0.7,
            risk="low",
        ))

    if features["tech_count"] > 10:
        report.patterns.append(TrafficPattern(
            name="Complex Stack",
            description="Large technology stack increases dependency management overhead",
            confidence=0.6,
            risk="low",
        ))

    if features["cve_count"] > 0 and features["port_count"] > 5:
        report.patterns.append(TrafficPattern(
            name="Exploitable Profile",
            description="Known CVEs combined with multiple open ports create exploitation opportunities",
            confidence=0.85,
            risk="critical",
        ))


def _threat_intelligence(features: dict, report: TrafficAnalysisReport) -> None:
    """ML-based threat intelligence from observed characteristics."""

    np.random.seed(42)
    n_samples = 300

    feature_keys = sorted(features.keys())
    X_train = np.random.uniform(0, 1, (n_samples, len(feature_keys)))

    risk = (
        X_train[:, feature_keys.index("port_count")] * 0.15 +
        X_train[:, feature_keys.index("cve_count")] * 0.2 +
        X_train[:, feature_keys.index("packet_loss")] * 0.15 +
        (1 - X_train[:, feature_keys.index("waf")]) * 0.1 +
        X_train[:, feature_keys.index("high_ports")] * 0.1 +
        X_train[:, feature_keys.index("subdomain_count")] * 0.05 +
        X_train[:, feature_keys.index("jitter")] * 0.05
    )
    y_train = np.digitize(risk, bins=[0.15, 0.3, 0.5])

    clf = RandomForestClassifier(n_estimators=50, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    X_target = np.array([[min(1, features[k] / max(1, abs(features[k]) * 2 + 1)) for k in feature_keys]])
    predicted = clf.predict(X_target)[0]
    proba = clf.predict_proba(X_target)[0]

    threat_levels = ["minimal", "low", "moderate", "elevated"]
    level = threat_levels[min(predicted, len(threat_levels) - 1)]
    confidence = float(max(proba))

    report.intelligence_score = predicted / 3.0

    if level in ("moderate", "elevated"):
        report.threat_intel.append(ThreatIntel(
            category="Network Threat Level",
            description=f"ML model predicts {level} threat level based on network characteristics",
            severity=level,
            confidence=confidence,
            indicators=[
                f"Open ports: {features['port_count']}",
                f"CVEs: {features['cve_count']}",
                f"Jitter: {features['jitter']}ms",
            ],
        ))

    if features["packet_loss"] > 0:
        report.threat_intel.append(ThreatIntel(
            category="Network Reliability",
            description="Packet loss may indicate network issues, congestion, or active interference",
            severity="low" if features["packet_loss"] < 3 else "moderate",
            confidence=0.7,
            indicators=[f"Packet loss: {features['packet_loss']}%"],
        ))

    if features["cve_count"] > 0:
        report.threat_intel.append(ThreatIntel(
            category="Vulnerability Exposure",
            description=f"{features['cve_count']} known vulnerabilities in detected technology stack",
            severity="elevated" if features["cve_count"] > 3 else "moderate",
            confidence=0.9,
            indicators=[f"CVE count: {features['cve_count']}"],
        ))

    report.model_info["threat_intel"] = {
        "algorithm": "RandomForestClassifier",
        "predicted_level": level,
        "confidence": round(confidence, 3),
    }


def _behavioral_scoring(features: dict, report: TrafficAnalysisReport) -> None:
    """Calculate overall behavioral risk score."""
    risk = 0.0

    risk += min(0.15, features["port_count"] * 0.015)
    risk += min(0.1, features["cve_count"] * 0.03)
    risk += min(0.1, features["packet_loss"] * 0.02)
    risk += min(0.1, features["jitter"] * 0.002)
    risk += 0.05 if not features["waf"] else 0
    risk += min(0.1, features["high_ports"] * 0.03)
    risk += min(0.05, features["subdomain_count"] * 0.001)
    risk += 0.05 if features["tls_handshake"] > 300 else 0
    risk += min(0.1, features["latency_variance"] * 0.001)

    report.behavioral_risk = round(min(1.0, risk), 3)
