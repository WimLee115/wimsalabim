"""Tests for Wimsalabim ML/AI engine. rootmap:WimLee115"""

from __future__ import annotations

import pytest


# === Anomaly Detection Tests ===

class TestAnomalyDetection:
    def test_anomaly_dataclass(self):
        from wimsalabim.ml.anomaly import Anomaly
        a = Anomaly(
            category="Port", description="test", severity="high", score=0.8,
        )
        assert a.category == "Port"
        assert a.score == 0.8

    def test_anomaly_report_properties(self):
        from wimsalabim.ml.anomaly import AnomalyReport, Anomaly
        report = AnomalyReport()
        report.anomalies.append(
            Anomaly("Test", "desc", "critical", 0.9)
        )
        assert report.anomaly_count == 1
        assert report.has_critical

    def test_detect_port_anomalies_unusual_combo(self):
        from wimsalabim.ml.anomaly import _detect_port_anomalies, AnomalyReport
        report = AnomalyReport()
        _detect_port_anomalies([21, 23, 80, 443], report)
        assert any("Legacy" in a.description for a in report.anomalies)

    def test_detect_port_anomalies_too_many(self):
        from wimsalabim.ml.anomaly import _detect_port_anomalies, AnomalyReport
        report = AnomalyReport()
        _detect_port_anomalies(list(range(20)), report)
        assert any("high number" in a.description.lower() for a in report.anomalies)

    def test_detect_config_anomalies_weak_both(self):
        from wimsalabim.ml.anomaly import _detect_config_anomalies, AnomalyReport
        report = AnomalyReport()
        _detect_config_anomalies(0.2, 0.2, 5, 3, 4, 300, 365, report)
        assert any(a.severity == "critical" for a in report.anomalies)

    def test_detect_config_anomalies_cert_expiring(self):
        from wimsalabim.ml.anomaly import _detect_config_anomalies, AnomalyReport
        report = AnomalyReport()
        _detect_config_anomalies(0.8, 0.8, 5, 3, 0, 7, 365, report)
        assert any("expiring" in a.description.lower() for a in report.anomalies)

    def test_detect_config_anomalies_new_domain(self):
        from wimsalabim.ml.anomaly import _detect_config_anomalies, AnomalyReport
        report = AnomalyReport()
        _detect_config_anomalies(0.8, 0.8, 5, 3, 0, 365, 15, report)
        assert any("new domain" in a.description.lower() for a in report.anomalies)

    def test_ml_detection_runs(self):
        from wimsalabim.ml.anomaly import detect_anomalies
        report = detect_anomalies(
            open_ports=[80, 443],
            tls_score=0.9,
            headers_score=0.8,
        )
        assert report.total_features_analyzed == 10

    def test_ml_detection_high_risk(self):
        from wimsalabim.ml.anomaly import detect_anomalies
        report = detect_anomalies(
            open_ports=list(range(1, 30)),
            tls_score=0.1,
            headers_score=0.1,
            info_leak_count=5,
            days_until_cert_expiry=5,
            domain_age_days=10,
        )
        assert report.anomaly_count > 0

    def test_normal_port_profiles(self):
        from wimsalabim.ml.anomaly import NORMAL_PORT_PROFILES
        assert "web_server" in NORMAL_PORT_PROFILES
        assert "standard_web" in NORMAL_PORT_PROFILES


# === Threat Classifier Tests ===

class TestThreatClassifier:
    def test_threat_vector_dataclass(self):
        from wimsalabim.ml.threat_classifier import ThreatVector
        tv = ThreatVector(
            name="Test", category="Cat", likelihood=0.8,
            impact="high", description="desc",
        )
        assert tv.likelihood == 0.8
        assert tv.impact == "high"

    def test_threat_report_properties(self):
        from wimsalabim.ml.threat_classifier import ThreatReport, ThreatVector
        report = ThreatReport()
        report.threats = [
            ThreatVector("T1", "C1", 0.9, "critical", "d1"),
            ThreatVector("T2", "C2", 0.5, "medium", "d2"),
        ]
        assert report.threat_count == 2
        assert len(report.critical_threats) == 1
        assert len(report.high_threats) == 0

    def test_threat_knowledge_base(self):
        from wimsalabim.ml.threat_classifier import THREAT_KNOWLEDGE_BASE
        assert "exposed_admin" in THREAT_KNOWLEDGE_BASE
        assert "weak_tls" in THREAT_KNOWLEDGE_BASE
        assert all("mitigations" in v for v in THREAT_KNOWLEDGE_BASE.values())

    def test_classify_threats_basic(self):
        from wimsalabim.ml.threat_classifier import classify_threats
        report = classify_threats(
            open_ports=[80, 443],
            tls_grade="A",
            headers_grade="A",
            email_grade="A",
            waf_detected=True,
        )
        assert report.threat_count >= 0
        assert report.attack_surface_score >= 0

    def test_classify_threats_risky(self):
        from wimsalabim.ml.threat_classifier import classify_threats
        report = classify_threats(
            open_ports=[22, 23, 80, 3306, 6379],
            risky_ports=3,
            tls_grade="F",
            headers_grade="F",
            headers_missing=8,
            info_leaks=4,
            email_grade="F",
            cors_reflects=True,
            sensitive_paths=3,
        )
        assert report.threat_count > 5
        assert report.attack_surface_score > 0.3

    def test_feature_extraction(self):
        from wimsalabim.ml.threat_classifier import _extract_features
        features = _extract_features(
            [80, 443], 0, "A", "B", 2, 1, [], "A",
            "A", False, 0, True, [], 0, 0, 0, 0,
        )
        assert features["port_count"] == 2
        assert features["tls_score"] == 1.0
        assert features["headers_score"] == 0.75

    def test_ml_threat_scoring_runs(self):
        from wimsalabim.ml.threat_classifier import classify_threats
        report = classify_threats()
        assert report.threat_model != ""
        assert "DecisionTree" in report.threat_model


# === Risk Engine Tests ===

class TestRiskEngine:
    def test_recommendation_dataclass(self):
        from wimsalabim.ml.risk_engine import Recommendation
        rec = Recommendation(
            priority=1, title="Fix TLS", description="desc",
            category="Encryption", effort="low", impact="high",
        )
        assert rec.priority == 1
        assert rec.effort == "low"

    def test_assess_risk_default(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk()
        assert assessment.risk_label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")
        assert 0 <= assessment.overall_risk <= 1
        assert 0 <= assessment.confidence <= 1

    def test_assess_risk_good_security(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk(
            tls_grade="A", headers_grade="A", email_grade="A",
            cors_grade="A", waf_detected=True,
        )
        assert assessment.overall_risk < 0.6

    def test_assess_risk_bad_security(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk(
            port_count=15, risky_ports=5,
            tls_grade="F", headers_grade="F",
            headers_missing=10, info_leaks=5,
            email_grade="F", cors_reflects=True,
            sensitive_paths=5, cve_critical=3,
        )
        assert assessment.overall_risk > 0.3

    def test_recommendations_generated(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk(
            tls_grade="F", risky_ports=3, headers_missing=6,
            email_grade="F", sensitive_paths=2,
        )
        assert len(assessment.recommendations) > 0
        assert assessment.recommendations[0].priority == 1

    def test_risk_breakdown(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk(risky_ports=3, tls_grade="F")
        assert "Network Exposure" in assessment.risk_breakdown
        assert "Encryption" in assessment.risk_breakdown

    def test_executive_summary_generated(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk()
        assert assessment.executive_summary != ""
        assert "risk" in assessment.executive_summary.lower()

    def test_technical_summary_generated(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk()
        assert assessment.technical_summary != ""
        assert "Risk Score" in assessment.technical_summary

    def test_model_info_populated(self):
        from wimsalabim.ml.risk_engine import assess_risk
        assessment = assess_risk()
        assert "ensemble" in assessment.model_info
        assert "training_samples" in assessment.model_info
        assert assessment.model_info["training_samples"] == 500

    def test_risk_labels_correct_ranges(self):
        from wimsalabim.ml.risk_engine import assess_risk
        # These are ML models so exact values aren't guaranteed,
        # but we can verify the structure
        assessment = assess_risk()
        valid_labels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}
        assert assessment.risk_label in valid_labels


# === Traffic Analyzer Tests ===

class TestTrafficAnalyzer:
    def test_traffic_pattern_dataclass(self):
        from wimsalabim.ml.traffic_analyzer import TrafficPattern
        tp = TrafficPattern(name="Test", description="desc", confidence=0.9, risk="high")
        assert tp.name == "Test"
        assert tp.confidence == 0.9

    def test_threat_intel_dataclass(self):
        from wimsalabim.ml.traffic_analyzer import ThreatIntel
        ti = ThreatIntel(
            category="Test", description="desc",
            severity="moderate", confidence=0.8,
        )
        assert ti.source == "ml_model"
        assert ti.indicators == []

    def test_traffic_report_properties(self):
        from wimsalabim.ml.traffic_analyzer import TrafficAnalysisReport, TrafficPattern, ThreatIntel
        report = TrafficAnalysisReport()
        report.patterns.append(TrafficPattern("P1", "d1", 0.8, "low"))
        report.threat_intel.append(ThreatIntel("C1", "d1", "low", 0.7))
        assert report.pattern_count == 1
        assert report.threat_count == 1

    def test_build_feature_vector(self):
        from wimsalabim.ml.traffic_analyzer import _build_feature_vector
        features = _build_feature_vector(
            [80, 443, 22], [50, 55, 60], 5.0, 0.0,
            100.0, 50.0, 200, 150.0, 8, 3, 5, 10, 0, True,
        )
        assert features["port_count"] == 3
        assert features["service_ports"] == 3
        assert features["high_ports"] == 0
        assert features["waf"] == 1
        assert features["avg_latency"] > 0

    def test_build_feature_vector_empty(self):
        from wimsalabim.ml.traffic_analyzer import _build_feature_vector
        features = _build_feature_vector([], [], 0, 0, 0, 0, 200, 0, 0, 0, 0, 0, 0, False)
        assert features["port_count"] == 0
        assert features["avg_latency"] == 0
        assert features["waf"] == 0

    def test_pattern_detection_wide_attack_surface(self):
        from wimsalabim.ml.traffic_analyzer import _pattern_detection, TrafficAnalysisReport
        report = TrafficAnalysisReport()
        features = {"port_count": 12, "waf": 0, "avg_latency": 0, "latency_variance": 0,
                     "packet_loss": 0, "jitter": 0, "tls_handshake": 0, "subdomain_count": 0,
                     "response_time": 0, "tech_count": 0, "cve_count": 0}
        _pattern_detection(features, report)
        assert any("Wide Attack Surface" in p.name for p in report.patterns)

    def test_pattern_detection_exploitable(self):
        from wimsalabim.ml.traffic_analyzer import _pattern_detection, TrafficAnalysisReport
        report = TrafficAnalysisReport()
        features = {"port_count": 8, "waf": 1, "avg_latency": 0, "latency_variance": 0,
                     "packet_loss": 0, "jitter": 0, "tls_handshake": 0, "subdomain_count": 0,
                     "response_time": 0, "tech_count": 0, "cve_count": 3}
        _pattern_detection(features, report)
        assert any("Exploitable" in p.name for p in report.patterns)

    def test_pattern_detection_slow_handshake(self):
        from wimsalabim.ml.traffic_analyzer import _pattern_detection, TrafficAnalysisReport
        report = TrafficAnalysisReport()
        features = {"port_count": 2, "waf": 1, "avg_latency": 0, "latency_variance": 0,
                     "packet_loss": 0, "jitter": 0, "tls_handshake": 500, "subdomain_count": 0,
                     "response_time": 0, "tech_count": 0, "cve_count": 0}
        _pattern_detection(features, report)
        assert any("Slow Crypto" in p.name for p in report.patterns)

    def test_behavioral_scoring_minimal(self):
        from wimsalabim.ml.traffic_analyzer import _behavioral_scoring, TrafficAnalysisReport
        report = TrafficAnalysisReport()
        features = {"port_count": 2, "cve_count": 0, "packet_loss": 0, "jitter": 0,
                     "waf": 1, "high_ports": 0, "subdomain_count": 0,
                     "tls_handshake": 50, "latency_variance": 0}
        _behavioral_scoring(features, report)
        assert report.behavioral_risk < 0.1

    def test_behavioral_scoring_high_risk(self):
        from wimsalabim.ml.traffic_analyzer import _behavioral_scoring, TrafficAnalysisReport
        report = TrafficAnalysisReport()
        features = {"port_count": 10, "cve_count": 5, "packet_loss": 5, "jitter": 50,
                     "waf": 0, "high_ports": 3, "subdomain_count": 100,
                     "tls_handshake": 500, "latency_variance": 200}
        _behavioral_scoring(features, report)
        assert report.behavioral_risk > 0.4

    def test_analyze_traffic_patterns_runs(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns(
            open_ports=[80, 443],
            latency_samples=[50, 55, 60],
            jitter_ms=5.0,
        )
        assert report.cluster_profile != ""
        assert report.cluster_label != ""
        assert "clustering" in report.model_info
        assert "threat_intel" in report.model_info

    def test_analyze_traffic_patterns_defaults(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns()
        assert report.cluster_profile != ""
        assert report.behavioral_risk >= 0

    def test_cluster_analysis_produces_valid_profile(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns(
            open_ports=[80, 443],
            latency_samples=[30, 32, 31],
            waf_detected=True,
        )
        valid_profiles = {"secure_enterprise", "standard_web", "vulnerable_target",
                          "minimal_service", "cloud_hosted", "unknown"}
        assert report.cluster_profile in valid_profiles

    def test_threat_intel_with_packet_loss(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns(packet_loss_pct=5.0)
        assert any(t.category == "Network Reliability" for t in report.threat_intel)

    def test_threat_intel_with_cves(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns(cve_count=5)
        assert any(t.category == "Vulnerability Exposure" for t in report.threat_intel)

    def test_model_info_threat_intel(self):
        from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
        report = analyze_traffic_patterns()
        ti = report.model_info["threat_intel"]
        assert ti["algorithm"] == "RandomForestClassifier"
        assert "predicted_level" in ti
        valid_levels = {"minimal", "low", "moderate", "elevated"}
        assert ti["predicted_level"] in valid_levels
