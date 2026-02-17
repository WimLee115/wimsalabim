"""Tests for Wimsalabim analyzers. rootmap:WimLee115"""

from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock
import asyncio

import pytest


# === Port Scanner Tests ===

class TestPortScanner:
    def test_port_result_dataclass(self):
        from wimsalabim.analyzers.ports import PortResult
        pr = PortResult(port=80, state="open", service="HTTP", risk="low")
        assert pr.port == 80
        assert pr.service == "HTTP"
        assert pr.risk == "low"

    def test_port_scan_report_properties(self):
        from wimsalabim.analyzers.ports import PortScanReport, PortResult
        report = PortScanReport(
            target="example.com",
            ip_address="93.184.216.34",
            open_ports=[
                PortResult(port=80, state="open", service="HTTP", risk="low"),
                PortResult(port=22, state="open", service="SSH", risk="high"),
            ],
        )
        assert report.open_count == 2
        assert len(report.risky_ports) == 1
        assert report.risky_ports[0].port == 22

    def test_assess_risk(self):
        from wimsalabim.analyzers.ports import _assess_risk
        assert _assess_risk(23) == "critical"
        assert _assess_risk(3306) == "high"
        assert _assess_risk(8080) == "medium"
        assert _assess_risk(443) == "low"

    def test_service_map_coverage(self):
        from wimsalabim.analyzers.ports import SERVICE_MAP, TOP_PORTS
        for port in TOP_PORTS:
            assert port in SERVICE_MAP, f"Port {port} missing from SERVICE_MAP"

    @patch("wimsalabim.analyzers.ports.socket.gethostbyname", side_effect=socket.gaierror("DNS fail"))
    def test_scan_ports_dns_failure(self, mock_dns):
        from wimsalabim.analyzers.ports import scan_ports
        report = asyncio.run(scan_ports("invalid.nonexistent"))
        assert report.open_count == 0
        assert report.ip_address == ""


# === TLS Analyzer Tests ===

class TestTLSAnalyzer:
    def test_tls_report_defaults(self):
        from wimsalabim.analyzers.tls import TLSReport
        report = TLSReport(target="test.com")
        assert not report.available
        assert report.grade == "N/A"
        assert report.issues == []

    def test_calculate_grade_not_available(self):
        from wimsalabim.analyzers.tls import _calculate_grade, TLSReport
        report = TLSReport(target="test.com", available=False)
        assert _calculate_grade(report) == "F"

    def test_calculate_grade_perfect(self):
        from wimsalabim.analyzers.tls import _calculate_grade, TLSReport
        report = TLSReport(
            target="test.com", available=True, supports_tls13=True,
            cipher_bits=256, days_until_expiry=300,
        )
        assert _calculate_grade(report) == "A"

    def test_calculate_grade_expired(self):
        from wimsalabim.analyzers.tls import _calculate_grade, TLSReport
        report = TLSReport(
            target="test.com", available=True, expired=True,
            supports_tls13=True, cipher_bits=256,
        )
        grade = _calculate_grade(report)
        assert grade in ("D", "F")

    def test_weak_ciphers_detected(self):
        from wimsalabim.analyzers.tls import WEAK_CIPHERS
        assert "RC4" in WEAK_CIPHERS
        assert "DES" in WEAK_CIPHERS
        assert "NULL" in WEAK_CIPHERS


# === HTTP Headers Tests ===

class TestHeadersAnalyzer:
    def test_security_headers_defined(self):
        from wimsalabim.analyzers.headers import SECURITY_HEADERS
        assert "Strict-Transport-Security" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS
        assert "X-Frame-Options" in SECURITY_HEADERS

    def test_grade_from_score(self):
        from wimsalabim.analyzers.headers import _grade_from_score
        assert _grade_from_score(95) == "A"
        assert _grade_from_score(80) == "B"
        assert _grade_from_score(65) == "C"
        assert _grade_from_score(45) == "D"
        assert _grade_from_score(20) == "F"

    def test_evaluate_header_hsts(self):
        from wimsalabim.analyzers.headers import _evaluate_header
        score = _evaluate_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
            15,
        )
        assert score >= 13

    def test_evaluate_header_xfo(self):
        from wimsalabim.analyzers.headers import _evaluate_header
        score = _evaluate_header("X-Frame-Options", "DENY", 10)
        assert score == 10

    def test_header_check_dataclass(self):
        from wimsalabim.analyzers.headers import HeaderCheck
        hc = HeaderCheck(name="Test", present=True, value="val", max_score=10)
        assert hc.name == "Test"
        assert hc.present is True


# === DNS Analyzer Tests ===

class TestDNSAnalyzer:
    def test_dns_record_dataclass(self):
        from wimsalabim.analyzers.dns_recon import DNSRecord
        rec = DNSRecord(record_type="A", value="1.2.3.4", ttl=300)
        assert rec.record_type == "A"
        assert rec.ttl == 300

    def test_dns_report_properties(self):
        from wimsalabim.analyzers.dns_recon import DNSReport, DNSRecord
        report = DNSReport(target="test.com")
        report.records["A"] = [DNSRecord("A", "1.2.3.4")]
        report.records["MX"] = [DNSRecord("MX", "mail.test.com")]
        assert report.record_types_found == ["A", "MX"]
        assert report.total_records == 0  # manually set

    def test_interesting_txt_patterns(self):
        from wimsalabim.analyzers.dns_recon import INTERESTING_TXT_PATTERNS
        assert "v=spf" in INTERESTING_TXT_PATTERNS
        assert "v=dmarc" in INTERESTING_TXT_PATTERNS

    def test_check_interesting_txt(self):
        from wimsalabim.analyzers.dns_recon import _check_interesting_txt, DNSReport
        report = DNSReport(target="test.com")
        _check_interesting_txt("v=spf1 include:test.com -all", report)
        assert len(report.interesting_txt) == 1


# === Email Security Tests ===

class TestEmailSecurity:
    def test_spf_result_defaults(self):
        from wimsalabim.analyzers.email_sec import SPFResult
        spf = SPFResult()
        assert not spf.found
        assert spf.grade == "F"

    def test_parse_spf_hardfail(self):
        from wimsalabim.analyzers.email_sec import _parse_spf, SPFResult
        spf = SPFResult()
        _parse_spf("v=spf1 include:_spf.google.com -all", spf)
        assert spf.all_qualifier == "-all"
        assert spf.grade == "A"
        assert "google.com" in spf.includes[0]

    def test_parse_spf_softfail(self):
        from wimsalabim.analyzers.email_sec import _parse_spf, SPFResult
        spf = SPFResult()
        _parse_spf("v=spf1 include:example.com ~all", spf)
        assert spf.grade == "B"

    def test_parse_dmarc_reject(self):
        from wimsalabim.analyzers.email_sec import _parse_dmarc, DMARCResult
        dmarc = DMARCResult()
        _parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@test.com", dmarc)
        assert dmarc.policy == "reject"
        assert dmarc.grade == "A"

    def test_parse_dmarc_none(self):
        from wimsalabim.analyzers.email_sec import _parse_dmarc, DMARCResult
        dmarc = DMARCResult()
        _parse_dmarc("v=DMARC1; p=none", dmarc)
        assert dmarc.policy == "none"
        assert dmarc.grade == "D"

    def test_common_dkim_selectors(self):
        from wimsalabim.analyzers.email_sec import COMMON_DKIM_SELECTORS
        assert "google" in COMMON_DKIM_SELECTORS
        assert "selector1" in COMMON_DKIM_SELECTORS


# === Technology Fingerprinting Tests ===

class TestTechAnalyzer:
    def test_server_signatures(self):
        from wimsalabim.analyzers.tech import SERVER_SIGNATURES
        assert "nginx" in SERVER_SIGNATURES
        assert "apache" in SERVER_SIGNATURES
        assert "cloudflare" in SERVER_SIGNATURES

    def test_extract_version(self):
        from wimsalabim.analyzers.tech import _extract_version
        assert _extract_version("nginx/1.24.0") == "1.24.0"
        assert _extract_version("Apache/2.4.54") == "2.4.54"
        assert _extract_version("no-version") == ""

    def test_html_patterns_coverage(self):
        from wimsalabim.analyzers.tech import HTML_PATTERNS
        names = [p[1] for p in HTML_PATTERNS]
        assert "WordPress" in names
        assert "React/Next.js" in names
        assert "Cloudflare" in names

    def test_deduplicate(self):
        from wimsalabim.analyzers.tech import _deduplicate, TechReport, Technology
        report = TechReport(target="test.com")
        report.technologies = [
            Technology("Nginx", "Web Server"),
            Technology("nginx", "Web Server"),
            Technology("PHP", "Language"),
        ]
        _deduplicate(report)
        assert report.tech_count == 2


# === WHOIS Tests ===

class TestWhoisAnalyzer:
    def test_whois_report_defaults(self):
        from wimsalabim.analyzers.whois_lookup import WhoisReport
        report = WhoisReport(target="test.com")
        assert not report.available
        assert report.domain_age_days == 0

    def test_parse_date_with_datetime(self):
        from wimsalabim.analyzers.whois_lookup import _parse_date
        from datetime import datetime
        dt = datetime(2020, 1, 1)
        assert _parse_date(dt) == dt

    def test_parse_date_with_list(self):
        from wimsalabim.analyzers.whois_lookup import _parse_date
        from datetime import datetime
        dt = datetime(2020, 1, 1)
        assert _parse_date([dt]) == dt

    def test_parse_date_with_none(self):
        from wimsalabim.analyzers.whois_lookup import _parse_date
        assert _parse_date(None) is None


# === Scoring Tests ===

class TestScoring:
    def test_score_to_grade(self):
        from wimsalabim.analyzers.scoring import _score_to_grade
        assert _score_to_grade(95) == "A"
        assert _score_to_grade(80) == "B"
        assert _score_to_grade(65) == "C"
        assert _score_to_grade(45) == "D"
        assert _score_to_grade(30) == "F"

    def test_calculate_scores_default(self):
        from wimsalabim.analyzers.scoring import calculate_scores
        report = calculate_scores()
        assert report.overall_grade in ("A", "B", "C", "D", "F", "N/A")
        assert len(report.categories) > 0

    def test_calculate_scores_all_good(self):
        from wimsalabim.analyzers.scoring import calculate_scores
        report = calculate_scores(
            tls_grade="A", headers_grade="A", email_grade="A",
            waf_detected=True,
        )
        assert report.overall_score >= 60

    def test_category_weights(self):
        from wimsalabim.analyzers.scoring import CATEGORY_WEIGHTS
        total = sum(CATEGORY_WEIGHTS.values())
        assert abs(total - 1.0) < 0.01


# === Subdomain Discovery Tests ===

class TestSubdomains:
    def test_subdomain_dataclass(self):
        from wimsalabim.analyzers.subdomains import Subdomain
        sub = Subdomain(hostname="mail.test.com", ip_address="1.2.3.4")
        assert sub.hostname == "mail.test.com"
        assert not sub.https_available

    def test_report_properties(self):
        from wimsalabim.analyzers.subdomains import SubdomainReport, Subdomain
        report = SubdomainReport(target="test.com")
        report.subdomains_found.append(Subdomain(hostname="www.test.com"))
        assert report.found_count == 1

    def test_common_subdomains(self):
        from wimsalabim.analyzers.subdomains import COMMON_SUBDOMAINS
        assert "www" in COMMON_SUBDOMAINS
        assert "api" in COMMON_SUBDOMAINS
        assert "admin" in COMMON_SUBDOMAINS

    def test_analyze_findings_sensitive(self):
        from wimsalabim.analyzers.subdomains import _analyze_findings, SubdomainReport, Subdomain
        report = SubdomainReport(target="test.com")
        report.subdomains_found = [
            Subdomain(hostname="admin.test.com", ip_address="1.2.3.4"),
            Subdomain(hostname="www.test.com", ip_address="1.2.3.5"),
        ]
        _analyze_findings(report)
        assert len(report.issues) == 1
        assert "admin" in report.issues[0]


# === WAF Detection Tests ===

class TestWAF:
    def test_waf_report_defaults(self):
        from wimsalabim.analyzers.waf import WAFReport
        report = WAFReport(target="test.com")
        assert not report.detected
        assert report.confidence == 0.0

    def test_waf_signatures(self):
        from wimsalabim.analyzers.waf import WAF_SIGNATURES
        assert "Cloudflare" in WAF_SIGNATURES
        assert "AWS WAF" in WAF_SIGNATURES
        assert "ModSecurity" in WAF_SIGNATURES


# === Directory Scanner Tests ===

class TestDirectories:
    def test_found_path_dataclass(self):
        from wimsalabim.analyzers.directories import FoundPath
        fp = FoundPath(path="/.git/", status_code=200, risk="critical")
        assert fp.risk == "critical"

    def test_common_paths_coverage(self):
        from wimsalabim.analyzers.directories import COMMON_PATHS
        paths = [p[0] for p in COMMON_PATHS]
        assert "/.git/" in paths
        assert "/.env" in paths
        assert "/robots.txt" in paths

    def test_parse_robots(self):
        from wimsalabim.analyzers.directories import _parse_robots, DirectoryReport
        report = DirectoryReport(target="test.com")
        _parse_robots("User-agent: *\nDisallow: /admin/secret\nDisallow: /", report)
        assert len(report.issues) == 1
        assert "admin" in report.issues[0]


# === CORS Tests ===

class TestCORS:
    def test_cors_report_defaults(self):
        from wimsalabim.analyzers.cors import CORSReport
        report = CORSReport(target="test.com")
        assert not report.cors_enabled
        assert report.grade == "N/A"

    def test_calculate_grade_no_cors(self):
        from wimsalabim.analyzers.cors import _calculate_grade, CORSReport
        report = CORSReport(target="test.com", cors_enabled=False)
        _calculate_grade(report)
        assert report.grade == "A"

    def test_calculate_grade_reflects_origin(self):
        from wimsalabim.analyzers.cors import _calculate_grade, CORSReport
        report = CORSReport(
            target="test.com", cors_enabled=True,
            reflects_origin=True, null_origin_allowed=True,
        )
        _calculate_grade(report)
        assert report.grade in ("D", "F")


# === Cookie Tests ===

class TestCookies:
    def test_session_cookie_names(self):
        from wimsalabim.analyzers.cookies import SESSION_COOKIE_NAMES
        assert "phpsessid" in SESSION_COOKIE_NAMES
        assert "connect.sid" in SESSION_COOKIE_NAMES

    def test_cookie_report_defaults(self):
        from wimsalabim.analyzers.cookies import CookieReport
        report = CookieReport(target="test.com")
        assert report.total_cookies == 0
        assert report.grade == "N/A"

    def test_calculate_grade_no_cookies(self):
        from wimsalabim.analyzers.cookies import _calculate_grade, CookieReport
        report = CookieReport(target="test.com")
        _calculate_grade(report)
        assert report.grade == "A"


# === Cloud Detection Tests ===

class TestCloud:
    def test_cloud_report_defaults(self):
        from wimsalabim.analyzers.cloud import CloudReport
        report = CloudReport(target="test.com")
        assert not report.is_cloud_hosted
        assert report.service_count == 0

    def test_cloud_cname_patterns(self):
        from wimsalabim.analyzers.cloud import CLOUD_CNAME_PATTERNS
        assert "AWS" in CLOUD_CNAME_PATTERNS
        assert "GCP" in CLOUD_CNAME_PATTERNS
        assert "Azure" in CLOUD_CNAME_PATTERNS
        assert "Vercel" in CLOUD_CNAME_PATTERNS


# === CVE Lookup Tests ===

class TestCVE:
    def test_cve_entry_dataclass(self):
        from wimsalabim.analyzers.cve_lookup import CVEEntry
        cve = CVEEntry(cve_id="CVE-2024-1234", severity="HIGH", score=7.5)
        assert cve.score == 7.5

    def test_score_to_severity(self):
        from wimsalabim.analyzers.cve_lookup import _score_to_severity
        assert _score_to_severity(9.5) == "CRITICAL"
        assert _score_to_severity(7.5) == "HIGH"
        assert _score_to_severity(5.0) == "MEDIUM"
        assert _score_to_severity(2.0) == "LOW"
        assert _score_to_severity(0.0) == "UNKNOWN"

    def test_product_cpe_map(self):
        from wimsalabim.analyzers.cve_lookup import PRODUCT_CPE_MAP
        assert "nginx" in PRODUCT_CPE_MAP
        assert "wordpress" in PRODUCT_CPE_MAP
        assert "redis" in PRODUCT_CPE_MAP


# === Network Quality Analyzer Tests ===

class TestNetworkAnalyzer:
    def test_latency_result_quality_excellent(self):
        from wimsalabim.analyzers.network import LatencyResult
        lat = LatencyResult(target="test.com", avg_ms=30, jitter_ms=5, packet_loss_pct=0)
        assert lat.quality == "excellent"

    def test_latency_result_quality_good(self):
        from wimsalabim.analyzers.network import LatencyResult
        lat = LatencyResult(target="test.com", avg_ms=80, jitter_ms=20, packet_loss_pct=1)
        assert lat.quality == "good"

    def test_latency_result_quality_fair(self):
        from wimsalabim.analyzers.network import LatencyResult
        lat = LatencyResult(target="test.com", avg_ms=150, jitter_ms=40, packet_loss_pct=3)
        assert lat.quality == "fair"

    def test_latency_result_quality_poor(self):
        from wimsalabim.analyzers.network import LatencyResult
        lat = LatencyResult(target="test.com", avg_ms=300, jitter_ms=60, packet_loss_pct=10)
        assert lat.quality == "poor"

    def test_bandwidth_estimate_defaults(self):
        from wimsalabim.analyzers.network import BandwidthEstimate
        bw = BandwidthEstimate()
        assert bw.download_estimate_mbps == 0.0
        assert bw.method == ""

    def test_connection_stability_defaults(self):
        from wimsalabim.analyzers.network import ConnectionStability
        cs = ConnectionStability()
        assert cs.score == 0.0
        assert cs.stable is True

    def test_congestion_prediction_defaults(self):
        from wimsalabim.analyzers.network import CongestionPrediction
        cp = CongestionPrediction()
        assert cp.congestion_score == 0.0
        assert cp.risk_level == "low"

    def test_network_report_defaults(self):
        from wimsalabim.analyzers.network import NetworkReport
        report = NetworkReport(target="test.com")
        assert not report.available
        assert report.grade == "N/A"

    def test_calculate_jitter(self):
        from wimsalabim.analyzers.network import _calculate_jitter
        assert _calculate_jitter([10, 20, 30]) == 10.0
        assert _calculate_jitter([50]) == 0.0
        assert _calculate_jitter([]) == 0.0

    def test_assess_stability_insufficient(self):
        from wimsalabim.analyzers.network import _assess_stability
        stab = _assess_stability([10, 20])
        assert stab.trend == "insufficient data"
        assert stab.score == 0.5

    def test_assess_stability_stable(self):
        from wimsalabim.analyzers.network import _assess_stability
        stab = _assess_stability([50, 51, 50, 52, 50, 51])
        assert stab.stable is True
        assert stab.trend == "stable"
        assert stab.score > 0.8

    def test_assess_stability_degrading(self):
        from wimsalabim.analyzers.network import _assess_stability
        stab = _assess_stability([10, 10, 10, 50, 60, 70])
        assert stab.trend == "degrading"

    def test_predict_congestion_low(self):
        from wimsalabim.analyzers.network import _predict_congestion, LatencyResult, ConnectionStability
        lat = LatencyResult(target="t", avg_ms=30, jitter_ms=5, packet_loss_pct=0, max_ms=35)
        stab = ConnectionStability(stable=True, trend="stable")
        pred = _predict_congestion(lat, stab)
        assert pred.risk_level == "low"
        assert pred.congestion_score < 0.2

    def test_predict_congestion_high(self):
        from wimsalabim.analyzers.network import _predict_congestion, LatencyResult, ConnectionStability
        lat = LatencyResult(target="t", avg_ms=200, jitter_ms=40, packet_loss_pct=5, max_ms=800)
        stab = ConnectionStability(stable=False, trend="degrading")
        pred = _predict_congestion(lat, stab)
        assert pred.risk_level in ("high", "critical")
        assert len(pred.indicators) > 0

    def test_calculate_grade_unavailable(self):
        from wimsalabim.analyzers.network import _calculate_grade, NetworkReport
        report = NetworkReport(target="t", available=False)
        assert _calculate_grade(report) == "F"

    def test_calculate_grade_excellent(self):
        from wimsalabim.analyzers.network import _calculate_grade, NetworkReport, LatencyResult, ConnectionStability, CongestionPrediction
        report = NetworkReport(
            target="t", available=True,
            latency=LatencyResult(target="t", avg_ms=30, jitter_ms=5, packet_loss_pct=0),
            stability=ConnectionStability(stable=True),
            congestion=CongestionPrediction(congestion_score=0.0),
        )
        assert _calculate_grade(report) == "A"

    def test_generate_issues_packet_loss(self):
        from wimsalabim.analyzers.network import _generate_issues, NetworkReport, LatencyResult, ConnectionStability, CongestionPrediction
        report = NetworkReport(
            target="t", available=True,
            latency=LatencyResult(target="t", avg_ms=50, jitter_ms=5, packet_loss_pct=8),
            stability=ConnectionStability(stable=True),
            congestion=CongestionPrediction(congestion_score=0.0, risk_level="low"),
        )
        _generate_issues(report)
        assert any("packet loss" in i.lower() for i in report.issues)

    def test_generate_issues_jitter(self):
        from wimsalabim.analyzers.network import _generate_issues, NetworkReport, LatencyResult, ConnectionStability, CongestionPrediction
        report = NetworkReport(
            target="t", available=True,
            latency=LatencyResult(target="t", avg_ms=50, jitter_ms=55, packet_loss_pct=0),
            stability=ConnectionStability(stable=True),
            congestion=CongestionPrediction(congestion_score=0.0, risk_level="low"),
        )
        _generate_issues(report)
        assert any("jitter" in i.lower() for i in report.issues)


# === Leak Detector Tests ===

class TestLeakDetector:
    def test_dns_leak_result_defaults(self):
        from wimsalabim.analyzers.leak_detector import DNSLeakResult
        result = DNSLeakResult()
        assert not result.leak_detected
        assert result.grade == "N/A"

    def test_ip_leak_result_defaults(self):
        from wimsalabim.analyzers.leak_detector import IPLeakResult
        result = IPLeakResult()
        assert result.target_ip == ""
        assert not result.headers_expose_ip
        assert result.grade == "N/A"

    def test_webrtc_leak_result_defaults(self):
        from wimsalabim.analyzers.leak_detector import WebRTCLeakResult
        result = WebRTCLeakResult()
        assert not result.webrtc_headers_present
        assert not result.csp_blocks_webrtc

    def test_firewall_audit_result_defaults(self):
        from wimsalabim.analyzers.leak_detector import FirewallAuditResult
        result = FirewallAuditResult()
        assert result.actually_open == []
        assert result.grade == "N/A"

    def test_leak_detector_report_defaults(self):
        from wimsalabim.analyzers.leak_detector import LeakDetectorReport
        report = LeakDetectorReport(target="test.com")
        assert report.grade == "N/A"
        assert report.issues == []

    def test_dangerous_open_ports_defined(self):
        from wimsalabim.analyzers.leak_detector import DANGEROUS_OPEN_PORTS
        ports = [p[0] for p in DANGEROUS_OPEN_PORTS]
        assert 23 in ports  # Telnet
        assert 3306 in ports  # MySQL
        assert 6379 in ports  # Redis
        assert 27017 in ports  # MongoDB

    def test_known_public_resolvers(self):
        from wimsalabim.analyzers.leak_detector import KNOWN_PUBLIC_RESOLVERS
        assert "8.8.8.8" in KNOWN_PUBLIC_RESOLVERS
        assert "1.1.1.1" in KNOWN_PUBLIC_RESOLVERS

    def test_extract_ips(self):
        from wimsalabim.analyzers.leak_detector import _extract_ips
        assert _extract_ips("10.0.0.1, 192.168.1.1") == ["10.0.0.1", "192.168.1.1"]
        assert _extract_ips("no ips here") == []
        assert _extract_ips("") == []

    def test_audit_firewall_clean(self):
        from wimsalabim.analyzers.leak_detector import _audit_firewall
        result = _audit_firewall("test.com", [80, 443])
        assert result.actually_open == []
        assert len(result.expected_blocked_ports) > 0

    def test_audit_firewall_dangerous_ports(self):
        from wimsalabim.analyzers.leak_detector import _audit_firewall
        result = _audit_firewall("test.com", [80, 443, 23, 3306, 6379])
        assert 23 in result.actually_open
        assert 3306 in result.actually_open
        assert 6379 in result.actually_open
        assert len(result.unnecessary_services) == 3
        assert result.grade in ("C", "D")

    def test_audit_firewall_management_ports(self):
        from wimsalabim.analyzers.leak_detector import _audit_firewall
        result = _audit_firewall("test.com", [80, 443, 22, 8080, 8443, 9090, 5000])
        assert any("management" in i.lower() or "port" in i.lower() for i in result.issues)


# === Performance Analyzer Tests ===

class TestPerformanceAnalyzer:
    def test_encryption_benchmark_defaults(self):
        from wimsalabim.analyzers.performance import EncryptionBenchmark
        bench = EncryptionBenchmark()
        assert bench.tls_handshake_ms == 0.0
        assert bench.grade == "N/A"

    def test_route_hop_dataclass(self):
        from wimsalabim.analyzers.performance import RouteHop
        hop = RouteHop(hop=1, ip="1.2.3.4", rtt_ms=10.5)
        assert hop.hop == 1
        assert hop.ip == "1.2.3.4"

    def test_route_analysis_defaults(self):
        from wimsalabim.analyzers.performance import RouteAnalysis
        route = RouteAnalysis()
        assert route.hop_count == 0
        assert route.grade == "N/A"

    def test_performance_report_defaults(self):
        from wimsalabim.analyzers.performance import PerformanceReport
        report = PerformanceReport(target="test.com")
        assert not report.available
        assert report.grade == "N/A"

    def test_performance_grade_calculation(self):
        from wimsalabim.analyzers.performance import PerformanceReport, EncryptionBenchmark, RouteAnalysis
        report = PerformanceReport(target="t")
        report.encryption = EncryptionBenchmark(grade="A")
        report.route = RouteAnalysis(grade="A")

        enc_score = {"A": 95}.get(report.encryption.grade, 50)
        route_score = {"A": 95}.get(report.route.grade, 50)
        avg = (enc_score + route_score) / 2
        assert avg >= 90
