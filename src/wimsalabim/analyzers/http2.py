"""HTTP/2 and HTTP/3 protocol detection and analysis. rootmap:WimLee115"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

import requests


@dataclass
class HTTP2Result:
    supported: bool = False
    negotiated_protocol: str = ""
    server_push: bool = False
    max_concurrent_streams: int = 0


@dataclass
class HTTP3Result:
    supported: bool = False
    alt_svc_header: str = ""
    quic_version: str = ""


@dataclass
class ProtocolSecurityCheck:
    name: str
    passed: bool = False
    description: str = ""


@dataclass
class ProtocolReport:
    target: str
    available: bool = False
    http_version: str = ""
    http2: HTTP2Result = field(default_factory=HTTP2Result)
    http3: HTTP3Result = field(default_factory=HTTP3Result)
    hsts_enabled: bool = False
    https_redirect: bool = False
    security_checks: list[ProtocolSecurityCheck] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"

    @property
    def checks_passed(self) -> int:
        return sum(1 for c in self.security_checks if c.passed)

    @property
    def checks_total(self) -> int:
        return len(self.security_checks)


def analyze_protocols(target: str) -> ProtocolReport:
    report = ProtocolReport(target=target)

    _check_http2_alpn(target, report)
    _check_http3_alt_svc(target, report)
    _check_https_redirect(target, report)
    _check_protocol_security(target, report)

    if report.http2.supported or report.http3.supported or report.http_version:
        report.available = True

    _calculate_grade(report)

    return report


def _check_http2_alpn(target: str, report: ProtocolReport) -> None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()

        ctx.set_alpn_protocols(["h2", "http/1.1"])

        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                protocol = ssock.selected_alpn_protocol()

                if protocol == "h2":
                    report.http2.supported = True
                    report.http2.negotiated_protocol = "h2"
                    report.http_version = "HTTP/2"
                elif protocol == "http/1.1":
                    report.http_version = "HTTP/1.1"
                else:
                    report.http_version = protocol or "HTTP/1.1"

    except Exception:
        report.http_version = "unknown"


def _check_http3_alt_svc(target: str, report: ProtocolReport) -> None:
    try:
        resp = requests.get(
            f"https://{target}", timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )

        alt_svc = resp.headers.get("Alt-Svc", "")
        if alt_svc:
            report.http3.alt_svc_header = alt_svc

            if "h3" in alt_svc.lower():
                report.http3.supported = True

                if "h3-29" in alt_svc:
                    report.http3.quic_version = "h3-29 (draft)"
                elif 'h3="' in alt_svc or "h3;" in alt_svc:
                    report.http3.quic_version = "h3 (RFC 9114)"
                else:
                    report.http3.quic_version = "h3"

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            report.hsts_enabled = True

    except requests.RequestException:
        pass


def _check_https_redirect(target: str, report: ProtocolReport) -> None:
    try:
        resp = requests.get(
            f"http://{target}", timeout=5, allow_redirects=False, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if location.startswith("https://"):
                report.https_redirect = True

    except requests.RequestException:
        pass


def _check_protocol_security(target: str, report: ProtocolReport) -> None:
    report.security_checks.append(ProtocolSecurityCheck(
        name="HTTP/2 Support",
        passed=report.http2.supported,
        description="HTTP/2 provides multiplexing, header compression, and improved performance",
    ))

    report.security_checks.append(ProtocolSecurityCheck(
        name="HTTP/3 (QUIC) Support",
        passed=report.http3.supported,
        description="HTTP/3 uses QUIC for faster connections and built-in encryption",
    ))

    report.security_checks.append(ProtocolSecurityCheck(
        name="HTTPS Redirect",
        passed=report.https_redirect,
        description="HTTP to HTTPS redirect ensures encrypted connections",
    ))

    report.security_checks.append(ProtocolSecurityCheck(
        name="HSTS Header",
        passed=report.hsts_enabled,
        description="HSTS prevents SSL stripping attacks",
    ))

    _check_tls_version(target, report)
    _check_downgrade_protection(target, report)

    if not report.http2.supported:
        report.issues.append("HTTP/2 not supported - missing performance benefits")
    if not report.https_redirect:
        report.issues.append("No HTTPS redirect - unencrypted connections possible")
    if not report.hsts_enabled:
        report.issues.append("HSTS not enabled - vulnerable to SSL stripping")


def _check_tls_version(target: str, report: ProtocolReport) -> None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()

        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                version = ssock.version()
                is_modern = version in ("TLSv1.3", "TLSv1.2")

                report.security_checks.append(ProtocolSecurityCheck(
                    name="Modern TLS Version",
                    passed=is_modern,
                    description=f"Using {version} - {'modern' if is_modern else 'outdated'} protocol",
                ))

                if not is_modern:
                    report.issues.append(f"Outdated TLS version: {version}")

    except Exception:
        report.security_checks.append(ProtocolSecurityCheck(
            name="Modern TLS Version",
            passed=False,
            description="Could not verify TLS version",
        ))


def _check_downgrade_protection(target: str, report: ProtocolReport) -> None:
    has_protection = report.hsts_enabled and report.https_redirect

    report.security_checks.append(ProtocolSecurityCheck(
        name="Downgrade Protection",
        passed=has_protection,
        description="HSTS + HTTPS redirect prevents protocol downgrade attacks",
    ))

    if not has_protection:
        report.issues.append("Incomplete downgrade protection (needs both HSTS and HTTPS redirect)")


def _calculate_grade(report: ProtocolReport) -> None:
    if not report.available:
        report.grade = "N/A"
        return

    score = 0

    if report.http2.supported:
        score += 25
    if report.http3.supported:
        score += 15
    if report.https_redirect:
        score += 20
    if report.hsts_enabled:
        score += 20

    passed = report.checks_passed
    total = report.checks_total
    if total > 0:
        score += int((passed / total) * 20)

    if score >= 85:
        report.grade = "A"
    elif score >= 70:
        report.grade = "B"
    elif score >= 50:
        report.grade = "C"
    elif score >= 30:
        report.grade = "D"
    else:
        report.grade = "F"
