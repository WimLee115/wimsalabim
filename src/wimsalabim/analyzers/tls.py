"""TLS/SSL certificate and protocol analyzer."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TLSReport:
    target: str
    available: bool = False
    protocol_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    expired: bool = False
    self_signed: bool = False
    san_domains: list[str] = field(default_factory=list)
    certificate_chain_length: int = 0
    weak_cipher: bool = False
    weak_protocol: bool = False
    supports_tls13: bool = False
    hsts_enabled: bool = False
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


def _check_protocol(target: str, protocol_const: int) -> bool:
    try:
        ctx = ssl.SSLContext(protocol_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target):
                return True
    except Exception:
        return False


def _check_tls13(target: str) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target):
                return True
    except Exception:
        return False


def analyze_tls(target: str) -> TLSReport:
    report = TLSReport(target=target)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    except Exception:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                report.available = True
                report.protocol_version = ssock.version() or ""
                cipher_info = ssock.cipher()
                if cipher_info:
                    report.cipher_suite = cipher_info[0]
                    report.cipher_bits = cipher_info[2] if len(cipher_info) > 2 else 0

                cert = ssock.getpeercert()
                if cert:
                    _parse_cert(cert, report)

                report.certificate_chain_length = len(
                    ssock.getpeercert(binary_form=False) or {}
                )
    except ssl.SSLCertVerificationError:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, 443), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=target) as ssock:
                    report.available = True
                    report.protocol_version = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        report.cipher_suite = cipher_info[0]
                        report.cipher_bits = cipher_info[2] if len(cipher_info) > 2 else 0
                    cert = ssock.getpeercert()
                    if cert:
                        _parse_cert(cert, report)
                    report.issues.append("Certificate verification failed")
        except Exception:
            return report
    except Exception:
        return report

    if report.cipher_suite:
        for weak in WEAK_CIPHERS:
            if weak.lower() in report.cipher_suite.lower():
                report.weak_cipher = True
                report.issues.append(f"Weak cipher detected: {report.cipher_suite}")
                break

    if report.protocol_version in WEAK_PROTOCOLS:
        report.weak_protocol = True
        report.issues.append(f"Weak protocol: {report.protocol_version}")

    report.supports_tls13 = _check_tls13(target)

    if report.subject and report.issuer:
        subj_cn = report.subject.get("commonName", "")
        iss_cn = report.issuer.get("commonName", "")
        iss_org = report.issuer.get("organizationName", "")
        if subj_cn == iss_cn and not iss_org:
            report.self_signed = True
            report.issues.append("Self-signed certificate")

    report.grade = _calculate_grade(report)
    return report


def _parse_cert(cert: dict, report: TLSReport) -> None:
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    report.subject = subject
    report.issuer = issuer
    report.serial_number = cert.get("serialNumber", "")

    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    report.not_before = not_before
    report.not_after = not_after

    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = expiry - now
            report.days_until_expiry = delta.days
            report.expired = delta.days < 0
            if report.expired:
                report.issues.append("Certificate has EXPIRED")
            elif delta.days < 30:
                report.issues.append(f"Certificate expires in {delta.days} days")
        except ValueError:
            pass

    san_list = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type == "DNS":
            san_list.append(san_value)
    report.san_domains = san_list


def _calculate_grade(report: TLSReport) -> str:
    if not report.available:
        return "F"

    score = 100

    if report.expired:
        score -= 50
    if report.self_signed:
        score -= 30
    if report.weak_cipher:
        score -= 25
    if report.weak_protocol:
        score -= 20
    if not report.supports_tls13:
        score -= 10
    if report.cipher_bits < 128:
        score -= 20
    if report.days_until_expiry < 30 and not report.expired:
        score -= 10

    score -= len(report.issues) * 5

    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
