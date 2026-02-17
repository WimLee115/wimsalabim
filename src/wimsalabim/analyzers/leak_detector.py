"""DNS/IP/WebRTC leak detection and firewall auditing. rootmap:WimLee115"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

import dns.resolver
import requests


@dataclass
class DNSLeakResult:
    leak_detected: bool = False
    resolvers_found: list[str] = field(default_factory=list)
    expected_resolvers: list[str] = field(default_factory=list)
    third_party_resolvers: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


@dataclass
class IPLeakResult:
    target_ip: str = ""
    reverse_dns: str = ""
    headers_expose_ip: bool = False
    exposed_ips: list[str] = field(default_factory=list)
    x_forwarded_for: str = ""
    x_real_ip: str = ""
    via_header: str = ""
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


@dataclass
class WebRTCLeakResult:
    webrtc_headers_present: bool = False
    stun_servers_referenced: list[str] = field(default_factory=list)
    csp_blocks_webrtc: bool = False
    permissions_policy_blocks: bool = False
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


@dataclass
class FirewallAuditResult:
    expected_blocked_ports: list[int] = field(default_factory=list)
    actually_open: list[int] = field(default_factory=list)
    unnecessary_services: list[str] = field(default_factory=list)
    missing_protections: list[str] = field(default_factory=list)
    rate_limiting_detected: bool = False
    geo_blocking_detected: bool = False
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


@dataclass
class LeakDetectorReport:
    target: str
    dns_leak: DNSLeakResult = field(default_factory=DNSLeakResult)
    ip_leak: IPLeakResult = field(default_factory=IPLeakResult)
    webrtc_leak: WebRTCLeakResult = field(default_factory=WebRTCLeakResult)
    firewall_audit: FirewallAuditResult = field(default_factory=FirewallAuditResult)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


DANGEROUS_OPEN_PORTS = [
    (23, "Telnet"),
    (135, "MSRPC"),
    (139, "NetBIOS"),
    (445, "SMB"),
    (161, "SNMP"),
    (1433, "MSSQL"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (2049, "NFS"),
    (5900, "VNC"),
]

KNOWN_PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
}


def detect_leaks(target: str, open_ports: list[int] | None = None) -> LeakDetectorReport:
    report = LeakDetectorReport(target=target)

    report.dns_leak = _check_dns_leaks(target)
    report.ip_leak = _check_ip_leaks(target)
    report.webrtc_leak = _check_webrtc_leaks(target)
    report.firewall_audit = _audit_firewall(target, open_ports or [])

    all_issues = (
        report.dns_leak.issues + report.ip_leak.issues +
        report.webrtc_leak.issues + report.firewall_audit.issues
    )
    report.issues = all_issues

    grades = []
    for component in (report.dns_leak, report.ip_leak, report.webrtc_leak, report.firewall_audit):
        grades.append({"A": 95, "B": 80, "C": 60, "D": 40, "F": 15, "N/A": 50}.get(component.grade, 50))

    avg = sum(grades) / len(grades) if grades else 50
    if avg >= 90:
        report.grade = "A"
    elif avg >= 75:
        report.grade = "B"
    elif avg >= 60:
        report.grade = "C"
    elif avg >= 40:
        report.grade = "D"
    else:
        report.grade = "F"

    return report


def _check_dns_leaks(target: str) -> DNSLeakResult:
    result = DNSLeakResult()

    resolver = dns.resolver.Resolver()

    try:
        ns_answers = resolver.resolve(target, "NS")
        result.expected_resolvers = [r.to_text().rstrip(".") for r in ns_answers]
    except Exception:
        pass

    try:
        a_answers = resolver.resolve(target, "A")
        system_resolvers = [str(ns) for ns in resolver.nameservers]

        for ns_ip in system_resolvers:
            if ns_ip in KNOWN_PUBLIC_RESOLVERS:
                result.resolvers_found.append(f"{ns_ip} ({KNOWN_PUBLIC_RESOLVERS[ns_ip]})")
            else:
                result.resolvers_found.append(ns_ip)
    except Exception:
        pass

    try:
        custom_resolver = dns.resolver.Resolver()
        custom_resolver.nameservers = ["8.8.8.8"]
        google_answer = custom_resolver.resolve(target, "A")
        google_ip = google_answer[0].to_text()

        default_answer = resolver.resolve(target, "A")
        default_ip = default_answer[0].to_text()

        if google_ip != default_ip:
            result.leak_detected = True
            result.third_party_resolvers.append(
                f"DNS resolution differs: default={default_ip}, Google={google_ip}"
            )
            result.issues.append("DNS resolution inconsistency detected - potential DNS manipulation")
    except Exception:
        pass

    if not result.leak_detected:
        result.grade = "A"
    else:
        result.grade = "D"
        result.issues.append("DNS leak indicators found")

    return result


def _check_ip_leaks(target: str) -> IPLeakResult:
    result = IPLeakResult()

    try:
        result.target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return result

    try:
        reverse = socket.gethostbyaddr(result.target_ip)
        result.reverse_dns = reverse[0]
    except (socket.herror, socket.gaierror):
        pass

    url = f"https://{target}"
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )

        headers = resp.headers

        xff = headers.get("X-Forwarded-For", "")
        if xff:
            result.x_forwarded_for = xff
            ips = _extract_ips(xff)
            if ips:
                result.exposed_ips.extend(ips)
                result.headers_expose_ip = True
                result.issues.append(f"X-Forwarded-For exposes IPs: {xff}")

        xri = headers.get("X-Real-IP", "")
        if xri:
            result.x_real_ip = xri
            result.headers_expose_ip = True
            result.issues.append(f"X-Real-IP header present: {xri}")

        via = headers.get("Via", "")
        if via:
            result.via_header = via
            ips = _extract_ips(via)
            if ips:
                result.exposed_ips.extend(ips)
                result.issues.append(f"Via header exposes infrastructure: {via}")

        for header_name in ("X-Backend-Server", "X-Served-By", "X-Server",
                            "X-Host", "X-Origin-Server"):
            val = headers.get(header_name, "")
            if val:
                result.issues.append(f"{header_name} exposes backend: {val}")
                result.headers_expose_ip = True
                ips = _extract_ips(val)
                result.exposed_ips.extend(ips)

    except requests.RequestException:
        pass

    if not result.headers_expose_ip and not result.exposed_ips:
        result.grade = "A"
    elif len(result.issues) <= 1:
        result.grade = "B"
    elif len(result.issues) <= 3:
        result.grade = "C"
    else:
        result.grade = "D"

    return result


def _check_webrtc_leaks(target: str) -> WebRTCLeakResult:
    result = WebRTCLeakResult()

    url = f"https://{target}"
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        headers = resp.headers
        body = resp.text[:50000].lower()

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            csp_lower = csp.lower()
            if "connect-src" in csp_lower:
                if "'none'" in csp_lower or "'self'" in csp_lower:
                    result.csp_blocks_webrtc = True

        pp = headers.get("Permissions-Policy", "")
        if pp:
            pp_lower = pp.lower()
            for directive in ("camera", "microphone", "geolocation"):
                if f"{directive}=()" in pp_lower:
                    result.permissions_policy_blocks = True
                    break

        stun_patterns = [
            r"stun:", r"turn:", r"stun\.l\.google\.com",
            r"rtcpeerconnection", r"getusermedia",
            r"webrtc", r"ice.*candidate",
        ]
        for pattern in stun_patterns:
            if re.search(pattern, body):
                result.webrtc_headers_present = True
                result.stun_servers_referenced.append(pattern.replace("\\", ""))
                break

        if result.webrtc_headers_present and not result.csp_blocks_webrtc:
            result.issues.append("WebRTC references found without CSP restrictions")
        if result.webrtc_headers_present and not result.permissions_policy_blocks:
            result.issues.append("WebRTC present but Permissions-Policy doesn't restrict media access")

    except requests.RequestException:
        pass

    if not result.webrtc_headers_present:
        result.grade = "A"
    elif result.csp_blocks_webrtc and result.permissions_policy_blocks:
        result.grade = "A"
    elif result.csp_blocks_webrtc or result.permissions_policy_blocks:
        result.grade = "B"
    elif not result.issues:
        result.grade = "B"
    else:
        result.grade = "C"

    return result


def _audit_firewall(target: str, open_ports: list[int]) -> FirewallAuditResult:
    result = FirewallAuditResult()
    port_set = set(open_ports)

    for port, service in DANGEROUS_OPEN_PORTS:
        result.expected_blocked_ports.append(port)
        if port in port_set:
            result.actually_open.append(port)
            result.unnecessary_services.append(f"{service} (port {port})")
            result.issues.append(f"Dangerous service exposed: {service} on port {port}")

    web_ports = {80, 443}
    management_ports = port_set - web_ports - {22}
    if len(management_ports) > 3:
        result.missing_protections.append(
            f"Too many non-web ports open ({len(management_ports)}): "
            f"{sorted(management_ports)}"
        )
        result.issues.append(f"{len(management_ports)} management/service ports exposed")

    url = f"https://{target}"
    try:
        responses = []
        for _ in range(5):
            resp = requests.get(
                url, timeout=5, allow_redirects=True, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )
            responses.append(resp.status_code)

        if 429 in responses:
            result.rate_limiting_detected = True
    except requests.RequestException:
        pass

    if not result.rate_limiting_detected:
        result.missing_protections.append("No rate limiting detected")

    if not result.actually_open and len(management_ports) <= 3:
        result.grade = "A"
    elif len(result.actually_open) <= 1 and len(management_ports) <= 5:
        result.grade = "B"
    elif len(result.actually_open) <= 3:
        result.grade = "C"
    else:
        result.grade = "D"

    return result


def _extract_ips(text: str) -> list[str]:
    return re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
