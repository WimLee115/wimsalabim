"""JavaScript secrets and sensitive data scanner. rootmap:WimLee115"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests


@dataclass
class SecretFinding:
    secret_type: str
    pattern_name: str
    matched_value: str
    source_url: str
    confidence: float = 0.0
    severity: str = "medium"


@dataclass
class JSEndpoint:
    url: str
    method: str = "GET"
    source: str = ""


@dataclass
class JSAnalysisReport:
    target: str
    available: bool = False
    scripts_found: list[str] = field(default_factory=list)
    scripts_analyzed: int = 0
    secrets: list[SecretFinding] = field(default_factory=list)
    endpoints: list[JSEndpoint] = field(default_factory=list)
    source_maps_exposed: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"

    @property
    def secret_count(self) -> int:
        return len(self.secrets)

    @property
    def critical_secrets(self) -> list[SecretFinding]:
        return [s for s in self.secrets if s.severity == "critical"]

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)


SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "critical", 0.95),
    ("AWS Secret Key", r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "critical", 0.9),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high", 0.9),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "high", 0.85),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "critical", 0.95),
    ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", "critical", 0.95),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", "high", 0.9),
    ("Stripe Secret", r"sk_live_[0-9a-zA-Z]{24,}", "critical", 0.95),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}", "low", 0.9),
    ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "critical", 0.99),
    ("JWT Token", r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+", "high", 0.8),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "high", 0.7),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high", 0.7),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "critical", 0.95),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", "medium", 0.8),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "high", 0.7),
    ("Generic API Key", r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]([a-zA-Z0-9]{16,64})['\"]", "medium", 0.6),
    ("Generic Secret", r"(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,64})['\"]", "medium", 0.5),
    ("Authorization Header", r"(?:Authorization|Bearer)\s*[:=]\s*['\"]([^'\"]{20,})['\"]", "high", 0.7),
    ("Database URL", r"(?:mongodb|postgres|mysql|redis)://[^\s'\"]+", "critical", 0.9),
]

ENDPOINT_PATTERNS = [
    (r"['\"](?:https?://[^'\"]*?/api/[^'\"]+)['\"]", "API URL"),
    (r"['\"](/api/v[0-9]+/[^'\"]+)['\"]", "API Path"),
    (r"['\"](/api/[^'\"]+)['\"]", "API Path"),
    (r"fetch\(['\"]([^'\"]+)['\"]", "Fetch Call"),
    (r"axios\.[a-z]+\(['\"]([^'\"]+)['\"]", "Axios Call"),
    (r"\.(?:get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", "HTTP Method"),
    (r"['\"](/graphql)['\"]", "GraphQL"),
    (r"['\"](/v[0-9]+/[^'\"]+)['\"]", "Versioned API"),
]


def analyze_js(target: str) -> JSAnalysisReport:
    report = JSAnalysisReport(target=target)

    scripts = _discover_scripts(target, report)
    if not scripts:
        report.grade = "N/A"
        return report

    report.available = True
    report.scripts_found = scripts

    for script_url in scripts[:20]:
        content = _fetch_script(script_url)
        if content:
            report.scripts_analyzed += 1
            _scan_secrets(content, script_url, report)
            _extract_endpoints(content, script_url, report)
            _check_source_map(content, script_url, report)

    _deduplicate_endpoints(report)
    _calculate_grade(report)

    return report


def _discover_scripts(target: str, report: JSAnalysisReport) -> list[str]:
    scripts = []

    url = f"https://{target}"
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        if resp.status_code != 200:
            return scripts

        src_pattern = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)

        for src in src_pattern:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = f"https://{target}{src}"
            elif not src.startswith("http"):
                src = f"https://{target}/{src}"

            if any(ext in src for ext in (".js", ".mjs", ".jsx")):
                scripts.append(src)

    except requests.RequestException:
        pass

    common_js = [
        f"https://{target}/main.js",
        f"https://{target}/app.js",
        f"https://{target}/bundle.js",
        f"https://{target}/static/js/main.js",
        f"https://{target}/dist/main.js",
        f"https://{target}/assets/index.js",
    ]

    for js_url in common_js:
        if js_url not in scripts:
            try:
                resp = requests.head(
                    js_url, timeout=5, allow_redirects=True, verify=False,
                    headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
                )
                if resp.status_code == 200:
                    scripts.append(js_url)
            except requests.RequestException:
                continue

    return scripts[:30]


def _fetch_script(url: str) -> str:
    try:
        resp = requests.get(
            url, timeout=10, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        if resp.status_code == 200:
            return resp.text[:500_000]
    except requests.RequestException:
        pass
    return ""


def _scan_secrets(content: str, source_url: str, report: JSAnalysisReport) -> None:
    for name, pattern, severity, confidence in SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        for match in matches[:3]:
            matched = match if isinstance(match, str) else match[0] if match else ""
            if len(matched) < 8:
                continue

            masked = matched[:4] + "****" + matched[-4:] if len(matched) > 12 else "****"

            report.secrets.append(SecretFinding(
                secret_type=severity,
                pattern_name=name,
                matched_value=masked,
                source_url=source_url,
                confidence=confidence,
                severity=severity,
            ))

    if report.secrets:
        report.issues.append(f"{len(report.secrets)} potential secrets found in JavaScript")


def _extract_endpoints(content: str, source_url: str, report: JSAnalysisReport) -> None:
    for pattern, method in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, content)
        for match in matches[:10]:
            if len(match) > 5 and not match.endswith((".css", ".png", ".jpg", ".svg", ".ico")):
                report.endpoints.append(JSEndpoint(
                    url=match,
                    method=method,
                    source=source_url,
                ))


def _check_source_map(content: str, script_url: str, report: JSAnalysisReport) -> None:
    match = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", content)
    if match:
        map_url = match.group(1)
        if map_url.startswith("data:"):
            return

        if not map_url.startswith("http"):
            base = script_url.rsplit("/", 1)[0]
            map_url = f"{base}/{map_url}"

        try:
            resp = requests.head(
                map_url, timeout=5, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )
            if resp.status_code == 200:
                report.source_maps_exposed.append(map_url)
                report.issues.append(f"Source map exposed: {map_url}")
        except requests.RequestException:
            pass


def _deduplicate_endpoints(report: JSAnalysisReport) -> None:
    seen = set()
    unique = []
    for ep in report.endpoints:
        if ep.url not in seen:
            seen.add(ep.url)
            unique.append(ep)
    report.endpoints = unique


def _calculate_grade(report: JSAnalysisReport) -> None:
    if not report.available:
        report.grade = "N/A"
        return

    score = 100

    critical = sum(1 for s in report.secrets if s.severity == "critical")
    high = sum(1 for s in report.secrets if s.severity == "high")
    medium = sum(1 for s in report.secrets if s.severity == "medium")

    score -= critical * 25
    score -= high * 15
    score -= medium * 5
    score -= len(report.source_maps_exposed) * 10

    if score >= 90:
        report.grade = "A"
    elif score >= 75:
        report.grade = "B"
    elif score >= 60:
        report.grade = "C"
    elif score >= 40:
        report.grade = "D"
    else:
        report.grade = "F"
