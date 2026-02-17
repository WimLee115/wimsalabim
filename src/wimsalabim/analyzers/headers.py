"""HTTP security headers analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 15,
        "description": "HSTS - Forces HTTPS connections",
    },
    "Content-Security-Policy": {
        "weight": 15,
        "description": "CSP - Controls resource loading",
    },
    "X-Frame-Options": {
        "weight": 10,
        "description": "Prevents clickjacking attacks",
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "Prevents MIME-type sniffing",
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controls referrer information",
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Controls browser features",
    },
    "X-XSS-Protection": {
        "weight": 5,
        "description": "Legacy XSS filter (deprecated but checked)",
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 5,
        "description": "COOP - Isolates browsing context",
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 5,
        "description": "CORP - Controls cross-origin reads",
    },
    "Cross-Origin-Embedder-Policy": {
        "weight": 5,
        "description": "COEP - Controls embedding",
    },
}

INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version", "X-Generator",
]


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: str = ""
    description: str = ""
    score: int = 0
    max_score: int = 0


@dataclass
class HeadersReport:
    target: str
    available: bool = False
    status_code: int = 0
    redirect_url: str = ""
    https_redirect: bool = False
    headers_present: list[HeaderCheck] = field(default_factory=list)
    headers_missing: list[HeaderCheck] = field(default_factory=list)
    info_leaks: dict[str, str] = field(default_factory=dict)
    cookies_issues: list[str] = field(default_factory=list)
    score: int = 0
    max_score: int = 100
    grade: str = "N/A"

    @property
    def present_count(self) -> int:
        return len(self.headers_present)

    @property
    def missing_count(self) -> int:
        return len(self.headers_missing)


def analyze_headers(target: str) -> HeadersReport:
    report = HeadersReport(target=target)

    url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        report.available = True
        report.status_code = resp.status_code
    except requests.RequestException:
        try:
            url = f"http://{target}"
            resp = requests.get(url, timeout=10, allow_redirects=True)
            report.available = True
            report.status_code = resp.status_code
        except requests.RequestException:
            return report

    if resp.history:
        first_url = resp.history[0].url
        if first_url.startswith("http://") and resp.url.startswith("https://"):
            report.https_redirect = True
        report.redirect_url = resp.url

    headers = resp.headers
    total_score = 0
    max_possible = 0

    for header_name, info in SECURITY_HEADERS.items():
        weight = info["weight"]
        max_possible += weight
        value = headers.get(header_name, "")

        check = HeaderCheck(
            name=header_name,
            present=bool(value),
            value=value[:200] if value else "",
            description=info["description"],
            max_score=weight,
        )

        if value:
            earned = _evaluate_header(header_name, value, weight)
            check.score = earned
            total_score += earned
            report.headers_present.append(check)
        else:
            report.headers_missing.append(check)

    for leak_header in INFO_LEAK_HEADERS:
        val = headers.get(leak_header, "")
        if val:
            report.info_leaks[leak_header] = val

    _check_cookies(resp, report)

    report.max_score = max_possible
    pct = (total_score / max_possible * 100) if max_possible > 0 else 0
    report.score = round(pct)
    report.grade = _grade_from_score(pct)

    return report


def _evaluate_header(name: str, value: str, max_score: int) -> int:
    value_lower = value.lower()

    if name == "Strict-Transport-Security":
        score = max_score * 0.6
        if "max-age=" in value_lower:
            try:
                age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                if age >= 31536000:
                    score = max_score
                elif age >= 15768000:
                    score = max_score * 0.8
            except (ValueError, IndexError):
                pass
        if "includesubdomains" in value_lower:
            score = min(score + 1, max_score)
        if "preload" in value_lower:
            score = min(score + 1, max_score)
        return round(score)

    if name == "Content-Security-Policy":
        score = max_score * 0.5
        if "default-src" in value_lower:
            score += max_score * 0.2
        if "'unsafe-inline'" not in value_lower:
            score += max_score * 0.15
        if "'unsafe-eval'" not in value_lower:
            score += max_score * 0.15
        return min(round(score), max_score)

    if name == "X-Frame-Options":
        if value_lower in ("deny", "sameorigin"):
            return max_score
        return round(max_score * 0.5)

    if name == "X-Content-Type-Options":
        return max_score if value_lower == "nosniff" else round(max_score * 0.5)

    return max_score


def _check_cookies(resp: requests.Response, report: HeadersReport) -> None:
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append(f"Cookie '{cookie.name}' missing Secure flag")
        if cookie.has_nonstandard_attr("httponly") is False:
            pass
        cookie_header = resp.headers.get("Set-Cookie", "")
        if cookie.name in cookie_header:
            if "httponly" not in cookie_header.lower():
                issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
            if "samesite" not in cookie_header.lower():
                issues.append(f"Cookie '{cookie.name}' missing SameSite attribute")
        report.cookies_issues.extend(issues)


def _grade_from_score(pct: float) -> str:
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"
