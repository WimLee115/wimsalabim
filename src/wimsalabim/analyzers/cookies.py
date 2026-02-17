"""Cookie security analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class CookieAnalysis:
    name: str
    value_preview: str = ""
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    path: str = "/"
    domain: str = ""
    expires: str = ""
    size: int = 0
    issues: list[str] = field(default_factory=list)
    risk: str = "info"


@dataclass
class CookieReport:
    target: str
    available: bool = False
    cookies: list[CookieAnalysis] = field(default_factory=list)
    total_cookies: int = 0
    secure_count: int = 0
    httponly_count: int = 0
    samesite_count: int = 0
    session_cookies: list[str] = field(default_factory=list)
    tracking_cookies: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


SESSION_COOKIE_NAMES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
    "session", "sessionid", "session_id", "sid", "laravel_session",
    "rack.session", "django_session", "csrftoken", "csrf_token",
    "_csrf", "xsrf-token",
}

TRACKING_COOKIE_PATTERNS = [
    "_ga", "_gid", "_gat", "__utm", "_fbp", "_fbc", "_gcl",
    "hubspot", "_hj", "_pk_", "intercom", "ajs_", "_mkto",
    "pardot", "eloqua", "__hs", "_clck", "_clsk",
]


def analyze_cookies(target: str) -> CookieReport:
    report = CookieReport(target=target)

    url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        report.available = True
    except requests.RequestException:
        try:
            url = f"http://{target}"
            resp = requests.get(url, timeout=10, allow_redirects=True)
            report.available = True
        except requests.RequestException:
            return report

    is_https = url.startswith("https")
    set_cookie_headers = resp.headers.get("Set-Cookie", "")
    raw_cookies = _extract_raw_cookies(resp)

    for cookie in resp.cookies:
        analysis = _analyze_cookie(cookie, set_cookie_headers, is_https)
        report.cookies.append(analysis)

        name_lower = cookie.name.lower()
        if name_lower in SESSION_COOKIE_NAMES:
            report.session_cookies.append(cookie.name)
        for pattern in TRACKING_COOKIE_PATTERNS:
            if pattern in name_lower:
                report.tracking_cookies.append(cookie.name)
                break

    report.total_cookies = len(report.cookies)
    report.secure_count = sum(1 for c in report.cookies if c.secure)
    report.httponly_count = sum(1 for c in report.cookies if c.httponly)
    report.samesite_count = sum(1 for c in report.cookies if c.samesite)

    _aggregate_issues(report)
    _calculate_grade(report)

    return report


def _analyze_cookie(
    cookie: requests.cookies.RequestsCookieJar,
    raw_header: str,
    is_https: bool,
) -> CookieAnalysis:
    analysis = CookieAnalysis(
        name=cookie.name,
        value_preview=cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
        secure=cookie.secure,
        path=cookie.path or "/",
        domain=cookie.domain or "",
        size=len(cookie.name) + len(cookie.value),
    )

    cookie_section = _find_cookie_section(cookie.name, raw_header)
    cookie_lower = cookie_section.lower()

    analysis.httponly = "httponly" in cookie_lower
    analysis.secure = analysis.secure or "secure" in cookie_lower

    if "samesite=strict" in cookie_lower:
        analysis.samesite = "Strict"
    elif "samesite=lax" in cookie_lower:
        analysis.samesite = "Lax"
    elif "samesite=none" in cookie_lower:
        analysis.samesite = "None"

    name_lower = cookie.name.lower()
    is_session = name_lower in SESSION_COOKIE_NAMES

    if is_https and not analysis.secure:
        analysis.issues.append("Missing Secure flag on HTTPS site")
        analysis.risk = "high" if is_session else "medium"

    if is_session and not analysis.httponly:
        analysis.issues.append("Session cookie missing HttpOnly flag")
        analysis.risk = "high"

    if not analysis.samesite:
        analysis.issues.append("Missing SameSite attribute")
        if is_session:
            analysis.risk = "medium"

    if analysis.samesite == "None" and not analysis.secure:
        analysis.issues.append("SameSite=None requires Secure flag")
        analysis.risk = "high"

    if analysis.path == "/":
        pass
    elif analysis.path and is_session:
        pass

    if analysis.size > 4096:
        analysis.issues.append(f"Cookie exceeds 4KB limit ({analysis.size} bytes)")

    return analysis


def _find_cookie_section(cookie_name: str, raw_header: str) -> str:
    for part in raw_header.split(","):
        if cookie_name in part:
            return part
    return ""


def _extract_raw_cookies(resp: requests.Response) -> list[str]:
    return resp.headers.get("Set-Cookie", "").split(",")


def _aggregate_issues(report: CookieReport) -> None:
    for cookie in report.cookies:
        for issue in cookie.issues:
            report.issues.append(f"{cookie.name}: {issue}")


def _calculate_grade(report: CookieReport) -> None:
    if report.total_cookies == 0:
        report.grade = "A"
        return

    score = 100
    total = report.total_cookies

    if total > 0:
        secure_pct = report.secure_count / total
        httponly_pct = report.httponly_count / total
        samesite_pct = report.samesite_count / total

        score -= round((1 - secure_pct) * 25)
        score -= round((1 - httponly_pct) * 25)
        score -= round((1 - samesite_pct) * 15)

    for cookie in report.cookies:
        if cookie.risk == "high":
            score -= 15
        elif cookie.risk == "medium":
            score -= 8

    score = max(0, score)

    if score >= 90:
        report.grade = "A"
    elif score >= 75:
        report.grade = "B"
    elif score >= 55:
        report.grade = "C"
    elif score >= 35:
        report.grade = "D"
    else:
        report.grade = "F"
