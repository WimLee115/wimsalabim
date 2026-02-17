"""CORS misconfiguration analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class CORSReport:
    target: str
    available: bool = False
    cors_enabled: bool = False
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    expose_headers: list[str] = field(default_factory=list)
    max_age: int = 0
    wildcard_origin: bool = False
    null_origin_allowed: bool = False
    reflects_origin: bool = False
    subdomain_allowed: bool = False
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


MALICIOUS_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def analyze_cors(target: str) -> CORSReport:
    report = CORSReport(target=target)

    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = requests.options(
            base_url,
            timeout=10,
            headers={
                "Origin": f"https://{target}",
                "Access-Control-Request-Method": "GET",
                "User-Agent": "Wimsalabim/0.1 Security Scanner",
            },
            allow_redirects=True,
            verify=False,
        )
        report.available = True
    except requests.RequestException:
        try:
            base_url = f"http://{target}"
            resp = requests.options(
                base_url, timeout=10,
                headers={"Origin": f"http://{target}",
                         "Access-Control-Request-Method": "GET"},
                allow_redirects=True,
            )
            report.available = True
        except requests.RequestException:
            return report

    _parse_cors_headers(resp, report)
    _test_origin_reflection(base_url, target, report)
    _test_null_origin(base_url, report)
    _test_subdomain(base_url, target, report)
    _calculate_grade(report)

    return report


def _parse_cors_headers(resp: requests.Response, report: CORSReport) -> None:
    headers = resp.headers

    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao:
        report.cors_enabled = True
        report.allow_origin = acao
        if acao == "*":
            report.wildcard_origin = True

    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acac.lower() == "true":
        report.allow_credentials = True

    acam = headers.get("Access-Control-Allow-Methods", "")
    if acam:
        report.allow_methods = [m.strip() for m in acam.split(",")]

    acah = headers.get("Access-Control-Allow-Headers", "")
    if acah:
        report.allow_headers = [h.strip() for h in acah.split(",")]

    aceh = headers.get("Access-Control-Expose-Headers", "")
    if aceh:
        report.expose_headers = [h.strip() for h in aceh.split(",")]

    acma = headers.get("Access-Control-Max-Age", "")
    if acma:
        try:
            report.max_age = int(acma)
        except ValueError:
            pass


def _test_origin_reflection(base_url: str, target: str, report: CORSReport) -> None:
    for origin in MALICIOUS_ORIGINS:
        if origin == "null":
            continue
        try:
            resp = requests.get(
                base_url, timeout=5, verify=False,
                headers={"Origin": origin,
                         "User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                report.reflects_origin = True
                report.issues.append(
                    f"CORS reflects arbitrary origin: {origin}"
                )
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acac.lower() == "true":
                    report.issues.append(
                        "CRITICAL: Reflected origin with credentials allowed"
                    )
                return
        except requests.RequestException:
            continue


def _test_null_origin(base_url: str, report: CORSReport) -> None:
    try:
        resp = requests.get(
            base_url, timeout=5, verify=False,
            headers={"Origin": "null",
                     "User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "null":
            report.null_origin_allowed = True
            report.issues.append("CORS allows null origin")
    except requests.RequestException:
        pass


def _test_subdomain(base_url: str, target: str, report: CORSReport) -> None:
    test_origin = f"https://evil.{target}"
    try:
        resp = requests.get(
            base_url, timeout=5, verify=False,
            headers={"Origin": test_origin,
                     "User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == test_origin:
            report.subdomain_allowed = True
            report.issues.append(
                f"CORS allows arbitrary subdomains: {test_origin}"
            )
    except requests.RequestException:
        pass


def _calculate_grade(report: CORSReport) -> None:
    if not report.cors_enabled:
        report.grade = "A"
        return

    score = 100

    if report.reflects_origin:
        score -= 40
    if report.null_origin_allowed:
        score -= 25
    if report.subdomain_allowed:
        score -= 20
    if report.wildcard_origin and report.allow_credentials:
        score -= 50
        report.issues.append("Wildcard origin with credentials is a critical misconfiguration")
    elif report.wildcard_origin:
        score -= 15

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
