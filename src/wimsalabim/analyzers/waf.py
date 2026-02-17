"""Web Application Firewall (WAF) detection analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class WAFReport:
    target: str
    detected: bool = False
    waf_name: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    bypass_hints: list[str] = field(default_factory=list)


WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"cf-ray": None, "cf-cache-status": None, "server": "cloudflare"},
        "cookies": ["__cfduid", "__cf_bm", "_cfuvid"],
        "body": ["cloudflare", "cf-browser-verification", "ray id"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": None, "x-amz-cf-id": None},
        "cookies": ["awsalb", "awsalbcors"],
        "body": [],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": None, "akamai-grn": None},
        "cookies": ["akamai", "ak_bmsc", "bm_sv"],
        "body": ["access denied", "akamai"],
    },
    "Imperva/Incapsula": {
        "headers": {"x-iinfo": None, "x-cdn": "incapsula"},
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
        "body": ["incapsula", "imperva"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": None, "server": "sucuri"},
        "cookies": ["sucuri_cloudproxy"],
        "body": ["sucuri", "cloudproxy"],
    },
    "F5 BIG-IP": {
        "headers": {"server": "big-ip", "x-wa-info": None},
        "cookies": ["bigipserver", "ts", "f5_cspm"],
        "body": [],
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
        "body": ["mod_security", "modsecurity", "noyb"],
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "cookies": ["barra_counter_session"],
        "body": ["barracuda"],
    },
    "Fortinet/FortiWeb": {
        "headers": {"server": "fortiweb"},
        "cookies": ["fortigate", "fortiweb"],
        "body": ["fortigate", "fortinet"],
    },
    "Wordfence": {
        "headers": {},
        "cookies": ["wfwaf-authcookie"],
        "body": ["wordfence", "wf-block"],
    },
    "DDoS-Guard": {
        "headers": {"server": "ddos-guard"},
        "cookies": ["__ddg1_", "__ddg2_"],
        "body": ["ddos-guard"],
    },
    "Fastly": {
        "headers": {"x-fastly-request-id": None, "via": "varnish"},
        "cookies": [],
        "body": [],
    },
    "Vercel": {
        "headers": {"x-vercel-id": None, "server": "vercel"},
        "cookies": [],
        "body": [],
    },
}

WAF_TRIGGER_PAYLOADS = [
    "/<script>alert(1)</script>",
    "/?id=1' OR '1'='1",
    "/?cmd=cat /etc/passwd",
    "/?file=../../etc/passwd",
    "/wp-admin/",
    "/?search=<img src=x onerror=alert(1)>",
]


def detect_waf(target: str) -> WAFReport:
    report = WAFReport(target=target)

    url = f"https://{target}" if not target.startswith("http") else target

    try:
        normal_resp = requests.get(
            url, timeout=10, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
    except requests.RequestException:
        try:
            url = f"http://{target}"
            normal_resp = requests.get(url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return report

    _check_signatures(normal_resp, report)

    if not report.detected:
        _trigger_waf(url, normal_resp.status_code, report)

    return report


def _check_signatures(resp: requests.Response, report: WAFReport) -> None:
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    cookies = {c.name.lower(): c.value for c in resp.cookies}
    body = resp.text[:5000].lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0.0
        evidence = []

        for header_key, header_val in sigs.get("headers", {}).items():
            header_key = header_key.lower()
            if header_key in headers:
                if header_val is None or header_val in headers[header_key]:
                    score += 0.4
                    evidence.append(f"Header match: {header_key}")

        for cookie_pattern in sigs.get("cookies", []):
            cookie_pattern = cookie_pattern.lower()
            for cookie_name in cookies:
                if cookie_pattern in cookie_name:
                    score += 0.3
                    evidence.append(f"Cookie match: {cookie_name}")
                    break

        for body_pattern in sigs.get("body", []):
            if body_pattern in body:
                score += 0.2
                evidence.append(f"Body match: {body_pattern}")

        if score >= 0.4:
            report.detected = True
            report.waf_name = waf_name
            report.confidence = min(score, 1.0)
            report.evidence = evidence
            return


def _trigger_waf(base_url: str, normal_status: int, report: WAFReport) -> None:
    for payload in WAF_TRIGGER_PAYLOADS[:3]:
        try:
            resp = requests.get(
                base_url + payload,
                timeout=5, allow_redirects=True, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )

            if resp.status_code in (403, 406, 429, 503) and normal_status == 200:
                report.detected = True
                report.waf_name = "Unknown WAF"
                report.confidence = 0.6
                report.evidence.append(
                    f"Payload triggered {resp.status_code} (normal: {normal_status})"
                )

                _check_signatures(resp, report)
                return

            body_lower = resp.text[:3000].lower()
            block_indicators = [
                "blocked", "forbidden", "access denied", "security",
                "waf", "firewall", "captcha", "challenge",
            ]
            if any(ind in body_lower for ind in block_indicators):
                report.detected = True
                report.waf_name = report.waf_name or "Unknown WAF"
                report.confidence = max(report.confidence, 0.5)
                report.evidence.append("Block page detected in response")
                return

        except requests.RequestException:
            continue
