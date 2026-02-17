"""Technology fingerprinting analyzer."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests


@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: float = 1.0


@dataclass
class TechReport:
    target: str
    available: bool = False
    technologies: list[Technology] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    framework: str = ""
    cms: str = ""
    cdn: str = ""
    waf_hint: str = ""
    programming_language: str = ""
    js_libraries: list[str] = field(default_factory=list)
    meta_generator: str = ""

    @property
    def tech_count(self) -> int:
        return len(self.technologies)

    @property
    def categories(self) -> dict[str, list[Technology]]:
        cats: dict[str, list[Technology]] = {}
        for t in self.technologies:
            cats.setdefault(t.category, []).append(t)
        return cats


SERVER_SIGNATURES = {
    "nginx": ("Nginx", "Web Server"),
    "apache": ("Apache", "Web Server"),
    "cloudflare": ("Cloudflare", "CDN/WAF"),
    "iis": ("Microsoft IIS", "Web Server"),
    "litespeed": ("LiteSpeed", "Web Server"),
    "openresty": ("OpenResty", "Web Server"),
    "caddy": ("Caddy", "Web Server"),
    "gunicorn": ("Gunicorn", "WSGI Server"),
    "uvicorn": ("Uvicorn", "ASGI Server"),
    "envoy": ("Envoy", "Proxy"),
    "traefik": ("Traefik", "Proxy"),
    "varnish": ("Varnish", "Cache"),
    "lighttpd": ("Lighttpd", "Web Server"),
}

POWERED_BY_MAP = {
    "php": ("PHP", "Language"),
    "asp.net": ("ASP.NET", "Framework"),
    "express": ("Express.js", "Framework"),
    "django": ("Django", "Framework"),
    "flask": ("Flask", "Framework"),
    "rails": ("Ruby on Rails", "Framework"),
    "next.js": ("Next.js", "Framework"),
    "nuxt": ("Nuxt.js", "Framework"),
    "laravel": ("Laravel", "Framework"),
    "spring": ("Spring", "Framework"),
    "kestrel": ("Kestrel/.NET", "Framework"),
}

HTML_PATTERNS = [
    (r'wp-content|wp-includes|wordpress', "WordPress", "CMS"),
    (r'drupal\.settings|Drupal\.', "Drupal", "CMS"),
    (r'joomla|/components/com_', "Joomla", "CMS"),
    (r'shopify\.com|cdn\.shopify', "Shopify", "E-commerce"),
    (r'woocommerce', "WooCommerce", "E-commerce"),
    (r'magento|mage/cookies', "Magento", "E-commerce"),
    (r'react|__NEXT_DATA__|_next/', "React/Next.js", "JS Framework"),
    (r'ng-version|ng-app|angular', "Angular", "JS Framework"),
    (r'vue\.js|__vue__|nuxt', "Vue.js", "JS Framework"),
    (r'svelte|__svelte', "Svelte", "JS Framework"),
    (r'jquery|jquery\.min\.js', "jQuery", "JS Library"),
    (r'bootstrap\.min\.(css|js)|bootstrap/', "Bootstrap", "CSS Framework"),
    (r'tailwindcss|tailwind\.', "Tailwind CSS", "CSS Framework"),
    (r'google-analytics|gtag|ga\.js|analytics\.js', "Google Analytics", "Analytics"),
    (r'googletagmanager\.com', "Google Tag Manager", "Analytics"),
    (r'cloudflare|cf-ray', "Cloudflare", "CDN"),
    (r'fastly', "Fastly", "CDN"),
    (r'akamai|akadns', "Akamai", "CDN"),
    (r'amazonaws\.com|aws', "AWS", "Cloud"),
    (r'azure|msecnd\.net', "Azure", "Cloud"),
    (r'googleapis\.com|gstatic', "Google Cloud", "Cloud"),
    (r'recaptcha|grecaptcha', "reCAPTCHA", "Security"),
    (r'cloudfront\.net', "CloudFront", "CDN"),
    (r'stripe\.com|stripe\.js', "Stripe", "Payment"),
    (r'sentry\.io|sentry-cdn', "Sentry", "Monitoring"),
    (r'hotjar\.com', "Hotjar", "Analytics"),
    (r'intercom\.io|intercom', "Intercom", "Customer Support"),
    (r'hubspot', "HubSpot", "Marketing"),
    (r'typekit|use\.typekit', "Adobe Fonts", "Fonts"),
    (r'fonts\.googleapis', "Google Fonts", "Fonts"),
]

CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-fastly-request-id": "Fastly",
    "x-akamai-": "Akamai",
    "x-cdn": "Generic CDN",
    "x-cache": "CDN Cache",
    "x-amz-cf-id": "CloudFront",
    "x-vercel-id": "Vercel",
    "x-netlify": "Netlify",
}


def analyze_tech(target: str) -> TechReport:
    report = TechReport(target=target)

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

    _analyze_headers(resp, report)
    _analyze_html(resp.text, report)
    _analyze_cookies(resp, report)
    _deduplicate(report)

    return report


def _analyze_headers(resp: requests.Response, report: TechReport) -> None:
    headers = resp.headers

    server = headers.get("Server", "")
    if server:
        report.server = server
        for sig, (name, cat) in SERVER_SIGNATURES.items():
            if sig in server.lower():
                version = _extract_version(server)
                report.technologies.append(Technology(name, cat, version))
                break

    powered = headers.get("X-Powered-By", "")
    if powered:
        report.powered_by = powered
        for sig, (name, cat) in POWERED_BY_MAP.items():
            if sig in powered.lower():
                version = _extract_version(powered)
                report.technologies.append(Technology(name, cat, version))
                if cat == "Language":
                    report.programming_language = f"{name} {version}".strip()
                elif cat == "Framework":
                    report.framework = name
                break

    for header_key, cdn_name in CDN_HEADERS.items():
        for h in headers:
            if header_key.lower() in h.lower():
                if cdn_name not in [t.name for t in report.technologies]:
                    report.technologies.append(Technology(cdn_name, "CDN"))
                    report.cdn = cdn_name
                break


def _analyze_html(html: str, report: TechReport) -> None:
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if gen_match:
        report.meta_generator = gen_match.group(1)
        report.technologies.append(Technology(gen_match.group(1), "CMS/Generator"))

    for pattern, name, category in HTML_PATTERNS:
        if re.search(pattern, html, re.I):
            if name not in [t.name for t in report.technologies]:
                report.technologies.append(Technology(name, category, confidence=0.8))
                if category == "CMS":
                    report.cms = name


def _analyze_cookies(resp: requests.Response, report: TechReport) -> None:
    cookie_sigs = {
        "PHPSESSID": ("PHP", "Language"),
        "JSESSIONID": ("Java", "Language"),
        "ASP.NET": ("ASP.NET", "Framework"),
        "connect.sid": ("Express.js", "Framework"),
        "laravel_session": ("Laravel", "Framework"),
        "django": ("Django", "Framework"),
        "rack.session": ("Ruby/Rack", "Framework"),
        "_cfuvid": ("Cloudflare", "CDN"),
        "wp-": ("WordPress", "CMS"),
    }

    for cookie in resp.cookies:
        for sig, (name, cat) in cookie_sigs.items():
            if sig.lower() in cookie.name.lower():
                if name not in [t.name for t in report.technologies]:
                    report.technologies.append(Technology(name, cat, confidence=0.7))
                break


def _extract_version(value: str) -> str:
    match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', value)
    return match.group(0) if match else ""


def _deduplicate(report: TechReport) -> None:
    seen = set()
    unique = []
    for tech in report.technologies:
        key = tech.name.lower()
        if key not in seen:
            seen.add(key)
            unique.append(tech)
    report.technologies = unique
