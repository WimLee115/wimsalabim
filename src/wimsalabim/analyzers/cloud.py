"""Cloud infrastructure detection analyzer."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

import requests


@dataclass
class CloudService:
    provider: str
    service: str
    evidence: str
    risk: str = "info"


@dataclass
class CloudReport:
    target: str
    services_detected: list[CloudService] = field(default_factory=list)
    cloud_provider: str = ""
    is_cloud_hosted: bool = False
    cdn_detected: str = ""
    storage_exposed: list[str] = field(default_factory=list)
    metadata_accessible: bool = False
    issues: list[str] = field(default_factory=list)

    @property
    def service_count(self) -> int:
        return len(self.services_detected)


CLOUD_IP_RANGES = {
    "AWS": [
        "3.", "13.", "15.", "18.", "34.", "35.", "44.", "50.", "52.", "54.",
        "63.", "75.", "76.", "99.", "100.", "107.", "108.", "109.", "142.",
        "143.", "150.", "157.", "160.", "161.", "162.", "168.", "170.", "174.",
        "175.", "176.", "177.", "184.", "185.", "192.", "198.", "199.", "204.",
        "205.", "216.",
    ],
    "Azure": ["13.", "20.", "23.", "40.", "51.", "52.", "65.", "70.", "104.", "168.", "191."],
    "GCP": ["8.34.", "8.35.", "23.236.", "23.251.", "34.", "35.", "104.", "107.", "108.", "130.", "142.", "146.", "162.", "172.", "173.", "199.", "209."],
}

CLOUD_CNAME_PATTERNS = {
    "AWS": [
        r"\.amazonaws\.com", r"\.cloudfront\.net", r"\.elasticbeanstalk\.com",
        r"\.elb\.amazonaws\.com", r"\.s3[\.\-]", r"\.awsglobalaccelerator\.com",
    ],
    "Azure": [
        r"\.azurewebsites\.net", r"\.azure-api\.net", r"\.azureedge\.net",
        r"\.azurefd\.net", r"\.cloudapp\.azure\.com", r"\.blob\.core\.windows\.net",
        r"\.trafficmanager\.net",
    ],
    "GCP": [
        r"\.googleapis\.com", r"\.appspot\.com", r"\.run\.app",
        r"\.cloudfunctions\.net", r"\.storage\.googleapis\.com",
        r"\.web\.app", r"\.firebaseapp\.com",
    ],
    "DigitalOcean": [r"\.digitaloceanspaces\.com", r"\.ondigitalocean\.app"],
    "Heroku": [r"\.herokuapp\.com", r"\.herokussl\.com"],
    "Vercel": [r"\.vercel\.app", r"\.now\.sh"],
    "Netlify": [r"\.netlify\.app", r"\.netlify\.com"],
    "Render": [r"\.onrender\.com"],
    "Railway": [r"\.railway\.app"],
    "Fly.io": [r"\.fly\.dev"],
}

STORAGE_PATTERNS = [
    ("https://{target}.s3.amazonaws.com", "AWS S3 Bucket"),
    ("https://s3.amazonaws.com/{target}", "AWS S3 Bucket"),
    ("https://{target}.blob.core.windows.net", "Azure Blob Storage"),
    ("https://storage.googleapis.com/{target}", "GCP Storage Bucket"),
    ("https://{target}.storage.googleapis.com", "GCP Storage Bucket"),
]


def analyze_cloud(target: str) -> CloudReport:
    report = CloudReport(target=target)

    _detect_by_ip(target, report)
    _detect_by_cname(target, report)
    _detect_by_headers(target, report)
    _check_storage_exposure(target, report)

    providers = [s.provider for s in report.services_detected]
    if providers:
        report.is_cloud_hosted = True
        from collections import Counter
        most_common = Counter(providers).most_common(1)
        if most_common:
            report.cloud_provider = most_common[0][0]

    return report


def _detect_by_ip(target: str, report: CloudReport) -> None:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return

    for provider, prefixes in CLOUD_IP_RANGES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                report.services_detected.append(CloudService(
                    provider=provider,
                    service="Compute",
                    evidence=f"IP {ip} matches {provider} range",
                ))
                return


def _detect_by_cname(target: str, report: CloudReport) -> None:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5

    try:
        answers = resolver.resolve(target, "CNAME")
        for rdata in answers:
            cname = rdata.to_text().rstrip(".")
            for provider, patterns in CLOUD_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, cname, re.I):
                        report.services_detected.append(CloudService(
                            provider=provider,
                            service="Hosting",
                            evidence=f"CNAME {cname} matches {provider}",
                        ))
                        return
    except Exception:
        pass


def _detect_by_headers(target: str, report: CloudReport) -> None:
    url = f"https://{target}"
    try:
        resp = requests.head(
            url, timeout=5, allow_redirects=True, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
    except requests.RequestException:
        return

    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

    header_cloud_map = {
        "x-amz-": ("AWS", "S3/CloudFront"),
        "x-ms-": ("Azure", "Azure Service"),
        "x-goog-": ("GCP", "Google Cloud"),
        "x-vercel-": ("Vercel", "Vercel Platform"),
        "x-netlify": ("Netlify", "Netlify CDN"),
        "x-fly-": ("Fly.io", "Fly.io Edge"),
        "x-render-": ("Render", "Render Platform"),
        "x-railway-": ("Railway", "Railway Platform"),
    }

    for header_key in headers:
        for prefix, (provider, service) in header_cloud_map.items():
            if header_key.startswith(prefix):
                if provider not in [s.provider for s in report.services_detected]:
                    report.services_detected.append(CloudService(
                        provider=provider,
                        service=service,
                        evidence=f"Header: {header_key}",
                    ))

    server = headers.get("server", "")
    if "amazons3" in server:
        report.services_detected.append(CloudService("AWS", "S3", "Server header"))
    elif "gse" in server or "google" in server:
        report.services_detected.append(CloudService("GCP", "Google Frontend", "Server header"))
    elif "microsoft" in server:
        report.services_detected.append(CloudService("Azure", "Azure Service", "Server header"))


def _check_storage_exposure(target: str, report: CloudReport) -> None:
    domain_parts = target.split(".")
    names_to_check = [target, domain_parts[0]] if domain_parts else [target]

    for name in names_to_check:
        for url_template, service_name in STORAGE_PATTERNS:
            url = url_template.format(target=name)
            try:
                resp = requests.head(url, timeout=3, allow_redirects=True)
                if resp.status_code in (200, 403):
                    status = "accessible" if resp.status_code == 200 else "exists but restricted"
                    report.storage_exposed.append(f"{service_name}: {url} ({status})")
                    if resp.status_code == 200:
                        report.issues.append(
                            f"Cloud storage publicly accessible: {url}"
                        )
            except requests.RequestException:
                continue
