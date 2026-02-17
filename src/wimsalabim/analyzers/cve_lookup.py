"""CVE vulnerability lookup for detected services."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class CVEEntry:
    cve_id: str
    severity: str = ""
    score: float = 0.0
    description: str = ""
    published: str = ""
    affected_product: str = ""


@dataclass
class CVEReport:
    target: str
    vulnerabilities: list[CVEEntry] = field(default_factory=list)
    products_checked: list[str] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    issues: list[str] = field(default_factory=list)

    @property
    def total_cves(self) -> int:
        return len(self.vulnerabilities)


PRODUCT_CPE_MAP = {
    "nginx": "cpe:2.3:a:f5:nginx",
    "apache": "cpe:2.3:a:apache:http_server",
    "iis": "cpe:2.3:a:microsoft:internet_information_services",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "php": "cpe:2.3:a:php:php",
    "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "drupal": "cpe:2.3:a:drupal:drupal",
    "joomla": "cpe:2.3:a:joomla:joomla",
    "jquery": "cpe:2.3:a:jquery:jquery",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "mysql": "cpe:2.3:a:oracle:mysql",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "redis": "cpe:2.3:a:redis:redis",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "express": "cpe:2.3:a:expressjs:express",
    "django": "cpe:2.3:a:djangoproject:django",
    "flask": "cpe:2.3:a:palletsprojects:flask",
    "spring": "cpe:2.3:a:vmware:spring_framework",
    "rails": "cpe:2.3:a:rubyonrails:rails",
    "laravel": "cpe:2.3:a:laravel:laravel",
    "next.js": "cpe:2.3:a:vercel:next.js",
    "react": "cpe:2.3:a:facebook:react",
    "angular": "cpe:2.3:a:google:angular",
    "vue.js": "cpe:2.3:a:vuejs:vue.js",
}


def lookup_cves(
    products: list[tuple[str, str]],
    target: str = "",
    max_per_product: int = 5,
) -> CVEReport:
    """Look up CVEs for detected products.

    Args:
        products: List of (product_name, version) tuples.
        target: Target domain for the report.
        max_per_product: Max CVEs to return per product.
    """
    report = CVEReport(target=target)

    for product_name, version in products:
        product_lower = product_name.lower()
        report.products_checked.append(f"{product_name} {version}".strip())

        cves = _query_osv(product_lower, version, max_per_product)
        if not cves:
            cves = _query_nist(product_lower, version, max_per_product)

        for cve in cves:
            cve.affected_product = product_name
            report.vulnerabilities.append(cve)

            if cve.severity == "CRITICAL":
                report.critical_count += 1
            elif cve.severity == "HIGH":
                report.high_count += 1
            elif cve.severity == "MEDIUM":
                report.medium_count += 1
            elif cve.severity == "LOW":
                report.low_count += 1

    if report.critical_count > 0:
        report.issues.append(
            f"{report.critical_count} CRITICAL vulnerabilities found"
        )
    if report.high_count > 0:
        report.issues.append(
            f"{report.high_count} HIGH severity vulnerabilities found"
        )

    return report


def _query_osv(product: str, version: str, limit: int) -> list[CVEEntry]:
    """Query the OSV.dev API for vulnerabilities."""
    results = []
    try:
        payload = {"package": {"name": product, "ecosystem": "OSS-Fuzz"}}
        if version:
            payload["version"] = version

        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulns", [])[:limit]:
                severity = "MEDIUM"
                score = 0.0
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score_str = sev.get("score", "")
                        try:
                            score = float(score_str) if score_str else 0.0
                        except ValueError:
                            score = 0.0
                        severity = _score_to_severity(score)

                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))

                results.append(CVEEntry(
                    cve_id=cve_id,
                    severity=severity,
                    score=score,
                    description=vuln.get("summary", "")[:200],
                    published=vuln.get("published", "")[:10],
                    affected_product=product,
                ))
    except Exception:
        pass
    return results


def _query_nist(product: str, version: str, limit: int) -> list[CVEEntry]:
    """Query NIST NVD API for vulnerabilities."""
    results = []
    try:
        keyword = f"{product} {version}".strip()
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulnerabilities", [])[:limit]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                score = 0.0
                severity = "MEDIUM"
                metrics = cve.get("metrics", {})
                for v3 in metrics.get("cvssMetricV31", []):
                    cvss = v3.get("cvssData", {})
                    score = cvss.get("baseScore", 0.0)
                    severity = cvss.get("baseSeverity", "MEDIUM")
                    break

                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break

                published = cve.get("published", "")[:10]

                results.append(CVEEntry(
                    cve_id=cve_id,
                    severity=severity.upper(),
                    score=score,
                    description=desc,
                    published=published,
                    affected_product=product,
                ))
    except Exception:
        pass
    return results


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"
