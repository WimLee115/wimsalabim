"""Common directory and path discovery analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class FoundPath:
    path: str
    status_code: int
    content_length: int = 0
    redirect_url: str = ""
    risk: str = "info"
    description: str = ""


@dataclass
class DirectoryReport:
    target: str
    found_paths: list[FoundPath] = field(default_factory=list)
    paths_checked: int = 0
    sensitive_paths: list[FoundPath] = field(default_factory=list)
    robots_txt: str = ""
    sitemap_found: bool = False
    issues: list[str] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return len(self.found_paths)

    @property
    def sensitive_count(self) -> int:
        return len(self.sensitive_paths)


COMMON_PATHS = [
    ("/robots.txt", "info", "Robots file"),
    ("/sitemap.xml", "info", "Sitemap"),
    ("/.git/", "critical", "Git repository exposed"),
    ("/.git/config", "critical", "Git config exposed"),
    ("/.env", "critical", "Environment file exposed"),
    ("/.env.local", "critical", "Local env file exposed"),
    ("/.env.production", "critical", "Production env file exposed"),
    ("/wp-admin/", "medium", "WordPress admin panel"),
    ("/wp-login.php", "medium", "WordPress login"),
    ("/admin/", "high", "Admin panel"),
    ("/admin/login", "high", "Admin login"),
    ("/administrator/", "high", "Admin panel"),
    ("/login", "medium", "Login page"),
    ("/api/", "medium", "API endpoint"),
    ("/api/v1/", "medium", "API v1 endpoint"),
    ("/api/v2/", "medium", "API v2 endpoint"),
    ("/graphql", "medium", "GraphQL endpoint"),
    ("/swagger/", "medium", "Swagger API docs"),
    ("/api-docs/", "medium", "API documentation"),
    ("/docs/", "info", "Documentation"),
    ("/.htaccess", "high", "Apache config exposed"),
    ("/.htpasswd", "critical", "Password file exposed"),
    ("/web.config", "high", "IIS config exposed"),
    ("/server-status", "high", "Apache server status"),
    ("/server-info", "high", "Apache server info"),
    ("/phpinfo.php", "high", "PHP info page"),
    ("/info.php", "high", "PHP info page"),
    ("/phpmyadmin/", "high", "phpMyAdmin exposed"),
    ("/adminer.php", "high", "Adminer DB tool"),
    ("/wp-config.php.bak", "critical", "WordPress config backup"),
    ("/backup/", "high", "Backup directory"),
    ("/backups/", "high", "Backup directory"),
    ("/dump.sql", "critical", "SQL dump exposed"),
    ("/database.sql", "critical", "SQL dump exposed"),
    ("/.DS_Store", "medium", "macOS metadata file"),
    ("/Thumbs.db", "low", "Windows metadata file"),
    ("/crossdomain.xml", "medium", "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "medium", "Silverlight policy"),
    ("/.well-known/security.txt", "info", "Security contact info"),
    ("/.well-known/openid-configuration", "info", "OpenID config"),
    ("/debug/", "high", "Debug endpoint"),
    ("/trace", "high", "Trace endpoint"),
    ("/elmah.axd", "high", "ELMAH error log"),
    ("/console/", "high", "Console endpoint"),
    ("/actuator/", "high", "Spring Boot actuator"),
    ("/actuator/health", "medium", "Spring health endpoint"),
    ("/actuator/env", "critical", "Spring env endpoint"),
    ("/metrics", "medium", "Metrics endpoint"),
    ("/health", "info", "Health check"),
    ("/status", "info", "Status page"),
    ("/.svn/", "high", "SVN repository exposed"),
    ("/.hg/", "high", "Mercurial repository exposed"),
    ("/config.json", "high", "Config file exposed"),
    ("/config.yml", "high", "Config file exposed"),
    ("/package.json", "medium", "Node.js package info"),
    ("/composer.json", "medium", "PHP composer info"),
    ("/Gemfile", "medium", "Ruby dependencies"),
    ("/requirements.txt", "medium", "Python dependencies"),
    ("/docker-compose.yml", "high", "Docker compose config"),
    ("/Dockerfile", "medium", "Dockerfile exposed"),
    ("/.dockerenv", "high", "Docker environment"),
    ("/terraform.tfstate", "critical", "Terraform state exposed"),
    ("/.aws/credentials", "critical", "AWS credentials exposed"),
    ("/id_rsa", "critical", "SSH private key exposed"),
    ("/id_ed25519", "critical", "SSH private key exposed"),
]


def scan_directories(target: str) -> DirectoryReport:
    report = DirectoryReport(target=target)

    base_url = f"https://{target}" if not target.startswith("http") else target

    session = requests.Session()
    session.headers.update({"User-Agent": "Wimsalabim/0.1 Security Scanner"})
    session.verify = False

    try:
        session.get(base_url, timeout=5)
    except requests.RequestException:
        base_url = f"http://{target}"
        try:
            session.get(base_url, timeout=5)
        except requests.RequestException:
            return report

    for path, risk, description in COMMON_PATHS:
        report.paths_checked += 1
        try:
            resp = session.get(
                base_url + path,
                timeout=5,
                allow_redirects=False,
            )

            if resp.status_code in (200, 301, 302, 403):
                found = FoundPath(
                    path=path,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    risk=risk,
                    description=description,
                )

                if resp.status_code in (301, 302):
                    found.redirect_url = resp.headers.get("Location", "")

                if resp.status_code == 200:
                    if path == "/robots.txt":
                        report.robots_txt = resp.text[:2000]
                        _parse_robots(resp.text, report)
                    elif path == "/sitemap.xml":
                        report.sitemap_found = True

                report.found_paths.append(found)

                if risk in ("high", "critical") and resp.status_code == 200:
                    report.sensitive_paths.append(found)
                    report.issues.append(
                        f"[{risk.upper()}] {description}: {path} (HTTP {resp.status_code})"
                    )

        except requests.RequestException:
            continue

    return report


def _parse_robots(content: str, report: DirectoryReport) -> None:
    for line in content.splitlines():
        line = line.strip().lower()
        if line.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                sensitive_keywords = [
                    "admin", "api", "private", "secret", "backup",
                    "config", "internal", "dashboard", "panel",
                ]
                if any(kw in path.lower() for kw in sensitive_keywords):
                    report.issues.append(
                        f"Robots.txt reveals sensitive path: {path}"
                    )
