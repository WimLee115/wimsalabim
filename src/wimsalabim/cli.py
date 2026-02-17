"""Wimsalabim CLI - Instant beautiful security reconnaissance. rootmap:WimLee115"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import warnings

import click
from rich.console import Console

from wimsalabim import __version__
from wimsalabim import display

console = Console()
warnings.filterwarnings("ignore")


@click.command()
@click.argument("target")
@click.option("--json-output", "-j", is_flag=True, help="Output results as JSON")
@click.option("--no-ports", is_flag=True, help="Skip port scanning")
@click.option("--no-tls", is_flag=True, help="Skip TLS analysis")
@click.option("--no-headers", is_flag=True, help="Skip HTTP headers check")
@click.option("--no-dns", is_flag=True, help="Skip DNS reconnaissance")
@click.option("--no-email", is_flag=True, help="Skip email security check")
@click.option("--no-tech", is_flag=True, help="Skip technology fingerprinting")
@click.option("--no-whois", is_flag=True, help="Skip WHOIS lookup")
@click.option("--no-subdomains", is_flag=True, help="Skip subdomain discovery")
@click.option("--no-waf", is_flag=True, help="Skip WAF detection")
@click.option("--no-dirs", is_flag=True, help="Skip directory scanning")
@click.option("--no-cors", is_flag=True, help="Skip CORS analysis")
@click.option("--no-cookies", is_flag=True, help="Skip cookie analysis")
@click.option("--no-cloud", is_flag=True, help="Skip cloud detection")
@click.option("--no-cve", is_flag=True, help="Skip CVE lookup")
@click.option("--no-ml", is_flag=True, help="Skip ML/AI analysis")
@click.option("--no-network", is_flag=True, help="Skip network quality analysis")
@click.option("--no-leaks", is_flag=True, help="Skip leak detection")
@click.option("--no-perf", is_flag=True, help="Skip performance analysis")
@click.option("--no-sectxt", is_flag=True, help="Skip security.txt check")
@click.option("--no-js", is_flag=True, help="Skip JavaScript analysis")
@click.option("--no-takeover", is_flag=True, help="Skip subdomain takeover check")
@click.option("--no-graphql", is_flag=True, help="Skip GraphQL analysis")
@click.option("--no-http2", is_flag=True, help="Skip HTTP/2 & HTTP/3 detection")
@click.option("--no-sitemap", is_flag=True, help="Skip sitemap/robots analysis")
@click.option("--ports", "-p", default=None, help="Custom port list (comma-separated)")
@click.option("--timeout", "-t", default=1.5, help="Port scan timeout in seconds")
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.option("--quick", "-q", is_flag=True, help="Quick scan (ports + TLS + headers only)")
def main(
    target: str,
    json_output: bool,
    no_ports: bool,
    no_tls: bool,
    no_headers: bool,
    no_dns: bool,
    no_email: bool,
    no_tech: bool,
    no_whois: bool,
    no_subdomains: bool,
    no_waf: bool,
    no_dirs: bool,
    no_cors: bool,
    no_cookies: bool,
    no_cloud: bool,
    no_cve: bool,
    no_ml: bool,
    no_network: bool,
    no_leaks: bool,
    no_perf: bool,
    no_sectxt: bool,
    no_js: bool,
    no_takeover: bool,
    no_graphql: bool,
    no_http2: bool,
    no_sitemap: bool,
    ports: str | None,
    timeout: float,
    version: bool,
    quick: bool,
) -> None:
    """Wimsalabim - Instant beautiful security reconnaissance.

    TARGET is the domain or IP address to scan.
    """
    if version:
        console.print(f"wimsalabim v{__version__}")
        sys.exit(0)

    target = target.strip().lower()
    if target.startswith("http://"):
        target = target[7:]
    if target.startswith("https://"):
        target = target[8:]
    target = target.rstrip("/")

    if quick:
        no_dns = no_email = no_whois = no_subdomains = True
        no_waf = no_dirs = no_cors = no_cookies = no_cloud = no_cve = True
        no_network = no_leaks = no_perf = True
        no_sectxt = no_js = no_takeover = no_graphql = no_http2 = no_sitemap = True

    start_time = time.monotonic()
    results = {}

    if not json_output:
        display.print_banner(target)

    custom_ports = None
    if ports:
        custom_ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]

    with console.status("[bold cyan]Scanning...[/bold cyan]", spinner="dots") if not json_output else _noop_context():

        # Port Scan
        if not no_ports:
            _status("Port scanning", json_output)
            from wimsalabim.analyzers.ports import scan_ports
            port_report = asyncio.run(scan_ports(target, ports=custom_ports, timeout=timeout))
            results["ports"] = port_report
        else:
            port_report = None

        # TLS Analysis
        if not no_tls:
            _status("TLS/SSL analysis", json_output)
            from wimsalabim.analyzers.tls import analyze_tls
            tls_report = analyze_tls(target)
            results["tls"] = tls_report
        else:
            tls_report = None

        # HTTP Headers
        if not no_headers:
            _status("HTTP headers check", json_output)
            from wimsalabim.analyzers.headers import analyze_headers
            headers_report = analyze_headers(target)
            results["headers"] = headers_report
        else:
            headers_report = None

        # DNS Recon
        if not no_dns:
            _status("DNS reconnaissance", json_output)
            from wimsalabim.analyzers.dns_recon import analyze_dns
            dns_report = analyze_dns(target)
            results["dns"] = dns_report
        else:
            dns_report = None

        # Email Security
        if not no_email:
            _status("Email security check", json_output)
            from wimsalabim.analyzers.email_sec import analyze_email_security
            email_report = analyze_email_security(target)
            results["email"] = email_report
        else:
            email_report = None

        # Technology Fingerprinting
        if not no_tech:
            _status("Technology fingerprinting", json_output)
            from wimsalabim.analyzers.tech import analyze_tech
            tech_report = analyze_tech(target)
            results["tech"] = tech_report
        else:
            tech_report = None

        # WHOIS
        if not no_whois:
            _status("WHOIS lookup", json_output)
            from wimsalabim.analyzers.whois_lookup import analyze_whois
            whois_report = analyze_whois(target)
            results["whois"] = whois_report
        else:
            whois_report = None

        # Subdomain Discovery
        if not no_subdomains:
            _status("Subdomain discovery", json_output)
            from wimsalabim.analyzers.subdomains import discover_subdomains
            subdomain_report = discover_subdomains(target, check_http=False)
            results["subdomains"] = subdomain_report
        else:
            subdomain_report = None

        # WAF Detection
        if not no_waf:
            _status("WAF detection", json_output)
            from wimsalabim.analyzers.waf import detect_waf
            waf_report = detect_waf(target)
            results["waf"] = waf_report
        else:
            waf_report = None

        # Directory Scan
        if not no_dirs:
            _status("Directory scanning", json_output)
            from wimsalabim.analyzers.directories import scan_directories
            dir_report = scan_directories(target)
            results["directories"] = dir_report
        else:
            dir_report = None

        # CORS Analysis
        if not no_cors:
            _status("CORS analysis", json_output)
            from wimsalabim.analyzers.cors import analyze_cors
            cors_report = analyze_cors(target)
            results["cors"] = cors_report
        else:
            cors_report = None

        # Cookie Analysis
        if not no_cookies:
            _status("Cookie analysis", json_output)
            from wimsalabim.analyzers.cookies import analyze_cookies
            cookie_report = analyze_cookies(target)
            results["cookies"] = cookie_report
        else:
            cookie_report = None

        # Cloud Detection
        if not no_cloud:
            _status("Cloud detection", json_output)
            from wimsalabim.analyzers.cloud import analyze_cloud
            cloud_report = analyze_cloud(target)
            results["cloud"] = cloud_report
        else:
            cloud_report = None

        # CVE Lookup
        cve_report = None
        if not no_cve and tech_report and tech_report.technologies:
            _status("CVE lookup", json_output)
            from wimsalabim.analyzers.cve_lookup import lookup_cves
            products = [
                (t.name, t.version) for t in tech_report.technologies if t.version
            ]
            if not products:
                products = [(t.name, "") for t in tech_report.technologies[:5]]
            cve_report = lookup_cves(products, target=target)
            results["cve"] = cve_report

        # Network Analysis
        network_report = None
        if not no_network:
            _status("Network quality analysis", json_output)
            from wimsalabim.analyzers.network import analyze_network
            network_report = analyze_network(target, samples=10)
            results["network"] = network_report

        # Leak Detection
        leak_report = None
        if not no_leaks:
            _status("Leak detection & firewall audit", json_output)
            from wimsalabim.analyzers.leak_detector import detect_leaks
            leak_report = detect_leaks(
                target,
                open_ports=[p.port for p in port_report.open_ports] if port_report else [],
            )
            results["leaks"] = leak_report

        # Performance Analysis
        perf_report = None
        if not no_perf:
            _status("Performance analysis", json_output)
            from wimsalabim.analyzers.performance import analyze_performance
            perf_report = analyze_performance(target)
            results["performance"] = perf_report

        # Security.txt
        sectxt_report = None
        if not no_sectxt:
            _status("Security.txt check", json_output)
            from wimsalabim.analyzers.security_txt import analyze_security_txt
            sectxt_report = analyze_security_txt(target)
            results["security_txt"] = sectxt_report

        # JavaScript Analysis
        js_report = None
        if not no_js:
            _status("JavaScript secrets scan", json_output)
            from wimsalabim.analyzers.js_analyzer import analyze_js
            js_report = analyze_js(target)
            results["js_analysis"] = js_report

        # Subdomain Takeover
        takeover_report = None
        if not no_takeover:
            _status("Subdomain takeover check", json_output)
            from wimsalabim.analyzers.subdomain_takeover import check_subdomain_takeover
            takeover_subs = [s.hostname for s in subdomain_report.subdomains_found] if subdomain_report else None
            takeover_report = check_subdomain_takeover(target, subdomains=takeover_subs)
            results["subdomain_takeover"] = takeover_report

        # GraphQL Analysis
        graphql_report = None
        if not no_graphql:
            _status("GraphQL security check", json_output)
            from wimsalabim.analyzers.graphql import analyze_graphql
            graphql_report = analyze_graphql(target)
            results["graphql"] = graphql_report

        # HTTP/2 & HTTP/3 Protocol Detection
        http2_report = None
        if not no_http2:
            _status("Protocol detection (HTTP/2, HTTP/3)", json_output)
            from wimsalabim.analyzers.http2 import analyze_protocols
            http2_report = analyze_protocols(target)
            results["protocols"] = http2_report

        # Sitemap & Robots Analysis
        sitemap_report = None
        if not no_sitemap:
            _status("Sitemap & robots.txt analysis", json_output)
            from wimsalabim.analyzers.sitemap import analyze_sitemap
            sitemap_report = analyze_sitemap(target)
            results["sitemap"] = sitemap_report

        # ML/AI Analysis
        anomaly_report = None
        threat_report = None
        risk_assessment = None
        traffic_report = None

        if not no_ml:
            _status("ML anomaly detection", json_output)
            from wimsalabim.ml.anomaly import detect_anomalies
            anomaly_report = detect_anomalies(
                open_ports=[p.port for p in port_report.open_ports] if port_report else [],
                tls_score=_grade_to_float(tls_report.grade if tls_report else "N/A"),
                headers_score=_grade_to_float(headers_report.grade if headers_report else "N/A"),
                dns_record_count=dns_report.total_records if dns_report else 0,
                subdomain_count=subdomain_report.found_count if subdomain_report else 0,
                tech_count=tech_report.tech_count if tech_report else 0,
                cookie_count=cookie_report.total_cookies if cookie_report else 0,
                info_leak_count=len(headers_report.info_leaks) if headers_report else 0,
                days_until_cert_expiry=tls_report.days_until_expiry if tls_report else 365,
                domain_age_days=whois_report.domain_age_days if whois_report else 365,
            )
            results["anomalies"] = anomaly_report

            _status("AI threat classification", json_output)
            from wimsalabim.ml.threat_classifier import classify_threats
            threat_report = classify_threats(
                open_ports=[p.port for p in port_report.open_ports] if port_report else [],
                risky_ports=len(port_report.risky_ports) if port_report else 0,
                tls_grade=tls_report.grade if tls_report else "N/A",
                headers_grade=headers_report.grade if headers_report else "N/A",
                headers_missing=headers_report.missing_count if headers_report else 0,
                info_leaks=len(headers_report.info_leaks) if headers_report else 0,
                dns_issues=dns_report.issues if dns_report else [],
                email_grade=email_report.grade if email_report else "N/A",
                cors_grade=cors_report.grade if cors_report else "N/A",
                cors_reflects=cors_report.reflects_origin if cors_report else False,
                cookie_issues=len(cookie_report.issues) if cookie_report else 0,
                waf_detected=waf_report.detected if waf_report else False,
                cloud_issues=cloud_report.issues if cloud_report else [],
                sensitive_subdomains=len(subdomain_report.issues) if subdomain_report else 0,
                sensitive_paths=dir_report.sensitive_count if dir_report else 0,
                cve_critical=cve_report.critical_count if cve_report else 0,
                cve_high=cve_report.high_count if cve_report else 0,
            )
            results["threats"] = threat_report

            _status("AI risk assessment", json_output)
            from wimsalabim.ml.risk_engine import assess_risk
            risk_assessment = assess_risk(
                port_count=port_report.open_count if port_report else 0,
                risky_ports=len(port_report.risky_ports) if port_report else 0,
                tls_grade=tls_report.grade if tls_report else "N/A",
                tls_issues=tls_report.issues if tls_report else [],
                headers_grade=headers_report.grade if headers_report else "N/A",
                headers_missing=headers_report.missing_count if headers_report else 0,
                info_leaks=len(headers_report.info_leaks) if headers_report else 0,
                dns_issues=(dns_report.issues if dns_report else []),
                email_grade=email_report.grade if email_report else "N/A",
                cors_grade=cors_report.grade if cors_report else "N/A",
                cors_reflects=cors_report.reflects_origin if cors_report else False,
                cookie_issues=len(cookie_report.issues) if cookie_report else 0,
                waf_detected=waf_report.detected if waf_report else False,
                cloud_issues=cloud_report.issues if cloud_report else [],
                subdomain_count=subdomain_report.found_count if subdomain_report else 0,
                sensitive_subdomains=len(subdomain_report.issues) if subdomain_report else 0,
                sensitive_paths=dir_report.sensitive_count if dir_report else 0,
                cve_critical=cve_report.critical_count if cve_report else 0,
                cve_high=cve_report.high_count if cve_report else 0,
                cve_total=cve_report.total_cves if cve_report else 0,
                cert_days_left=tls_report.days_until_expiry if tls_report else 365,
                domain_age_days=whois_report.domain_age_days if whois_report else 365,
                anomaly_score=anomaly_report.anomaly_score if anomaly_report else 0,
                attack_surface=threat_report.attack_surface_score if threat_report else 0,
            )
            results["risk_assessment"] = risk_assessment

            _status("AI traffic pattern analysis", json_output)
            from wimsalabim.ml.traffic_analyzer import analyze_traffic_patterns
            traffic_report = analyze_traffic_patterns(
                open_ports=[p.port for p in port_report.open_ports] if port_report else [],
                latency_samples=network_report.latency.samples if network_report else [],
                jitter_ms=network_report.latency.jitter_ms if network_report else 0,
                packet_loss_pct=network_report.latency.packet_loss_pct if network_report else 0,
                tls_handshake_ms=perf_report.encryption.tls_handshake_ms if perf_report else 0,
                bandwidth_mbps=network_report.bandwidth.download_estimate_mbps if network_report else 0,
                tech_count=tech_report.tech_count if tech_report else 0,
                cookie_count=cookie_report.total_cookies if cookie_report else 0,
                header_count=headers_report.present_count if headers_report else 0,
                subdomain_count=subdomain_report.found_count if subdomain_report else 0,
                cve_count=cve_report.total_cves if cve_report else 0,
                waf_detected=waf_report.detected if waf_report else False,
            )
            results["traffic"] = traffic_report

            _status("ML vulnerability prediction", json_output)
            from wimsalabim.ml.vulnerability_predictor import predict_vulnerabilities
            vuln_report = predict_vulnerabilities(
                port_count=port_report.open_count if port_report else 0,
                risky_ports=len(port_report.risky_ports) if port_report else 0,
                tls_score=_grade_to_float(tls_report.grade if tls_report else "N/A"),
                headers_score=_grade_to_float(headers_report.grade if headers_report else "N/A"),
                headers_missing=headers_report.missing_count if headers_report else 0,
                info_leaks=len(headers_report.info_leaks) if headers_report else 0,
                has_csp=any(h.name == "Content-Security-Policy" for h in headers_report.headers_present) if headers_report else False,
                cors_reflects=cors_report.reflects_origin if cors_report else False,
                cookie_issues=len(cookie_report.issues) if cookie_report else 0,
                waf_detected=waf_report.detected if waf_report else False,
                subdomain_count=subdomain_report.found_count if subdomain_report else 0,
                sensitive_paths=dir_report.sensitive_count if dir_report else 0,
                cve_count=cve_report.total_cves if cve_report else 0,
                cloud_hosted=cloud_report.is_cloud_hosted if cloud_report else False,
                tech_count=tech_report.tech_count if tech_report else 0,
                has_graphql=graphql_report.available if graphql_report else False,
                js_secrets=js_report.secret_count if js_report else 0,
            )
            results["vulnerability_prediction"] = vuln_report
        else:
            vuln_report = None

        # Scoring
        _status("Calculating scores", json_output)
        from wimsalabim.analyzers.scoring import calculate_scores
        scoring_report = calculate_scores(
            tls_grade=tls_report.grade if tls_report else "N/A",
            tls_issues=tls_report.issues if tls_report else [],
            headers_grade=headers_report.grade if headers_report else "N/A",
            headers_issues=[f"Missing: {h.name}" for h in headers_report.headers_missing] if headers_report else [],
            dns_issues=dns_report.issues if dns_report else [],
            email_grade=email_report.grade if email_report else "N/A",
            email_issues=email_report.issues if email_report else [],
            ports_open=port_report.open_count if port_report else 0,
            ports_risky=len(port_report.risky_ports) if port_report else 0,
            cors_issues=cors_report.issues if cors_report else [],
            cookie_issues=cookie_report.issues if cookie_report else [],
            waf_detected=waf_report.detected if waf_report else False,
            cloud_issues=cloud_report.issues if cloud_report else [],
            ml_risk_score=risk_assessment.overall_risk if risk_assessment else 0.0,
        )
        results["scoring"] = scoring_report

    elapsed = time.monotonic() - start_time

    if json_output:
        _output_json(results, elapsed)
    else:
        _output_rich(
            results, elapsed,
            port_report, tls_report, headers_report, dns_report,
            email_report, tech_report, whois_report, subdomain_report,
            waf_report, dir_report, cors_report, cookie_report,
            cloud_report, cve_report, network_report, leak_report,
            perf_report, sectxt_report, js_report, takeover_report,
            graphql_report, http2_report, sitemap_report,
            anomaly_report, threat_report,
            traffic_report, vuln_report, risk_assessment, scoring_report,
        )


def _output_rich(
    results, elapsed,
    port_report, tls_report, headers_report, dns_report,
    email_report, tech_report, whois_report, subdomain_report,
    waf_report, dir_report, cors_report, cookie_report,
    cloud_report, cve_report, network_report, leak_report,
    perf_report, sectxt_report, js_report, takeover_report,
    graphql_report, http2_report, sitemap_report,
    anomaly_report, threat_report,
    traffic_report, vuln_report, risk_assessment, scoring_report,
):
    console.print()

    if port_report:
        display.print_ports(port_report)
    if tls_report:
        display.print_tls(tls_report)
    if headers_report:
        display.print_headers(headers_report)
    if dns_report:
        display.print_dns(dns_report)
    if email_report:
        display.print_email(email_report)
    if tech_report:
        display.print_tech(tech_report)
    if whois_report:
        display.print_whois(whois_report)
    if subdomain_report:
        display.print_subdomains(subdomain_report)
    if waf_report:
        display.print_waf(waf_report)
    if dir_report:
        display.print_directories(dir_report)
    if cors_report:
        display.print_cors(cors_report)
    if cookie_report:
        display.print_cookies(cookie_report)
    if cloud_report:
        display.print_cloud(cloud_report)
    if cve_report:
        display.print_cve(cve_report)
    if network_report:
        display.print_network(network_report)
    if leak_report:
        display.print_leaks(leak_report)
    if perf_report:
        display.print_performance(perf_report)
    if sectxt_report:
        display.print_security_txt(sectxt_report)
    if js_report:
        display.print_js_analysis(js_report)
    if takeover_report:
        display.print_subdomain_takeover(takeover_report)
    if graphql_report:
        display.print_graphql(graphql_report)
    if http2_report:
        display.print_protocols(http2_report)
    if sitemap_report:
        display.print_sitemap(sitemap_report)
    if anomaly_report:
        display.print_anomalies(anomaly_report)
    if threat_report:
        display.print_threats(threat_report)
    if traffic_report:
        display.print_traffic_analysis(traffic_report)
    if vuln_report:
        display.print_vulnerability_predictions(vuln_report)
    if risk_assessment:
        display.print_risk_assessment(risk_assessment)

    display.print_scoring(scoring_report)
    display.print_footer(elapsed)


def _output_json(results: dict, elapsed: float) -> None:
    import dataclasses

    def _serialize(obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        if isinstance(obj, set):
            return list(obj)
        return str(obj)

    output = {
        "version": __version__,
        "watermark": "rootmap:WimLee115",
        "scan_time": round(elapsed, 2),
        "results": {},
    }

    for key, report in results.items():
        try:
            output["results"][key] = _serialize(report)
        except Exception:
            output["results"][key] = str(report)

    print(json.dumps(output, indent=2, default=str))


def _grade_to_float(grade: str) -> float:
    return {"A": 0.95, "B": 0.8, "C": 0.6, "D": 0.4, "F": 0.15, "N/A": 0.5}.get(grade, 0.5)


def _status(msg: str, json_output: bool) -> None:
    if not json_output:
        console.log(f"[dim]{msg}...[/dim]")


class _noop_context:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


if __name__ == "__main__":
    main()
