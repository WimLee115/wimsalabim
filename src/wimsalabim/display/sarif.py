"""SARIF 2.1.0 export.

Only the subset needed to be ingested by GitHub Code Scanning, GitLab
Security Dashboard, and Defect Dojo. We do not pretend to implement the
full SARIF specification — we implement the practical interop slice.
"""

from __future__ import annotations

from typing import Any

from wimsalabim import __version__
from wimsalabim.core.schema import Finding, ScanReport, Severity

_SEV_TO_LEVEL: dict[Severity, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(report: ScanReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for analyzer_name, result in sorted(report.analyzers.items()):
        rep = result.report
        if rep is None:
            continue
        for finding in rep.findings:
            rule_id = finding.id
            if rule_id not in rules:
                rules[rule_id] = _rule_for(finding)
            results.append(_result_for(finding, rule_id, analyzer_name, report.target))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wimsalabim",
                        "version": __version__,
                        "informationUri": "https://github.com/WimLee115/wimsalabim",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "tool_version": report.tool_version,
                    "config_hash": report.config_hash,
                    "schema": report.schema_version,
                    "started_at": report.started_at.isoformat(),
                    "signature": report.signature,
                    "signing_pubkey": report.signing_pubkey,
                },
            }
        ],
    }


def _rule_for(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _SEV_TO_LEVEL[finding.severity]},
        "properties": {"severity": finding.severity},
    }
    if finding.cwe:
        rule["properties"]["cwe"] = finding.cwe
        rule["properties"]["tags"] = [finding.cwe]
    if finding.references:
        rule["helpUri"] = finding.references[0]
    if finding.remediation:
        rule["help"] = {"text": finding.remediation}
    return rule


def _result_for(
    finding: Finding,
    rule_id: str,
    analyzer_name: str,
    target: str,
) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": _SEV_TO_LEVEL[finding.severity],
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"https://{target}"},
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [
                    {"name": analyzer_name, "kind": "module"},
                ],
            }
        ],
        "properties": {
            "analyzer": analyzer_name,
            "severity": finding.severity,
            "source_kind": finding.source.kind,
            "source_timestamp": finding.source.timestamp.isoformat(),
            "cwe": finding.cwe,
            "cvss_score": finding.cvss_score,
        },
    }


__all__ = ["render_sarif"]
