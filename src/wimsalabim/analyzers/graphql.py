"""GraphQL introspection and security analysis. rootmap:WimLee115"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import requests


@dataclass
class GraphQLType:
    name: str
    kind: str
    field_count: int = 0


@dataclass
class GraphQLReport:
    target: str
    available: bool = False
    endpoint: str = ""
    introspection_enabled: bool = False
    types_exposed: list[GraphQLType] = field(default_factory=list)
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    debug_mode: bool = False
    suggestions_enabled: bool = False
    batch_queries_allowed: bool = False
    field_suggestions: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"

    @property
    def type_count(self) -> int:
        return len(self.types_exposed)

    @property
    def user_types(self) -> list[GraphQLType]:
        return [t for t in self.types_exposed if not t.name.startswith("__")]


COMMON_ENDPOINTS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

FIELD_SUGGESTION_QUERY = '{ __nonexistent_field_xyz }'


def analyze_graphql(target: str) -> GraphQLReport:
    report = GraphQLReport(target=target)

    endpoint = _find_endpoint(target, report)
    if not endpoint:
        return report

    report.available = True
    report.endpoint = endpoint

    _check_introspection(endpoint, report)
    _check_field_suggestions(endpoint, report)
    _check_batch_queries(endpoint, report)
    _check_debug_mode(endpoint, report)
    _calculate_grade(report)

    return report


def _find_endpoint(target: str, report: GraphQLReport) -> str:
    for path in COMMON_ENDPOINTS:
        url = f"https://{target}{path}"
        try:
            resp = requests.post(
                url, timeout=8, verify=False,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Wimsalabim/0.1 Security Scanner",
                },
                json={"query": "{ __typename }"},
            )

            if resp.status_code in (200, 400) and _is_graphql_response(resp.text):
                return url

        except requests.RequestException:
            continue

    for path in COMMON_ENDPOINTS[:3]:
        url = f"http://{target}{path}"
        try:
            resp = requests.post(
                url, timeout=5, verify=False,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Wimsalabim/0.1 Security Scanner",
                },
                json={"query": "{ __typename }"},
            )

            if resp.status_code in (200, 400) and _is_graphql_response(resp.text):
                return url

        except requests.RequestException:
            continue

    return ""


def _is_graphql_response(text: str) -> bool:
    try:
        data = json.loads(text)
        return "data" in data or "errors" in data
    except (json.JSONDecodeError, TypeError):
        return False


def _check_introspection(endpoint: str, report: GraphQLReport) -> None:
    try:
        resp = requests.post(
            endpoint, timeout=10, verify=False,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Wimsalabim/0.1 Security Scanner",
            },
            json={"query": INTROSPECTION_QUERY},
        )

        if resp.status_code != 200:
            return

        data = resp.json()

        if "data" not in data or "__schema" not in (data.get("data") or {}):
            return

        report.introspection_enabled = True
        report.issues.append("GraphQL introspection is enabled (exposes full schema)")

        schema = data["data"]["__schema"]

        if schema.get("queryType"):
            report.query_type = schema["queryType"].get("name", "")
        if schema.get("mutationType"):
            report.mutation_type = schema["mutationType"].get("name", "")
        if schema.get("subscriptionType"):
            report.subscription_type = schema["subscriptionType"].get("name", "")

        for t in schema.get("types", []):
            field_count = len(t.get("fields") or [])
            report.types_exposed.append(GraphQLType(
                name=t["name"],
                kind=t["kind"],
                field_count=field_count,
            ))

        user_types = report.user_types
        if len(user_types) > 20:
            report.issues.append(f"Large schema exposed: {len(user_types)} custom types visible")

        sensitive_names = {"user", "admin", "auth", "password", "token", "secret",
                           "credential", "payment", "billing", "internal"}
        for t in user_types:
            if any(s in t.name.lower() for s in sensitive_names):
                report.issues.append(f"Sensitive type exposed: {t.name}")

    except (requests.RequestException, json.JSONDecodeError, KeyError):
        pass


def _check_field_suggestions(endpoint: str, report: GraphQLReport) -> None:
    try:
        resp = requests.post(
            endpoint, timeout=8, verify=False,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Wimsalabim/0.1 Security Scanner",
            },
            json={"query": FIELD_SUGGESTION_QUERY},
        )

        data = resp.json()
        errors = data.get("errors", [])

        for error in errors:
            msg = error.get("message", "")
            if "did you mean" in msg.lower():
                report.suggestions_enabled = True
                report.field_suggestions.append(msg)
                report.issues.append("Field suggestions enabled (information disclosure)")
                break

    except (requests.RequestException, json.JSONDecodeError):
        pass


def _check_batch_queries(endpoint: str, report: GraphQLReport) -> None:
    try:
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        resp = requests.post(
            endpoint, timeout=8, verify=False,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Wimsalabim/0.1 Security Scanner",
            },
            json=batch,
        )

        data = resp.json()
        if isinstance(data, list) and len(data) == 2:
            report.batch_queries_allowed = True
            report.issues.append("Batch queries allowed (DoS risk via query batching)")

    except (requests.RequestException, json.JSONDecodeError):
        pass


def _check_debug_mode(endpoint: str, report: GraphQLReport) -> None:
    try:
        resp = requests.post(
            endpoint, timeout=8, verify=False,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Wimsalabim/0.1 Security Scanner",
            },
            json={"query": "{ __nonexistent }"},
        )

        data = resp.json()
        errors = data.get("errors", [])

        for error in errors:
            extensions = error.get("extensions", {})
            if extensions.get("exception") or extensions.get("stacktrace"):
                report.debug_mode = True
                report.issues.append("GraphQL debug mode enabled (stack traces exposed)")
                break

            if "stack" in str(error).lower() or "traceback" in str(error).lower():
                report.debug_mode = True
                report.issues.append("GraphQL debug information leaked in errors")
                break

    except (requests.RequestException, json.JSONDecodeError):
        pass


def _calculate_grade(report: GraphQLReport) -> None:
    if not report.available:
        report.grade = "N/A"
        return

    score = 100

    if report.introspection_enabled:
        score -= 30
    if report.debug_mode:
        score -= 20
    if report.suggestions_enabled:
        score -= 10
    if report.batch_queries_allowed:
        score -= 15

    sensitive_types = sum(1 for i in report.issues if "Sensitive type" in i)
    score -= sensitive_types * 5

    if score >= 90:
        report.grade = "A"
    elif score >= 75:
        report.grade = "B"
    elif score >= 60:
        report.grade = "C"
    elif score >= 40:
        report.grade = "D"
    else:
        report.grade = "F"
