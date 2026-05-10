# Changelog

All notable changes to `wimsalabim` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- **`wimsalabim watch` subcommand** — daemonized scan-loop. Periodically
  rescans one or more targets, persists snapshots in the `BaselineStore`,
  and reports drift (added/removed/changed findings) against the previous
  baseline. Flags: `--interval`, `--once`, `--diff-only`, `--db`, plus the
  full `scan` flag-set (analyzer selection, Tor, offline, authorization).
  Graceful shutdown via SIGINT/SIGTERM. Authorization is verified once per
  target at startup.

### Planned
- Mock TLS server fixture to lift `tls.py` coverage.
- Socket-mock fixture to lift `ports.py` coverage.
- Periodic re-verification of authorization for long-running `watch` sessions.

---

## [0.2.1] — 2026-05-10

Security-hardening release. No functional changes; addresses 56 alerts in
the GitHub Security tab from CodeQL and OpenSSF Scorecard against the
v0.2.0 baseline.

### Changed
- **All GitHub Actions pinned to commit SHAs** instead of mutable tags
  (`actions/checkout@<sha>` etc., with the original tag preserved as a
  trailing comment). Closes 28+ Scorecard `Pinned-Dependencies` findings.
  Dependabot is configured to keep them current via auto-PRs.
- **Restrictive default workflow permissions**: every workflow now declares
  a top-level `permissions: contents: read`, and each job adds only the
  additional scopes it actually needs (`id-token: write`,
  `security-events: write`, …). Closes 3 Scorecard `Token-Permissions`
  findings.
- **`SECURITY.md` enriched** with supported-versions, reporting channels,
  PGP-key placeholder, disclosure timeline, scope, hardening checklist,
  and build-provenance verification commands. Aligns with the Scorecard
  `Security-Policy` heuristic.

### Security
- 9 CodeQL alerts reviewed and dismissed with rationale:
  - 2× `py/incomplete-url-substring-sanitization` — test assertions, not
    URL sanitization.
  - 2× `py/unsafe-cyclic-import` — design choice; the cycle is
    `TYPE_CHECKING`-only, runtime acyclic.
  - 2× `py/unused-import` — intentional decorator-side-effect import
    (already `# noqa: F401`).
  - 1× `py/unused-global-variable` — global flag declared with `global`
    keyword and read in the same function.

---

## [0.2.0] — 2026-05-10

A complete refactor from v0.1. **Not backwards-compatible.** v0.1 users should
treat this as a new tool with the same name.

### Added
- **Authorization Gate** — `core/authorization.py`. Active analyzers refuse
  to run without verified proof (DNS-TXT, well-known, or self-owned manifest).
  Implements NL Sr 138ab compliance in code.
- **Provenance Engine** — every `Finding` carries a `Source` block with kind,
  target, timestamp, and optional body-SHA-256.
- **Crypto-signed reports** — Ed25519 signature over RFC-8785 canonical JSON.
  `wimsalabim sign` and `wimsalabim verify` round-trip with tamper detection.
- **OpenTimestamps integration** — optional `.ots` proof anchored on Bitcoin
  via the upstream `ots` CLI.
- **Plugin architecture** — `@analyzer(name=…, legal_class=…, capabilities=…)`
  decorator + `Capabilities` declaration.
- **SARIF 2.1.0 export** — for GitHub Code Scanning, GitLab, Defect Dojo.
- **Markdown export** — GitHub-flavored, suitable for PR comments.
- **Watchlist baseline** — `wimsalabim.watch.baseline.BaselineStore` with
  SQLite snapshots and `Diff` detection (CLI subcommand pending).
- **Privacy guards** — telemetry blacklist enforced at the HTTP-client layer.
  WHOIS-PII redacted by default.
- **Strict typing** — `mypy --strict` clean across 30 source files.
- **Strict linting** — `ruff` with 40+ rule sets including `ASYNC`, `TRY`,
  `PTH`, `PL`. Zero violations.
- **Test suite** — 118 tests, 76% coverage, including a `test_no_telemetry.py`
  that statically forbids known telemetry SDKs.
- **Pentest report** — `docs/PENTEST_REPORT.md` documents the audit.
- **PVNL branding** — under the Privacy Verzet NL flag.

### Changed
- License from **MIT** → **AGPL-3.0-or-later**. Network-use disclosure clause
  matters for a tool that operators may run as a service.
- Minimum Python from **3.9** → **3.10**. We use `match`, PEP 604 unions,
  and `tuple[int, ...]` annotations natively.
- Schema versioning: reports now declare `schema_version: "wimsalabim/2.0"`.

### Removed
- All `sklearn` "ML modules" — they were sklearn classes imported but never
  trained. Replaced by transparent `HeuristicRiskEngine` with rule-based,
  CWE-mapped, explainable scoring.
- `requests` dependency. Replaced by `httpx` (async, HTTP/2-capable).
- `--no-ml` flag (no longer relevant).

### Security
- Bandit clean (0 high, 0 medium, 5 low — all subprocess in OTS, acceptable).
- pip-audit clean (no known vulnerabilities in deps).

---

## [0.1.0] — earlier

The original release. Marked as **historical**; please upgrade to 0.2.0.

Audit found:
- 656-line `main()` with in-function imports.
- `except Exception:` swallowing failures silently.
- Tests asserting hardcoded values, not behavior.
- "ML" modules with `IsolationForest`/`DecisionTree` classes but no training,
  hardcoded `training_samples=500` in test data.

Score: **3.7 / 10**. See [`docs/PENTEST_REPORT.md`](docs/PENTEST_REPORT.md) §8.

---

[Unreleased]: https://github.com/WimLee115/wimsalabim/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/WimLee115/wimsalabim/releases/tag/v0.2.0
[0.1.0]: https://github.com/WimLee115/wimsalabim/releases/tag/v0.1.0
