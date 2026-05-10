# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x: (use 0.2+)     |

## Reporting a vulnerability

> **Do not open a public GitHub issue for security vulnerabilities.**

Please report privately via one of these channels:

- **GitHub private vulnerability reporting**:
  <https://github.com/WimLee115/wimsalabim/security/advisories/new>
- **Email**: `security@wimlee115.invalid` *(replace with real address before publication; PGP key listed below)*
- **Anonymous channel**: via the alias-relay on `bewindklacht.nl`

Encrypted reports are strongly preferred. We will:

- **Acknowledge** receipt within **72 hours**.
- **Triage** and confirm or refute the issue within **7 days**.
- **Provide a fix or mitigation timeline** within **30 days**.

## PGP key

```
TBD: replace with real fingerprint and link before publication.
Example:
    Fingerprint: 1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678
    Public key : https://github.com/WimLee115.gpg
```

## Disclosure policy

We follow industry-standard **coordinated disclosure** with a **90-day window**:

1. We acknowledge your report within 72 hours.
2. We confirm or refute the issue within 7 days.
3. We work on a fix and coordinate a release date.
4. We credit you in the release notes (anonymous on request).
5. After **90 days**, or after a fix is shipped — whichever is sooner — the
   issue may be disclosed publicly.

If active in-the-wild exploitation is confirmed, we may compress the timeline.

## Scope

**In scope:**

- The `wimsalabim` CLI and Python library (this repository).
- The cryptographic-integrity flow (`sign`, `verify`, canonical JSON, key handling).
- The `AuthorizationGate` enforcement.
- The HTTP client privacy hooks and telemetry blacklist.
- Build/release pipeline (`.github/workflows/release.yml`) — supply-chain integrity.

**Out of scope:**

- Third-party dependencies — please report upstream; we will follow with a bump.
- The OpenTimestamps subprocess — report to OTS upstream.
- Issues in the *output* of the tool (i.e. vulnerabilities the tool *finds* on
  third-party targets) — those are findings, not tool defects.
- Documentation typos — open a regular PR.

## Hardening checklist for operators

If you operate `wimsalabim` in CI / production / shared infrastructure:

```
   ┌──────────────────────────────────────────────────────────────┐
   │                                                              │
   │   [ ]  Run as a non-root user                                │
   │   [ ]  Pin dependencies via lockfile (`pip-compile`)         │
   │   [ ]  Store signing keys outside the repo (mode 0600)       │
   │   [ ]  Rotate signing keys yearly                            │
   │   [ ]  Restrict outbound traffic to expected destinations    │
   │   [ ]  Enable `--via-tor` if metadata-protection matters     │
   │   [ ]  Verify report signatures on the receiving side        │
   │   [ ]  Anchor important reports with OpenTimestamps          │
   │   [ ]  Treat `~/.wimsalabim/` as sensitive (it holds keys)   │
   │                                                              │
   └──────────────────────────────────────────────────────────────┘
```

## Known not-bugs

The following are **not** security bugs:

- `bandit` LOW warnings on `subprocess.run(["ots", ...])` — args are list-form,
  no shell, paths are operator-controlled. Suppressed with `# nosec` comments
  with rationale (see `src/wimsalabim/core/timestamps.py`).
- `denied` status for active analyzers without authorization — that is the gate
  doing its job (NL Sr 138ab compliance).
- Refusal to connect to telemetry-blacklist hosts — that is the privacy guard
  doing its job. See `src/wimsalabim/core/privacy.py`.
- Signed reports tagged "Unverified" on GitHub — that means the **author's**
  GPG/SSH key isn't registered with GitHub as a signing key. The signature
  itself is still cryptographically valid; verify with `wimsalabim verify`.

## Security tooling we run

| Tool         | When                                | Surface                            |
| ------------ | ----------------------------------- | ---------------------------------- |
| `bandit`     | pre-commit + CI + release           | Python static security analysis    |
| `pip-audit`  | pre-commit + CI + release           | Dependency vulnerability scan      |
| `mypy --strict` | pre-commit + CI                  | Type safety                        |
| `ruff` (40+ rule sets) | pre-commit + CI            | Lint + style + bug-class detection |
| CodeQL       | per-PR + weekly                     | Semantic code analysis             |
| OpenSSF Scorecard | weekly                         | Project-health metrics             |
| Manual review | every PR by maintainers            | Logic, design, intent              |

## Build provenance & artefact integrity

Released artefacts on PyPI and GitHub are:

- **Built reproducibly** in the `Release` workflow (verified by Verify-job).
- **Signed with Sigstore** (cosign-keyless) using GitHub's OIDC.
- **Attested with build-provenance** via `actions/attest-build-provenance`.
- **Published to PyPI via OIDC trusted-publisher** — no API tokens in repo
  secrets.

Verify a downloaded artefact:

```bash
# Sigstore signature
sigstore verify identity \
  --cert-identity-regexp 'https://github.com/WimLee115/wimsalabim' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  wimsalabim-X.Y.Z-py3-none-any.whl

# Provenance attestation
gh attestation verify \
  --owner WimLee115 \
  wimsalabim-X.Y.Z-py3-none-any.whl
```

## Reference

- This file is published at the repository root and at
  `https://github.com/WimLee115/wimsalabim/security/policy`.
- Audit baseline: [`docs/PENTEST_REPORT.md`](docs/PENTEST_REPORT.md).
- Legal kader: [`docs/legal.md`](docs/legal.md).
