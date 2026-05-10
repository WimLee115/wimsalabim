# Security Policy

## Reporting a vulnerability

> **Do not open a public GitHub issue for security vulnerabilities.**

Please report privately to:

- Email: `security@wimlee115.invalid` (replace with real address before publication)
- PGP key fingerprint: *(to be added)*
- Or via the anonymous alias channel on `bewindklacht.nl`.

Encrypted reports are strongly preferred. We will acknowledge receipt within
**72 hours** and aim to provide a status update within **7 days**.

---

## Disclosure policy

We follow industry-standard **coordinated disclosure** with a **90-day window**:

1. We acknowledge your report.
2. We confirm or refute the issue.
3. We work on a fix and coordinate a release date.
4. We credit you in the release notes (or keep you anonymous if you prefer).
5. After 90 days, or after a fix is shipped — whichever comes first — the
   issue may be disclosed publicly.

If active in-the-wild exploitation is occurring, we may compress the timeline.

---

## Scope

In scope:

- The `wimsalabim` CLI and Python library (this repository).
- The `cryptographic-integrity` flow (sign/verify, canonical JSON, key handling).
- The `AuthorizationGate` enforcement.
- The HTTP client privacy hooks.

Out of scope:

- Third-party dependencies (report upstream; we will follow with a bump).
- The OpenTimestamps subprocess (report to OTS upstream).
- Issues with public targets we scan (those are the *output* of the tool).

---

## Hardening checklist for operators

If you operate `wimsalabim` in CI / production / shared infrastructure:

```
   ┌──────────────────────────────────────────────────────────────┐
   │                                                              │
   │   [ ]  Run as a non-root user.                               │
   │   [ ]  Pin dependencies via lockfile (`pip-compile`).        │
   │   [ ]  Store signing keys outside the repo (mode 0600).      │
   │   [ ]  Rotate signing keys yearly.                           │
   │   [ ]  Restrict outbound traffic to expected destinations.   │
   │   [ ]  Enable `--via-tor` if metadata-protection matters.    │
   │   [ ]  Verify report signatures on the receiving side.       │
   │   [ ]  Anchor important reports with OpenTimestamps.         │
   │   [ ]  Treat `~/.wimsalabim/` as sensitive (it holds keys).  │
   │                                                              │
   └──────────────────────────────────────────────────────────────┘
```

---

## Known not-bugs

The following are **not** security bugs:

- `bandit B603` warnings on `subprocess.run(["ots", ...])` — args are list-form,
  no shell, paths are operator-controlled.
- `denied` status for active analyzers without authorization — that is the gate
  doing its job.
- Refusal to connect to telemetry-blacklist hosts (e.g. `*.google-analytics.com`)
  — that is the privacy guard doing its job.

---

## Security tooling we run

| Tool         | When                                |
| ------------ | ----------------------------------- |
| `bandit`     | Pre-commit + CI                     |
| `pip-audit`  | Pre-commit + CI                     |
| `mypy --strict` | Pre-commit + CI                  |
| `ruff`       | Pre-commit + CI                     |
| Manual review | Every PR by maintainers            |
| Pentest report | Maintained at [`docs/PENTEST_REPORT.md`](docs/PENTEST_REPORT.md) |
