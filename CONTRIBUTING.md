# Contributing to `wimsalabim`

Thank you for considering a contribution. This document describes how to get
started, the standards we hold ourselves to, and what we will and will not accept.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Quick start

```bash
git clone https://github.com/WimLee115/wimsalabim.git
cd wimsalabim
make dev        # creates .venv, installs dev deps, installs pre-commit hooks
make all        # lint + typecheck + test + audit (the same gates CI runs)
```

If you don't have `make`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
ruff format src tests
ruff check src tests
mypy src
pytest -v
bandit -r src --severity-level low
pip-audit
```

---

## What we look for

| Welcome                                                     | Not accepted                                                  |
| ----------------------------------------------------------- | ------------------------------------------------------------- |
| New **passive** analyzers (cookies, security.txt, robots, sitemap, …) | Active features without a clear authorization story  |
| Mock fixtures lifting `tls.py` / `ports.py` coverage        | Telemetry, analytics, phone-home of any kind                  |
| More CWE / CVSS mappings on existing findings               | "AI" features without a published model card                  |
| Translations of user-facing strings                         | Vendored binaries or pre-compiled blobs                       |
| Fuzz / property-based tests on parsers                      | Code that breaks `mypy --strict` or our `ruff` rule set       |
| Documentation, examples, troubleshooting recipes            | Pull requests that lower coverage below the 70% gate          |
| Bug reports with reproducer + expected output               | Snark, harassment, low-effort comments (see Code of Conduct)  |

---

## The merge gate

Every PR must, at the time of merge:

```
   ✓  ruff format --check src tests        (no diff)
   ✓  ruff check src tests                 (0 violations)
   ✓  mypy src                             (0 errors, --strict)
   ✓  pytest                               (all passing, ≥ 70% coverage)
   ✓  bandit -r src --severity-level low   (no medium / high findings)
   ✓  pip-audit                            (no known vulnerabilities)
   ✓  pre-commit hooks                     (whitespace, secrets, large files)
```

CI enforces these. PRs that fail any gate are not merged until fixed. There is no `[skip ci]`.

---

## Development workflow

### Branch naming

```
   feat/<short-name>          new feature or analyzer
   fix/<short-name>           bug fix
   docs/<short-name>          documentation
   chore/<short-name>         build / CI / housekeeping
   refactor/<short-name>      no functional change
   test/<short-name>          tests only
```

### Commit messages

We use **Conventional Commits**:

```
feat(headers): add Permissions-Policy v2 detection
fix(tls): handle SNI-less servers gracefully
docs(readme): clarify --auth-self-owned format
refactor(orchestrator): extract retry loop into helper
test(headers): mock CSP variants
chore(deps): bump pydantic to 2.7
```

The first line is ≤ 72 characters. The body (optional) explains *why*, not *what*.

### Pull request size

- Aim for **≤ 400 lines** of diff per PR. Split larger work into stacked PRs.
- One concern per PR. A new analyzer + a bugfix should be two PRs.
- Update tests in the same PR as the code change. Never "tests will follow."

### Pull request description

Use the template in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md). Required sections: **Summary**, **Why**, **Test plan**, **Risk**.

---

## Adding a new analyzer

The full plugin guide is in [`README.md` § Plugin development](README.md#plugin-development). The 60-second version:

1. Create `src/wimsalabim/analyzers/<my_analyzer>.py`.
2. Decorate your class with `@analyzer(name=…, legal_class=…, capabilities=…, description=…)`.
3. Implement `async def analyze(self, context: AnalysisContext) -> BaseReport`.
4. Import the module in `src/wimsalabim/analyzers/__init__.py` to trigger registration.
5. Add tests under `tests/test_analyzer_<name>.py` using `respx` (HTTP) or mock fixtures.
6. Add a row in the README's "Built-in analyzers" table.
7. Add CWE/CVSS metadata to your findings where applicable.
8. If your analyzer is `active` or `intrusive`, document the authorization rationale in the PR description.

---

## Reporting bugs

Open an issue with the **Bug report** template in `.github/ISSUE_TEMPLATE/bug_report.md`. Include:

- `wimsalabim --version`
- Python version and OS
- Minimal reproducer (target if public, exact CLI invocation)
- Expected vs actual output (paste, do not screenshot)
- A signed scan report (`--sign`) is gold for reproducibility

For **security vulnerabilities**, do **not** open a public issue. Follow [`SECURITY.md`](SECURITY.md).

---

## Style notes

- **Type everything.** `mypy --strict` is non-negotiable.
- **No `Any` without comment.** If you must use `Any`, add `# noqa: <rule>` with a one-line reason.
- **Imports at the top.** Local imports inside functions are flagged (`PLC0415`).
- **Magic numbers go to constants.** `_EXPIRY_CRITICAL_DAYS = 7` instead of `if days_left < 7`.
- **Errors are typed.** Don't `raise Exception(...)`. Use the hierarchy in `core/exceptions.py` or extend it.
- **Logs are structured.** `log.info("event", key=value)` — no f-strings inside log calls.
- **Time is UTC.** `datetime.now(tz=timezone.utc)` everywhere; the schema rejects naive datetimes.

---

## Running a local pre-publish check

```bash
make all              # all CI gates
make build            # produces dist/*.whl + dist/*.tar.gz
twine check dist/*    # validates metadata
```

---

## Releasing (maintainers only)

1. Bump version in `pyproject.toml`.
2. Update `CHANGELOG.md` (move "Unreleased" → "v0.X.Y").
3. `git tag -s v0.X.Y -m "release v0.X.Y"`.
4. `git push origin v0.X.Y`.
5. CI builds, tests, signs, publishes to PyPI.
6. Create GitHub Release with the changelog section as body.

---

## Communication

- **Issues**: bugs, feature requests, design discussions.
- **Pull requests**: code, docs, tests.
- **Discussions**: open-ended questions, "how would you…", showcasing scans you ran.

We are a small project; please be patient. Triage happens weekly.

---

Captain `WimLee115` reads every PR.
Welkom aan boord.
