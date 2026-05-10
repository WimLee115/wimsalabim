## Summary

<!-- One-paragraph description of what this PR does. -->

## Why

<!-- The motivation. Link an issue if applicable. -->

Fixes # (issue)

## Test plan

<!--
What you ran locally to verify. Be concrete.

Example:
- ruff format --check src tests          (no diff)
- ruff check src tests                   (0 violations)
- mypy src                               (0 errors)
- pytest -v                              (118 passed → 124 passed)
- New test: tests/test_analyzer_<x>.py covers <scenarios>
-->

## Risk

<!--
What could go wrong? Backwards compatibility? Performance regression?
Any flag that defaults differently? Any new dependency?
-->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (requires a major version bump)
- [ ] Documentation
- [ ] Refactor (no functional change)
- [ ] Tests
- [ ] CI / build

## Checklist

- [ ] CI green (`make all`).
- [ ] Coverage did not drop below the gate.
- [ ] Updated `CHANGELOG.md` under `[Unreleased]`.
- [ ] Added or updated tests.
- [ ] Added or updated docs (README, docs/, or inline).
- [ ] No telemetry, analytics, or third-party callbacks introduced.
- [ ] If active analyzer: documented authorization story.
- [ ] Conventional Commit message in the merge commit (`feat:`, `fix:`, …).
