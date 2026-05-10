---
name: Bug report
about: Report a defect that you can reproduce
title: "[bug] "
labels: ["bug", "triage"]
assignees: []
---

## Summary

<!-- One-sentence description of the bug. -->

## Reproducer

```bash
# Exact command(s) you ran:
wimsalabim scan example.com --enable headers

# What you expected:

# What you got:
```

## Environment

- `wimsalabim --version`: <!-- e.g., 0.2.0 -->
- Python: <!-- python --version -->
- OS: <!-- uname -a / Windows version -->
- Installed via: <!-- pipx / pip / source -->

## Logs

<details>
<summary>Full output (use --verbose if applicable)</summary>

```
<paste here>
```

</details>

## Signed scan report (optional, gold for reproducibility)

<!-- If you signed the failing scan with `--sign`, attach the JSON here. -->

## Checklist

- [ ] I am using the latest released version.
- [ ] I have searched existing issues for duplicates.
- [ ] My reproducer is minimal — only the analyzers needed to demonstrate the bug.
- [ ] No sensitive data in this report (or I have redacted it).
