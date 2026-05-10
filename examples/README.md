# Examples

Real-world artefacts you can read or reuse.

## `owned-domains.txt`

Sample manifest for `--auth-self-owned`. One host per line; subdomains
auto-included.

```bash
wimsalabim scan api.example.com \
  --auth-self-owned ./owned-domains.txt \
  --enable ports
```

## `github-action.yml`

Drop-in GitHub Actions workflow that scans your domain daily and uploads
the SARIF report to GitHub Code Scanning. Requires:

- `vars.TARGET_DOMAIN` set in repository variables.
- A committed `security/owned-domains.txt` listing the operator-owned scope.

## `sample-report.json`

A real, **unsigned** JSON report from a passive scan of `example.com`
(analyzers: `dns_recon`, `tls`, `headers`). Use it to:

- Understand the JSON shape without running the tool.
- Test downstream parsers / dashboards against a stable fixture.
- See how findings, sources, and metadata fit together.

> Generated 2026-05-10 against the live example.com endpoint.

## `sample-report-signed.json`

A real, **Ed25519-signed** JSON report. Includes `signature` and
`signing_pubkey` fields. Verify with:

```bash
wimsalabim verify examples/sample-report-signed.json
# → ✓ valid   pubkey ZijlnIQcLjclkw5f…   digest 5484e2cf…
```

If you mutate any field and re-run, verification fails:

```bash
python -c "
import json
d = json.load(open('examples/sample-report-signed.json'))
d['target'] = 'evil.example.com'
json.dump(d, open('examples/sample-report-signed.json', 'w'))
"
wimsalabim verify examples/sample-report-signed.json
# → ✗ INVALID signature
```

This is the basis of forensic-grade reporting: if it verifies, the
contents are exactly what the signer wrote.
