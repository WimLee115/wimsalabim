# Wimsalabim

> Instant beautiful security reconnaissance for any domain - ML/AI-powered network intelligence

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/wimsalabim)](https://pypi.org/project/wimsalabim/)

`rootmap:WimLee115`

```
 __        ___                       _       _     _
 \ \      / (_)_ __ ___  ___  __ _| | __ _| |__ (_)_ __ ___
  \ \ /\ / /| | '_ ` _ \/ __|/ _` | |/ _` | '_ \| | '_ ` _ \
   \ V  V / | | | | | | \__ \ (_| | | (_| | |_) | | | | | | |
    \_/\_/  |_|_| |_| |_|___/\__,_|_|\__,_|_.__/|_|_| |_| |_|
```

One command. Beautiful output. Zero config. ML/AI-powered security insights.

## What It Does

Point Wimsalabim at any domain and get an instant, gorgeous security overview:

```bash
wimsalabim example.com
```

## Features

### Core Analyzers
| Module | Description |
|--------|-------------|
| **Port Scan** | Async port scanner with service detection & banner grabbing |
| **TLS/SSL Audit** | Certificate analysis, protocol versions, cipher evaluation, expiry warnings |
| **HTTP Headers** | Security headers grade (CSP, HSTS, X-Frame-Options, CORS, 10+ headers) |
| **DNS Recon** | A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA records + zone transfer check |
| **Email Security** | SPF, DKIM, DMARC analysis with per-protocol grading |
| **Tech Fingerprint** | Detects frameworks, CMS, servers, CDNs, JS libraries, cloud providers |
| **WHOIS** | Registration info, domain age, expiry, privacy protection detection |

### Extra Modules
| Module | Description |
|--------|-------------|
| **Subdomain Discovery** | DNS brute-force + crt.sh certificate transparency |
| **WAF Detection** | Identifies 15+ WAFs (Cloudflare, AWS WAF, Akamai, Imperva, etc.) |
| **Directory Scan** | 70+ common paths including .git, .env, admin panels, backups |
| **CORS Analysis** | Origin reflection, null origin, subdomain, wildcard+credentials tests |
| **Cookie Security** | Secure/HttpOnly/SameSite flags, session cookie analysis |
| **Cloud Detection** | AWS, Azure, GCP, Vercel, Netlify + storage bucket exposure check |
| **CVE Lookup** | Cross-references detected tech with OSV.dev and NIST NVD databases |

### ML/AI Engine
| Module | Description |
|--------|-------------|
| **Anomaly Detection** | Isolation Forest statistical anomaly detection on security profile |
| **Threat Classifier** | Decision Tree threat classification with knowledge base + mitigations |
| **Risk Engine** | Ensemble ML (GradientBoosting + RandomForest) risk assessment with recommendations |

## Installation

```bash
# Recommended
pipx install wimsalabim

# Or with pip
pip install wimsalabim
```

## Usage

```bash
# Full scan
wimsalabim example.com

# Quick scan (ports + TLS + headers only)
wimsalabim example.com --quick

# JSON output for CI/CD
wimsalabim example.com --json-output

# Custom ports
wimsalabim example.com --ports 80,443,8080,8443

# Skip specific modules
wimsalabim example.com --no-subdomains --no-dirs

# Skip ML analysis
wimsalabim example.com --no-ml
```

### All Options

```
Usage: wimsalabim [OPTIONS] TARGET

Options:
  -j, --json-output     Output results as JSON
  -q, --quick           Quick scan (ports + TLS + headers only)
  -p, --ports TEXT      Custom port list (comma-separated)
  -t, --timeout FLOAT   Port scan timeout in seconds
  -v, --version         Show version
  --no-ports            Skip port scanning
  --no-tls              Skip TLS analysis
  --no-headers          Skip HTTP headers check
  --no-dns              Skip DNS reconnaissance
  --no-email            Skip email security check
  --no-tech             Skip technology fingerprinting
  --no-whois            Skip WHOIS lookup
  --no-subdomains       Skip subdomain discovery
  --no-waf              Skip WAF detection
  --no-dirs             Skip directory scanning
  --no-cors             Skip CORS analysis
  --no-cookies          Skip cookie analysis
  --no-cloud            Skip cloud detection
  --no-cve              Skip CVE lookup
  --no-ml               Skip ML/AI analysis
  --help                Show this message and exit
```

## Output

Wimsalabim produces beautiful Rich-powered terminal output with:
- Color-coded security grades (A-F) per module
- Risk-classified port scan results
- Visual risk bars and score breakdowns
- AI-generated threat vectors with mitigations
- Executive + technical risk summaries
- Prioritized remediation recommendations

JSON output (`--json-output`) is available for CI/CD integration and automation.

## ML/AI Pipeline

```
Scan Results
    |
    v
[Anomaly Detection] -- Isolation Forest detects statistical outliers
    |
    v
[Threat Classifier] -- Decision Tree classifies threat vectors
    |                   + rule-based knowledge base
    v
[Risk Engine]       -- GradientBoosting + RandomForest ensemble
    |                   predicts overall risk score
    v
Recommendations     -- Prioritized, actionable remediation steps
```

## Disclaimer

Wimsalabim is designed for **authorized security testing only**. Always ensure you have permission to scan the target. Use responsibly and ethically.

## License

MIT License - see [LICENSE](LICENSE)

## Author

Created by [WimLee115](https://github.com/WimLee115) with Claude Opus 4.6

`rootmap:WimLee115`
