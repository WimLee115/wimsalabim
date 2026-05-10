# Architecture

This document explains how `wimsalabim` is built and why. For a beginner-friendly
overview, see the **Architecture** section in [`README.md`](../README.md#architecture).

---

## Design principles

1. **Honest by construction.** No claim ships in a report that isn't backed by
   provenance. No score is opaque. No "AI" hides behind a black box.
2. **Default to safe.** Passive analyzers run anywhere; active analyzers refuse
   to run without proof of authorization.
3. **Local-first.** Nothing leaves the machine that the operator didn't ask for.
4. **Explicit over implicit.** No magic entry-points, no auto-discovery via
   reflection. Plugins register through one decorator + one import line.
5. **Small public surface.** `core/` and `risk/` form a stable API. Analyzers
   are extension points.

---

## Layered model

```
   ┌───────────────────────────────────────────────────────────────┐
   │                                                               │
   │   L4    Renderers           rich · markdown · sarif           │
   │                                                               │
   │   L3    Risk engine         HeuristicRiskEngine + rules       │
   │                                                               │
   │   L2    Orchestration       Orchestrator (asyncio.gather)     │
   │                                                               │
   │   L1    Analyzers           dns_recon · tls · headers · ports │
   │                                                               │
   │   L0    Core primitives     schema, exceptions, gate, http,   │
   │                              registry, crypto, canonical, …   │
   │                                                               │
   └───────────────────────────────────────────────────────────────┘
```

Lower layers know nothing about higher ones. `core/schema.py` does not import
from `analyzers/`; `analyzers/` does not import from `display/`. This keeps
the dependency graph acyclic and the test scope per module narrow.

---

## Lifecycle of a scan

```
   1.  CLI parses flags             cli.py
                │
   2.  CLI builds OrchestratorConfig
                │
   3.  Authorization is verified    core/authorization.py
                                    (DNS-TXT / well-known / self-owned)
                │
   4.  Orchestrator constructs HTTP
       client with privacy hooks    core/http_client.py
                │
   5.  Per analyzer in parallel:
       a. Gate check                core/authorization.AuthorizationGate.check()
       b. analyze() called          analyzers/<x>.py
       c. Result wrapped            schema.AnalyzerResult
       d. Errors typed-mapped       core/exceptions.py
                │
   6.  Risk engine assesses         risk/heuristic.py
       — predicates fire on the dict of AnalyzerResult
                │
   7.  ScanReport composed          core/orchestrator.py
       — config_hash deterministic via canonical/hash_obj
                │
   8.  Optional: signing            core/crypto.py
       — Ed25519 over canonical-JSON-without-signature
                │
   9.  Optional: OTS anchor         core/timestamps.py
                │
  10.  Renderer outputs             display/<format>.py
```

Steps 5a–5d run **concurrently** under `asyncio.gather`. The per-analyzer
timeout is enforced with `asyncio.wait_for`.

---

## Why pydantic v2 + frozen models

Frozen pydantic models give us four properties for free:

1. **Validation at the boundary.** Naive datetimes are rejected; CWE strings
   must match `CWE-\d+`; CVSS scores must be in `[0, 10]`.
2. **Hashability.** Identical inputs produce identical canonical JSON.
3. **Tamper-evidence.** A signed report cannot be mutated in-place; any change
   forces a new object, which would break the signature.
4. **Documentation.** The schema is the docs.

---

## Why no monkey-patchable globals

The registry (`core/registry._REGISTRY`) is module-level state but only mutated
during decorator execution at import time. Tests that need an empty registry
use a fixture that snapshot-restores the state — never reaching into the global
mutable behavior under load.

---

## Why httpx and not requests

| Concern                   | requests                   | httpx                                    |
| ------------------------- | -------------------------- | ---------------------------------------- |
| Async                     | sync only                  | sync + async                             |
| HTTP/2                    | no                         | yes                                      |
| Event hooks (privacy gate)| limited                    | first-class                              |
| Connection pooling        | yes                        | yes (better)                             |
| SOCKS5 (Tor)              | via `requests[socks]`      | via `httpx.Proxy("socks5://...")`        |
| Timeouts                  | global                     | granular (`connect`, `read`, `write`)    |
| Type hints                | partial                    | complete                                 |

The privacy guard is implemented as an event hook on `request`. This catches
the request *before the socket opens*, which is what we want.

---

## The Authorization Gate, in detail

```python
class AuthorizationGate:
    def check(self, *, target: str, legal_class: LegalClass) -> None:
        if legal_class == "passive":
            return                                        # always allowed
        if self._authz is None:
            raise AuthorizationDenied(...)                # active without proof
        if not _hosts_match(self._authz.target, target):
            raise AuthorizationDenied(...)                # proof for wrong target
        if legal_class == "intrusive" and not self._allow_intrusive:
            raise AuthorizationDenied(...)                # extra guard
```

The gate is **fail-closed**. There is no path that reaches an active analyzer
without one of the three explicit `Authorization` modes succeeding first.

`_hosts_match` allows subdomain widening: if the operator proved authorization
for `example.com`, then `api.example.com` is also covered. This matches how
bug-bounty programs typically scope.

---

## The risk engine, in detail

A `Rule` is a quadruple:

```python
Rule(
    rule_id, name, severity, points,
    cwe,
    predicate=Callable[[dict[str, AnalyzerResult]], bool],
    rationale_fn=Callable[[dict[str, AnalyzerResult]], str],
)
```

`HeuristicRiskEngine.assess` walks the rule registry, fires each predicate,
collects `RuleHit` objects, sums points (capped at 100), and computes a final
grade.

**Severity-aware grading:** the raw score determines the grade band, but any
unmitigated `critical` rule pulls the grade to **D-or-worse**. Rationale: a
single missed-but-critical finding (e.g., expired certificate) is operationally
worse than several mediums.

To add a rule:

1. Append to `RULE_REGISTRY` in `src/wimsalabim/risk/rules.py`.
2. Add a unit test in `tests/test_risk.py` that constructs the input scenario
   and asserts the rule fires.
3. Reference the CWE identifier where applicable.

There is no way to add a rule "from outside" the codebase. This is deliberate
— rule logic is part of the audit surface.

---

## What is not in scope

- **Active offensive features.** No exploitation, fuzzing, brute force, or
  credential testing.
- **Vulnerability database mirror.** We rely on the cert/CWE conventions; CVE
  lookup is on the roadmap as a passive-only enrichment.
- **Multi-target queue.** One scan = one target. Compose with shell tooling
  if you need a fleet.
- **Web UI / dashboard.** CLI tools compose; GUIs don't.

---

## Roadmap items requiring architectural change

| Feature                          | Affects                                                |
| -------------------------------- | ------------------------------------------------------ |
| `wimsalabim watch` daemon        | New layer between CLI and Orchestrator                 |
| Configuration files (`config.toml`)| New layer above CLI flags; precedence rules         |
| PQC hybrid signing               | `core/crypto.py` extended with `liboqs` bindings       |
| Distributed-watch federation     | New `federation/` package; needs a wire protocol       |

Each of these will arrive with its own design note in this folder.
