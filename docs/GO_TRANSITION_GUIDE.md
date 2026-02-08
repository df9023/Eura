# EURA Go Transition Guide

## Decision: New Repo

Create a **new repository** (`eura-core` or `eura-v3`). Keep this Python repo (`Eura`) intact as:
- The live MVP you can demo while the rewrite is in progress
- A test oracle to validate Go scanner output against
- The source of truth for rule definitions (`rules_db.json`)
- The React frontend (copy `frontend/` into the new repo later)

---

## Target Architecture

```
eura-v3/
├── cmd/
│   └── eura/                  # Go CLI entry point
│       └── main.go
├── internal/
│   ├── scanner/               # Core scanning orchestrator
│   │   ├── scanner.go
│   │   └── scanner_test.go
│   ├── discovery/             # File discovery & prioritization
│   │   ├── discovery.go
│   │   └── discovery_test.go
│   ├── parser/                # Dependency parsers (one file per ecosystem)
│   │   ├── parser.go          # Common interface
│   │   ├── requirements.go    # Python requirements.txt
│   │   ├── packagejson.go     # Node package.json
│   │   ├── pyproject.go       # pyproject.toml (PEP 621 + Poetry)
│   │   ├── pomxml.go          # Maven pom.xml
│   │   ├── gradle.go          # Gradle build files
│   │   ├── gomod.go           # Go go.mod
│   │   ├── cargo.go           # Rust Cargo.toml
│   │   ├── gemfile.go         # Ruby Gemfile + gemspec
│   │   └── *_test.go          # One test file per parser
│   ├── rules/                 # Rule engine
│   │   ├── engine.go          # Rule evaluation engine
│   │   ├── loader.go          # Load rules from JSON
│   │   ├── cra.go             # CRA rule implementations
│   │   ├── aiact.go           # AI Act rule implementations
│   │   └── *_test.go
│   ├── secrets/               # Secret detection
│   │   ├── detector.go
│   │   └── detector_test.go
│   ├── ai/                    # AI/ML component detection
│   │   ├── detector.go
│   │   └── detector_test.go
│   ├── verdict/               # Compliance scoring & verdicts
│   │   ├── verdict.go
│   │   └── verdict_test.go
│   ├── sbom/                  # SBOM generation (SPDX + CycloneDX)
│   │   ├── spdx.go
│   │   ├── cyclonedx.go
│   │   └── *_test.go
│   ├── sarif/                 # SARIF 2.1.0 export
│   │   ├── sarif.go
│   │   └── sarif_test.go
│   ├── osv/                   # OSV.dev vulnerability client
│   │   ├── client.go
│   │   └── client_test.go
│   ├── github/                # GitHub API client
│   │   ├── client.go
│   │   └── client_test.go
│   └── output/                # Output formatters (JSON, pretty, SARIF)
│       ├── json.go
│       └── pretty.go
├── api/                       # FastAPI Python API (kept in Python)
│   ├── main.py
│   ├── routes.py
│   ├── schemas/
│   └── requirements.txt
├── frontend/                  # React dashboard (copied from Python repo)
│   └── ...
├── data/
│   └── rules_db.json          # Rule definitions (shared between Go & Python)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
└── README.md
```

---

## Migration Order (10 Phases)

### Phase 1: Project Scaffold & CLI Shell
**Effort: 1 session (~2 hours)**

Set up the Go module, CLI framework, and basic project structure.

```
Tasks:
- [ ] `go mod init github.com/yourorg/eura-core`
- [ ] Set up `cmd/eura/main.go` with cobra or plain flag parsing
- [ ] Create `internal/` package layout
- [ ] Add Makefile (build, test, lint, install)
- [ ] Add `.golangci.yml` for linting
- [ ] Add GitHub Actions CI (go test, go vet, staticcheck)
- [ ] CLI: `eura scan ./path` (stub that prints "not implemented")
- [ ] CLI: `eura version` (prints version + commit hash)
```

**Go libraries to use:**
- `github.com/spf13/cobra` — CLI framework (or just `flag` if you prefer minimal)
- `github.com/rs/zerolog` — structured logging
- `github.com/BurntSushi/toml` — TOML parsing (for pyproject.toml, Cargo.toml)

### Phase 2: File Discovery
**Effort: 1 session (~1.5 hours)**

Port `app/services/file_discovery.py` → `internal/discovery/`.

```
Tasks:
- [ ] Port file prioritization logic (manifests → configs → docs → code)
- [ ] Port skip-directory patterns (.git, node_modules, venv, etc.)
- [ ] Use `filepath.Walk` or `fs.WalkDir` for local scanning
- [ ] Test with real repos on disk
- [ ] Benchmark: should be 10-100x faster than Python os.walk
```

**Python reference:** `app/services/file_discovery.py`

### Phase 3: Dependency Parsers
**Effort: 2-3 sessions (~5 hours)**

Port all 9 parsers from `app/services/dependencies.py`.

```
Tasks:
- [ ] Define common Dependency struct + Parser interface
- [ ] Port requirements.txt parser (regex)
- [ ] Port package.json parser (encoding/json)
- [ ] Port pyproject.toml parser (BurntSushi/toml)
- [ ] Port pom.xml parser (encoding/xml with namespace support)
- [ ] Port build.gradle parser (regex)
- [ ] Port go.mod parser (golang.org/x/mod/modfile — stdlib!)
- [ ] Port Cargo.toml parser (BurntSushi/toml)
- [ ] Port Gemfile + gemspec parser (regex)
- [ ] Port all 86 parser tests (table-driven tests in Go)
```

**Key advantage:** Go has `golang.org/x/mod/modfile` for go.mod parsing — better than our regex approach. `encoding/xml` handles namespaces natively. `BurntSushi/toml` is the canonical Go TOML library.

**Python reference:** `app/services/dependencies.py`, `tests/test_dependency_parsers.py`

### Phase 4: Secret Detection
**Effort: 1 session (~1.5 hours)**

Port `app/services/secret_detector.py`.

```
Tasks:
- [ ] Port regex patterns for API keys, tokens, passwords
- [ ] Port confidence scoring logic
- [ ] Compile regexes once at init (Go's regexp.MustCompile)
- [ ] Port false-positive filtering
```

**Python reference:** `app/services/secret_detector.py`

### Phase 5: Rule Engine
**Effort: 2-3 sessions (~6 hours)**

This is the biggest piece. Port the rule evaluation engine.

```
Tasks:
- [ ] Define Rule, RuleResult, Signal structs
- [ ] Port rule loader (reads rules_db.json)
- [ ] Port signal builder (builds evaluation context from scan data)
- [ ] Port all 35 CRA rule evaluations
- [ ] Port AI Act rules (classification + high-risk docs)
- [ ] Port evidence collector
- [ ] Port parallel evaluation (goroutines + sync.WaitGroup)
- [ ] Port all 87 CRA rule tests
```

**Key advantage:** Go's goroutines are ideal for parallel rule evaluation. `sync.WaitGroup` replaces `asyncio.gather()`.

**Python reference:** `app/services/rule_engine.py`, `app/services/ai_act_rules.py`, `tests/test_cra_rules.py`

### Phase 6: OSV Vulnerability Scanning
**Effort: 1 session (~2 hours)**

Port the OSV.dev API client.

```
Tasks:
- [ ] Port batch API request logic
- [ ] Port ecosystem mapping (PyPI, npm, Go, etc.)
- [ ] Port vulnerability report aggregation
- [ ] Use net/http client with context + timeouts
- [ ] Port all 49 OSV tests (mock HTTP responses)
```

**Python reference:** `app/services/osv.py`, `tests/test_osv.py`

### Phase 7: Compliance Scoring & Verdicts
**Effort: 1 session (~1 hour)**

Port the verdict and scoring logic.

```
Tasks:
- [ ] Port VerdictGenerator (SHIP_ALLOWED / SHIP_BLOCKED)
- [ ] Port ComplianceScorer (severity-weighted 0-100)
- [ ] Port environment-aware blocking (dev vs production)
```

**Python reference:** `app/services/compliance_evaluation.py`

### Phase 8: SBOM + SARIF + Badges
**Effort: 1-2 sessions (~3 hours)**

Port all compliance artifact generators.

```
Tasks:
- [ ] Port SPDX 2.3 JSON generation
- [ ] Port CycloneDX 1.5 JSON generation
- [ ] Port SARIF 2.1.0 generation
- [ ] Port SVG badge generation
- [ ] Port purl generation for all ecosystems
```

**Python reference:** `app/services/sbom.py`, `app/services/sarif.py`, `app/services/badge.py`

### Phase 9: CLI Polish + JSON Output
**Effort: 1 session (~2 hours)**

Make the CLI production-ready.

```
Tasks:
- [ ] Wire all components into scanner orchestrator
- [ ] JSON output (machine-readable, pipe to jq)
- [ ] Pretty output (human-readable, colored)
- [ ] SARIF output (for CI integrations)
- [ ] Exit codes: 0 = SHIP_ALLOWED, 1 = SHIP_BLOCKED, 2 = error
- [ ] --format flag (json, pretty, sarif)
- [ ] --environment flag (dev, staging, production, eu-production)
- [ ] --output flag (write to file)
- [ ] GitHub repo scanning (owner/repo syntax)
- [ ] Build: `go build -ldflags` with version + commit hash
```

### Phase 10: Python API Integration
**Effort: 1-2 sessions (~3 hours)**

Connect the Go binary to the existing Python FastAPI API.

```
Tasks:
- [ ] Copy FastAPI API into api/ directory
- [ ] Modify scan endpoint to invoke Go binary via subprocess
- [ ] Parse Go JSON output back into Python Pydantic models
- [ ] Copy React frontend into frontend/ directory
- [ ] Docker Compose: Go scanner + Python API + Vite frontend
- [ ] Health check endpoint that verifies Go binary is available
```

**Integration pattern:**
```python
# In Python API
import subprocess, json

async def run_scan(repo_path: str) -> dict:
    result = subprocess.run(
        ["./eura", "scan", repo_path, "--format", "json"],
        capture_output=True, text=True, timeout=300
    )
    return json.loads(result.stdout)
```

---

## What Stays in Python

| Component | Reason |
|-----------|--------|
| FastAPI REST API | Excellent for rapid API development, Pydantic validation |
| LLM integration | OpenAI SDK, prompt engineering |
| Remediation templates | String templating, low performance sensitivity |
| Database layer | Supabase client, ORM convenience |
| React frontend | Not language-dependent (separate build) |

## What Moves to Go

| Component | Reason |
|-----------|--------|
| File discovery | `fs.WalkDir` is 10-100x faster |
| Dependency parsers | Strong typed parsing, `encoding/xml`, `BurntSushi/toml` |
| Secret detection | Regex scanning over large codebases |
| Rule engine | Parallel goroutine evaluation |
| OSV client | `net/http` with proper context/timeout |
| Scoring/verdicts | Pure logic, no dependencies |
| SBOM/SARIF generation | JSON marshaling |
| CLI | Single binary distribution |

---

## Total Estimated Effort

| Phase | Sessions | Hours |
|-------|----------|-------|
| 1. Scaffold + CLI | 1 | 2 |
| 2. File discovery | 1 | 1.5 |
| 3. Dependency parsers | 2-3 | 5 |
| 4. Secret detection | 1 | 1.5 |
| 5. Rule engine | 2-3 | 6 |
| 6. OSV client | 1 | 2 |
| 7. Scoring/verdicts | 1 | 1 |
| 8. SBOM/SARIF/badges | 1-2 | 3 |
| 9. CLI polish | 1 | 2 |
| 10. Python integration | 1-2 | 3 |
| **Total** | **12-18** | **~27 hours** |

This is roughly 2-3 weeks of focused work (or 4-6 weeks at a relaxed pace).

---

## Go Libraries Cheat Sheet

| Need | Library | Notes |
|------|---------|-------|
| CLI framework | `github.com/spf13/cobra` | Or `flag` stdlib for minimal |
| TOML parsing | `github.com/BurntSushi/toml` | De facto standard |
| JSON | `encoding/json` (stdlib) | Built-in, fast enough |
| XML (pom.xml) | `encoding/xml` (stdlib) | Namespace-aware |
| go.mod parsing | `golang.org/x/mod/modfile` | Official parser |
| HTTP client | `net/http` (stdlib) | Use with `context.Context` |
| Logging | `github.com/rs/zerolog` | Structured, fast |
| Testing | `testing` (stdlib) | Table-driven tests |
| Assertions | `github.com/stretchr/testify` | Optional but nice |
| Regex | `regexp` (stdlib) | RE2 syntax (no backrefs) |
| File walking | `io/fs` (stdlib) | `fs.WalkDir` |
| Concurrency | `sync` (stdlib) | `WaitGroup`, `Mutex` |
| Color output | `github.com/fatih/color` | Terminal colors |

---

## Go Idioms to Follow

1. **Table-driven tests** — every parser test should be a `[]struct{ name, input, want }` slice
2. **Errors are values** — return `(result, error)`, never panic
3. **Interfaces are small** — `type Parser interface { Parse(content string) ([]Dep, error) }`
4. **Accept interfaces, return structs** — concrete return types, interface parameters
5. **Context everywhere** — `ctx context.Context` as first param for anything I/O
6. **No init()** — explicit initialization in main()
7. **internal/ for private packages** — prevents external import

---

## Validation Strategy

Run both scanners against the same repos and diff the output:

```bash
# Python scanner
python -m cli.eura_cli scan ./test-repo --format json > python_result.json

# Go scanner
./eura scan ./test-repo --format json > go_result.json

# Compare (jq + diff)
diff <(jq -S . python_result.json) <(jq -S . go_result.json)
```

Key fields to validate:
- Same number of dependencies detected
- Same rule results (PASS/FAIL/UNKNOWN)
- Same verdict (SHIP_ALLOWED/SHIP_BLOCKED)
- Same or better compliance score
- Same vulnerability count

---

## When to Start

**Not yet.** Finish these first in the Python repo:
1. Demo the React dashboard to stakeholders
2. Get at least 5 real-world repos scanned successfully
3. Collect feedback on which rules are too noisy / too quiet
4. Stabilize the rule definitions in `rules_db.json`

The Go rewrite should be driven by a concrete need (distribution pain, performance bottleneck, or enterprise customer requirement), not by architecture aesthetics.

**Start the Go rewrite when:**
- You need a single-binary CLI distribution (no Python runtime)
- Scan times on large repos exceed acceptable thresholds
- You have a customer who needs on-prem/air-gapped deployment
- The Python parsers are hitting correctness limits on real-world codebases