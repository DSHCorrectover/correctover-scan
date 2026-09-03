# correctover-scan

> Security scanner for MCP servers and AI agents — detects credential exposure, SSRF, command injection risk and missing auth across your MCP configuration. 14 checks mapped to OWASP AISVS 1.0. Run anywhere with `npx correctover-scan`.

![npm](https://img.shields.io/npm/v/correctover-scan)
![license](https://img.shields.io/npm/l/correctover-scan) [![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)

---

### Verifiable artifacts behind this tool

- **Third-party interoperability** — joint assessment merged into the [EMILIA protocol](https://github.com/emiliaprotocol/emilia-protocol/pull/693)
- **66 signed conformance test vectors** — reproducible by anyone: [ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors)
- **Published methodology** — [Zenodo DOI 10.5281/zenodo.21783723](https://doi.org/10.5281/zenodo.21783723)
- **Need a human audit?** — 116-check manual audit methodology, 5-day turnaround: [Agent Output Audit](https://correctover.com/agent-audit.html)

`correctover-scan` audits the MCP (Model Context Protocol) configuration files used by Claude Code, Claude Desktop, Cursor, VS Code and other AI agent tools. It scans for credential leaks, SSRF exposure, missing transport encryption, over-broad tool permissions and more — 14 security checks covering the issues that turn MCP integrations into RCE, data exfiltration and prompt-injection paths. Zero install: `npx correctover-scan` runs locally, works in CI, and outputs SARIF for GitHub code scanning.

**v1.4.0** adds a second mode: `--bundle` code-layer signal scanning for published npm packages and bundled/minified JavaScript — 17 checks over shipped code, with [file+line findings, minified-code reformatting and context-based false-positive suppression](#-bundle--published-package-code-scan-v140).

## ⚡ Quick Start — running in 30 seconds

Zero config, no account, no sign-up — scan the current directory for MCP configuration issues:

```bash
npx correctover-scan@latest
```

It auto-detects MCP config files (`.cursor/mcp.json`, `claude_desktop_config.json`, `.claude/mcp.json`, `mcp.json`, `.vscode/mcp.json` and more) and runs 14 checks. Everything runs locally on your machine — config files are not uploaded.

```bash
# Scan a specific config file
npx correctover-scan mcp.json

# Recursively scan a project directory
npx correctover-scan -d ./my-project -r

# SARIF output for GitHub code scanning
npx correctover-scan mcp.json -f sarif > report.sarif
```

## What It Checks

| # | Check | Severity | AISVS |
|---|-------|----------|-------|
| 1 | TLS Transport Encryption | 🔴 Critical | C10.1 |
| 2 | Server Authentication | 🟠 High | C10.2 |
| 3 | Timeout Configuration | 🟡 Medium | C9.1 |
| 4 | Credential Exposure | 🔴 Critical | C5.1 |
| 5 | Tool Allowlist | 🟠 High | C9.3 |
| 6 | Token Budget Control | 🟠 High | C9.1 |
| 7 | SSRF Protection | 🔴 Critical | C10.3 |
| 8 | Audit Logging | 🟡 Medium | C12.1 |
| 9 | Sandbox Isolation | 🟡 Medium | C4.1 |
| 10 | Dependency Version Pinning | 🟡 Medium | C6.1 |
| 11 | Error Handling Strategy | 🟡 Medium | C12.2 |
| 12 | Input Validation | 🟠 High | C2.1 |
| 13 | Output Validation | 🟡 Medium | C7.1 |
| 14 | Kill Switch | 🟠 High | C9.5 |

## Output Formats

```bash
# Terminal (default)
correctover-scan mcp.json

# JSON
correctover-scan mcp.json -f json

# SARIF (for CI integration)
correctover-scan mcp.json -f sarif > report.sarif
```

## Supported Config Files

Auto-detects these files:
- `.cursor/mcp.json`
- `claude_desktop_config.json`
- `.claude/mcp.json`
- `mcp.json` / `mcp.yaml` / `mcp.yml`
- `.vscode/mcp.json`
- `.mcp/mcp.json`
- `config/mcp.json`

## 📦 Bundle / published-package code scan (v1.4.0)

### Usage

```bash
# Audit an unpacked npm package: reads package.json entry (main/module/bin)
# and every .js/.mjs/.cjs/.ts file in the tree (node_modules skipped)
npx correctover-scan@latest --bundle ./node_modules/some-pkg
npx correctover-scan@latest -b ./pkg                      # -b is shorthand for --bundle

# Audit a single minified/bundled JS file
npx correctover-scan@latest --bundle dist/app.min.js

# A positional .js/.mjs/.cjs/.ts target auto-selects bundle mode
npx correctover-scan@latest ./cli.js

# Outputs: text (default), JSON, or SARIF with file+line locations
npx correctover-scan@latest -b ./pkg -f json
npx correctover-scan@latest -b ./pkg -f sarif > bundle.sarif
npx correctover-scan@latest -b ./pkg -o report.txt        # write the report to a file
npx correctover-scan@latest -b ./pkg -f json -o bundle.json
```

Exit code is `1` when any check produces a fail-level finding — drop the command straight into CI.

### What bundle mode is — and what it is not

Bundle mode is **signal scanning over shipped/minified code**. Minifiers rename local variables, but property names, string literals, URLs, environment-variable names and error messages survive bundling — so the attack-surface signals the checks rely on are still present in the published artifact.

- **12 automatic checks** return a verdict (pass / warn / fail) — hardcoded secrets, cloud-metadata/SSRF, `shell:true`/`exec` subprocess calls, dynamic `eval`/`Function`/`vm`, plaintext endpoints, MCP transport auth, permission gates, missing timeouts/kill-switch/input validation, env-credential flow, sandbox signals.
- **5 semi-automatic checks** (token budget, audit logging/telemetry, supply-chain/SBOM, error handling/retry, output truncation/filtering) **enumerate the signals** they find in shipped code — the signal's presence is verifiable, but whether the control is actually enforced needs human review. Those signals are listed in the JSON output and never counted as fails.
- Every finding is grounded at **file + line with a code snippet**. Minified files are detected and lightly reformatted internally (statement/block expansion, no dependencies) so line numbers stay usable; already-formatted source is scanned untouched.
- Known-benign patterns are suppressed with context heuristics and reported as info — for example cloud-SDK metadata credential providers (AWS IMDS / GCP metadata), `shell:false` fixed-argument spawn calls, sandbox VM implementations, localhost/spec-namespace URLs and placeholder/example strings.

**Honest scope:** bundle mode does not prove reachability or intent — a signal that is located correctly may still be unreachable in practice, and conclusions on the semi-automatic checks remain a manual-review job. It is an automated triage layer that points a reviewer at the exact lines to examine; it does **not** replace the **116-check manual audit methodology**, where reviewers trace data flow and what each capability can actually be made to do. Scanning covers JavaScript/TypeScript code, configuration and protocol-layer signals; deep logic compiled into native binaries (e.g. Bun `--compile` single-file executables) is outside static analysis and is not covered by bundle mode. Everything runs locally — package code is not uploaded.

### Bundle checks (17)

Check ids continue the config scanner's 14-check scheme so text/JSON/SARIF outputs stay aligned.

| # | Check | Type | Severity | AISVS |
|---|-------|------|----------|-------|
| 1 | Hardcoded credentials in code (sk-/ghp_/AKIA/AIza/xox patterns, placeholder-aware) | automatic | 🔴 Critical | C5.1 |
| 2 | Plaintext HTTP outbound endpoints (localhost/spec/example hosts suppressed) | automatic | 🟠 High | C10.1 |
| 3 | Cloud metadata & intranet addresses / SSRF (169.254.x, RFC1918, GCP metadata; cloud-SDK & guard context suppressed) | automatic | 🔴 Critical | C10.3 |
| 4 | Subprocess execution — `shell:true` / `exec` (`shell:false` fixed-arg spawn not flagged) | automatic | 🟠 High | C4.1 |
| 5 | Dynamic code execution — `eval` / `new Function` / `vm` (sandbox/shim contexts suppressed) | automatic | 🟠 High | C4.1 |
| 6 | Environment-variable credential flow (hardcoded fallback secrets flagged) | automatic | 🟡 Medium | C5.1 |
| 7 | Permission modes & tool gates (`allowedTools`, `dangerouslySkipPermissions`) | automatic | 🟠 High | C9.3 |
| 8 | MCP transport authentication (remote sse/http/ws without Authorization signal) | automatic | 🟠 High | C10.2 |
| 9 | Timeout & interruption signals (`AbortSignal.timeout` / `timeout` options) | automatic | 🟡 Medium | C9.1 |
| 10 | Kill switch — `AbortController` / `AbortSignal` presence | automatic | 🟠 High | C9.5 |
| 11 | Sandbox isolation signals (bwrap / sandbox manager) | automatic | 🟡 Medium | C4.1 |
| 12 | Input validation / schema signals | automatic | 🟠 High | C2.1 |
| 13 | Token budget constants (`MAX_*_TOKENS` / cost limits) | semi-automatic | 🟠 High | C9.1 |
| 14 | Audit logging / telemetry endpoints | semi-automatic | 🟡 Medium | C12.1 |
| 15 | Supply chain / vendor SBOM (native artifacts, vendor versions) | semi-automatic | 🟡 Medium | C6.1 |
| 16 | Error handling / retry / fallback | semi-automatic | 🟡 Medium | C12.2 |
| 17 | Output truncation / filtering | semi-automatic | 🟡 Medium | C7.1 |

The free-tier daily scan allowance applies to bundle scans too (counted the same way as config scans); a Pro license removes the limit. License verification runs sub-millisecond on the core verification hot path.

## CI/CD Integration

### GitHub Actions

```yaml
- uses: DSHCorrectover/correctover-scan-action@v1
  with:
    path: ./mcp.json
```

### Web Scanner

Try the online version: [correctover.com/scan](https://correctover.com/scan/)

## Standards Compliance

- **OWASP AISVS 1.0** — AI System Vulnerability Severity
- **GB/T《智能体应用安全基本要求》** — Chinese National Mandatory Standard

## Manual audit

The free automated scan covers surface-level configuration checks. A manual Correctover audit goes deeper:

- **116-check manual audit methodology** — reviewers trace what each MCP tool can actually be made to do, not just whether a config field is present
- Findings grounded in **real MCP ecosystem CVEs**
- **5-day turnaround**, delivered as a PDF report with recommended fixes
- A **free 1-page summary** of your configuration first — you decide whether to continue after reading it

For first customers, if the manual audit finds no critical-severity issue, you pay nothing.

- Get your free 1-page summary: email [234114134@coze.email](mailto:234114134@coze.email?subject=Free%20audit%20scan%20summary)
- Learn more about the manual audit: https://correctover.com/agent-audit.html

## Links

- [correctover.com](https://correctover.com) — AI Agent Runtime Assurance
- [CCS Standard](https://correctover.com/ccs) — Conformance Specification
- [Web Scanner](https://correctover.com/scan/) — Online version
- [GitHub](https://github.com/DSHCorrectover) — Source code
- [Conformance test vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors) — 66 signed, reproducible
- [EMILIA interoperability](https://github.com/emiliaprotocol/emilia-protocol/pull/693) — merged joint assessment
- [Framework paper (Zenodo)](https://doi.org/10.5281/zenodo.21783723) — DOI 10.5281/zenodo.21783723
- [Agent Output Audit](https://correctover.com/agent-audit.html) — 116-check manual audit, 5-day turnaround

## Specification

CCS (Correctover Conformance Shape) is published as an individual Internet-Draft: **[draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/)**.

An Internet-Draft is an individual submission. It is not an RFC, an adopted working-group item, or IETF endorsement; the Datatracker page is authoritative for revision and status.

## License

MIT © Correctover

