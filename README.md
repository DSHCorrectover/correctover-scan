# correctover-scan

[![Rekor anchored](https://img.shields.io/badge/Rekor%20anchored-logIndex%202697131671-1455A3)](https://search.sigstore.dev/?logIndex=2697131671)
![npm](https://img.shields.io/npm/v/correctover-scan)
![license](https://img.shields.io/npm/l/correctover-scan)
[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)

> **CCS-aligned** security scanner for MCP servers and AI agents ([IETF draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/)). Credential exposure, SSRF, command-injection risk, missing auth. **14 checks → OWASP AISVS 1.0.** Zero install: `npx correctover-scan`.

**Scan finds risk in config. Runtime blocks the call.**  
After scanning, put enforcement on the path:

```bash
npx -y agent-runtime-guard   # fail-closed tool-call intercept + Ed25519 receipts
```

→ [agent-runtime-guard](https://github.com/DSHCorrectover/agent-runtime-guard) · [COMPARE.md](https://github.com/DSHCorrectover/agent-runtime-guard/blob/main/COMPARE.md)

---

### Verifiable artifacts behind this tool

- **Third-party interoperability** — joint assessment merged into the [EMILIA protocol](https://github.com/emiliaprotocol/emilia-protocol/pull/693)
- **66 signed conformance test vectors** — [ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors)
- **Published methodology** — [Zenodo DOI 10.5281/zenodo.21783723](https://doi.org/10.5281/zenodo.21783723)
- **Human audit** — 116-check methodology: [Agent Output Audit](https://correctover.com/agent-audit.html)

`correctover-scan` audits MCP configuration used by Claude Code, Claude Desktop, Cursor, VS Code and other agents. It flags credential leaks, SSRF exposure, missing TLS, over-broad tools and related issues — the config problems that become RCE, exfil and injection paths. Runs locally (no upload), CI-friendly, SARIF for GitHub code scanning.

**v1.4.0** adds `--bundle` mode: signal scanning over published npm packages and minified JS (17 checks, file+line findings).

## Where it sits (vs other tools)

| Layer | Tool | Job |
|-------|------|-----|
| Config scan (this repo) | **correctover-scan** | Find risky MCP / agent config before runtime |
| Runtime intercept | [agent-runtime-guard](https://github.com/DSHCorrectover/agent-runtime-guard) | Block *this* tool call; emit receipt |
| Egress firewall | Pipelock-class | Mediate outbound network |
| Discovery / posture | Reco / Pluto-class | Inventory agents & permissions |
| Ecosystem data | [m[m[mcp-atlas-census](https://github.com/DSHCorrectover/mcp-atlas-census) | 229,827 tools with schema (CC0) |

Scanners do not stop a live `curl|sh`. Runtime guards do not replace a full config audit. Use both.

## ⚡ Quick Start — 30 seconds

```bash
npx correctover-scan@latest
```

Auto-detects `.cursor/mcp.json`, `claude_desktop_config.json`, `.claude/mcp.json`, `mcp.json`, `.vscode/mcp.json`, and more. Local only — configs are not uploaded.

```bash
npx correctover-scan mcp.json
npx correctover-scan -d ./my-project -r
npx correctover-scan mcp.json -f sarif > report.sarif
npx correctover-scan --demo
```

## What It Checks (config mode, 14)

| # | Check | Severity | AISVS |
|---|-------|----------|-------|
| 1 | TLS Transport Encryption | Critical | C10.1 |
| 2 | Server Authentication | High | C10.2 |
| 3 | Timeout Configuration | Medium | C9.1 |
| 4 | Credential Exposure | Critical | C5.1 |
| 5 | Tool Allowlist | High | C9.3 |
| 6 | Token Budget Control | High | C9.1 |
| 7 | SSRF Protection | Critical | C10.3 |
| 8 | Audit Logging | Medium | C12.1 |
| 9 | Sandbox Isolation | Medium | C4.1 |
| 10 | Dependency Version Pinning | Medium | C6.1 |
| 11 | Error Handling Strategy | Medium | C12.2 |
| 12 | Input Validation | High | C2.1 |
| 13 | Output Validation | Medium | C7.1 |
| 14 | Kill Switch | High | C9.5 |

## Output formats

```bash
correctover-scan mcp.json
correctover-scan mcp.json -f json
correctover-scan mcp.json -f sarif > report.sarif
```

## Supported config files

- `.cursor/mcp.json`
- `claude_desktop_config.json`
- `.claude/mcp.json`
- `mcp.json` / `mcp.yaml` / `mcp.yml`
- `.vscode/mcp.json`
- `.mcp/mcp.json`
- `config/mcp.json`

## Bundle / published-package scan (v1.4.0)

```bash
npx correctover-scan@latest --bundle ./node_modules/some-pkg
npx correctover-scan@latest -b ./pkg
npx correctover-scan@latest --bundle dist/app.min.js
npx correctover-scan@latest -b ./pkg -f sarif > bundle.sarif
```

Exit code `1` on fail-level findings — CI-ready.

**Honest scope:** signal scanning over shipped/minified JS/TS; not full reachability proof; not a substitute for the 116-check manual audit. Local only — no upload.

| # | Check | Type | Severity |
|---|-------|------|----------|
| 1–12 | Secrets, plaintext HTTP, SSRF/metadata, subprocess, eval/vm, env creds, permission gates, MCP auth, timeout, kill switch, sandbox, input validation | automatic | Crit–Med |
| 13–17 | Token budget, audit/telemetry, SBOM, error/retry, output filter | semi-automatic (signals only) | High–Med |

## CI

```yaml
- uses: DSHCorrectover/correctover-scan-action@v1
  with:
    path: ./mcp.json
```

Browser (no upload): https://correctover.com/scan.html

## Standards

- OWASP AISVS 1.0
- GB/T《智能体应用安全基本要求》
- CCS draft: [draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/) (personal Internet-Draft — not an RFC)

## Manual audit / commercial

Automated scan = surface config. Manual audit = 116 checks, data-flow, 5-day PDF. Free 1-page summary first: wangguigui@correctover.com

## License

MIT © Correctover — free lead-gen CLI. Runtime engine and manual audit products are separate/commercial. See https://correctover.com

## Commercial (overseas)

Scanner is free. Human CCS-mapped audits and private runtime deploy are scoped 1:1 — written quote follows scoping, not listed here. **wangguigui@correctover.com**

**wangguigui@correctover.com** · [GTM](https://correctover-gtm.pages.dev/) · Runtime: [agent-runtime-guard](https://github.com/DSHCorrectover/agent-runtime-guard)
