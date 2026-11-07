# correctover-scan

[![Rekor anchored](https://img.shields.io/badge/Rekor%20anchored-logIndex%202697131671-1455A3)](https://search.sigstore.dev/?logIndex=2697131671)
![npm](https://img.shields.io/npm/v/correctover-scan)
![license](https://img.shields.io/npm/l/correctover-scan)
[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)
[![Security Score](https://img.shields.io/badge/Security%20Score-76%2F100-orange)](https://github.com/DSHCorrectover/correctover-scan/blob/main/CORRECTOVER_SELF_AUDIT_REPORT.md)
[![Weekly Self-Audit](https://img.shields.io/badge/Self--Audit-Passing-green)](https://github.com/DSHCorrectover/correctover-scan/blob/main/CORRECTOVER_SELF_AUDIT_REPORT.md)

> **CCS-aligned** security scanner for MCP servers and AI agents ([IETF draft-correctover-ccs](https://datatracker.ietf.org/doc/draft-correctover-ccs/)). Credential exposure, SSRF, command-injection risk, missing auth. **14 checks → OWASP AISVS 1.0.** Zero install: `npx correctover-scan`.

### 🔒 We Practice What We Preach

**We scan our own code with correctover-scan every week.** Latest self-audit found real vulnerabilities (SSRF, missing input validation) — and we fixed them publicly. [Read our self-audit report →](https://github.com/DSHCorrectover/correctover-scan/blob/main/CORRECTOVER_SELF_AUDIT_REPORT.md)

**Current Security Score: 76/100** (improving weekly, target: 95+/100)

---

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
| Ecosystem data | [mcp-atlas-census](https://github.com/DSHCorrectover/mcp-atlas-census) | 229,827 tools with schema (CC0) |

Scanners do not stop a live `curl|sh`. Runtime guards do not replace a full config audit. Use both.

## ⚡ Quick Start — 30 seconds

```bash
npx correctover-scan@latest
```

Auto-detects `.cursor/mcp.json`, `claude_desktop_config.json`, `.claude/mcp.json`, `mcp.json`, `.vscode/mcp.json`, and more. Local only — configs are not uploaded.
