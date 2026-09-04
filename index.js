#!/usr/bin/env node
/**
 * correctover-scan — CCS Security Scanner for MCP Configurations
 * Usage: npx correctover-scan [config-file] [options]
 * 
 * Scans MCP configuration files for security issues.
 * Maps to OWASP AISVS 1.0 and Chinese National Standard《智能体应用安全基本要求》
 */

const fs = require('fs');
const path = require('path');
const { runScan, parseConfig, KNOWN_CONFIG_PATHS } = require('./core/scanner');
const { runBundleScan, discoverBundleFiles } = require('./core/bundle-scanner');
const { recordCall, getUpgradeMessage } = require('./core/license');
const { formatHTMLReport, normalizeConfigFindings, normalizeBundleFindings, failHint } = require('./core/report');

const VERSION = '1.7.3';
const PRODUCT = 'correctover-scan';
const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.ts']);

// Colors
const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m',
  cyan: '\x1b[36m', white: '\x1b[37m', gray: '\x1b[90m',
  bgRed: '\x1b[41m', bgGreen: '\x1b[42m', bgYellow: '\x1b[43m',
};

const icons = { pass: '✅', warn: '⚠️', fail: '❌', info: 'ℹ️' };
const sevColors = { critical: c.red, high: c.yellow, medium: c.cyan, low: c.gray };
const sevLabels = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

function printBanner(stream) {
  const out = stream === 'stderr' ? console.error : console.log;
  out(`
${c.bold}${c.blue}  ╔══════════════════════════════════════════╗
  ║   CCS Security Scanner by Correctover    ║
  ║   AI Agent Runtime Assurance             ║
  ╚══════════════════════════════════════════╝${c.reset}
  ${c.dim}v${VERSION} | OWASP AISVS 1.0 | 14 checks · MCP config + JS bundle modes${c.reset}
`);
}

function findConfigFiles(dir) {
  const found = [];
  for (const relPath of KNOWN_CONFIG_PATHS) {
    const fullPath = path.resolve(dir, relPath);
    if (fs.existsSync(fullPath)) {
      found.push(fullPath);
    }
  }
  // Also scan for any mcp*.json or mcp*.yaml in common locations
  const scanDirs = ['.', '.cursor', '.claude', '.vscode', '.mcp', 'config'];
  for (const d of scanDirs) {
    const dirPath = path.resolve(dir, d);
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      try {
        const files = fs.readdirSync(dirPath);
        for (const f of files) {
          if (/^mcp[_-]?.*\.(json|yaml|yml)$/.test(f)) {
            const fp = path.join(dirPath, f);
            if (!found.includes(fp)) found.push(fp);
          }
        }
      } catch (e) {}
    }
  }
  return found;
}

function formatResults(results, stats, filename) {
  const lines = [];
  
  // File header
  lines.push(`${c.bold}📄 ${filename}${c.reset}`);
  lines.push('─'.repeat(50));

  // Score
  const scoreColor = stats.score >= 80 ? c.green : stats.score >= 60 ? c.yellow : c.red;
  lines.push(`\n${c.bold}Security Score: ${scoreColor}${c.bold}${stats.score}/100${c.reset}`);
  lines.push(`  ${c.green}✓ ${stats.pass} passed${c.reset}  ${c.yellow}⚠ ${stats.warn} warnings${c.reset}  ${c.red}✗ ${stats.fail} critical${c.reset}  ${c.blue}ℹ ${stats.info} info${c.reset}\n`);

  // Group by category
  const categories = {};
  for (const r of results) {
    if (!categories[r.category]) categories[r.category] = [];
    categories[r.category].push(r);
  }

  for (const [cat, checks] of Object.entries(categories)) {
    lines.push(`${c.dim}── ${cat} ──${c.reset}`);
    for (const r of checks) {
      const icon = icons[r.status];
      const sevColor = sevColors[r.severity];
      const sevLabel = sevLabels[r.severity];
      const statusStr = r.status === 'pass' ? c.green + 'PASS' : r.status === 'fail' ? c.red + 'FAIL' : r.status === 'warn' ? c.yellow + 'WARN' : c.blue + 'INFO';
      lines.push(`  ${icon} ${r.name} ${c.reset}[${statusStr}${c.reset}] ${c.dim}${r.aisvs}${c.reset}`);
    }
    lines.push('');
  }

  // Recommendations
  const issues = results.filter(r => r.status === 'fail' || r.status === 'warn');
  if (issues.length > 0) {
    lines.push(`${c.bold}${c.yellow}Recommendations:${c.reset}\n`);
    for (const r of issues) {
      const icon = r.status === 'fail' ? '🔴' : '🟡';
      lines.push(`  ${icon} ${c.bold}${r.name}${c.reset}`);
      lines.push(`     ${c.gray}${r.fix}${c.reset}\n`);
    }
  } else {
    lines.push(`${c.green}${c.bold}🎉 All checks passed! Your MCP configuration is secure.${c.reset}\n`);
  }

  // CTA
  lines.push('');
  lines.push(`${c.dim}── Upgrade ─────────────────────────────────${c.reset}`);
  if (stats.fail > 0 || stats.score < 60) {
    lines.push(`${c.yellow}${c.bold}⚡ Score too low? CCS Pro generates formal compliance reports.${c.reset}`);
    lines.push(`${c.dim}   Enterprise: real-time runtime protection + Token guarantee${c.reset}`);
    lines.push(`${c.cyan}   → Upgrade: https://correctover.com/checkout${c.reset}`);
  } else {
    lines.push(`${c.green}✓ Good score! Get a formal compliance certificate with CCS Pro.${c.reset}`);
    lines.push(`${c.dim}  Audit reports · Team dashboard · Custom rules · SOC 2 ready${c.reset}`);
    lines.push(`${c.cyan}  → https://correctover.com/checkout${c.reset}`);
  }
  lines.push(`${c.dim}Enterprise: runtime SDK + Token guarantee → https://correctover.com${c.reset}`);
  lines.push('');
  lines.push(`${c.dim}Web: https://correctover.com/scan/ | GitHub: https://github.com/DSHCorrectover${c.reset}`);

  // Manual audit CTA
  lines.push('');
  lines.push(`${c.dim}Free automated scan covers surface-level checks. A manual Correctover audit goes deeper: 116 semantic intent rules, 5-day turnaround, findings grounded in real MCP ecosystem CVEs. First customers: if we find no critical-severity issue, you pay nothing. \u2192 ${c.cyan}https://dshcorrectover.github.io/agent-audit/${c.reset}`);

  return lines.join('\n');
}

/* ------------------------------------------------------------------ */
/* Bundle mode output                                                  */
/* ------------------------------------------------------------------ */

function formatBundleResults(bundle, baseLabel) {
  const lines = [];
  const stats = bundle.stats;
  lines.push(`${c.bold}📦 Bundle/code scan: ${baseLabel}${c.reset}`);
  lines.push(`  ${c.dim}files: ${bundle.files.length} · code-layer checks: ${bundle.checks.length} (12 automatic verdicts + 5 semi-automatic signal enums; check ids continue the 14-check config scheme)${c.reset}`);
  lines.push('─'.repeat(50));

  const scoreColor = stats.score >= 80 ? c.green : stats.score >= 60 ? c.yellow : c.red;
  lines.push(`\n${c.bold}Security Score: ${scoreColor}${c.bold}${stats.score}/100${c.reset}`);
  lines.push(`  ${c.green}✓ ${stats.pass} checks passed${c.reset}  ${c.yellow}⚠ ${stats.warn} checks with warnings${c.reset}  ${c.red}✗ ${stats.fail} checks with critical findings${c.reset}  ${c.blue}ℹ ${stats.info} checks info-only${c.reset}`);
  lines.push(`  ${c.dim}findings: ${stats.findings.fail} fail · ${stats.findings.warn} warn · ${stats.findings.info} info · ${stats.findings.suppressed} suppressed by context heuristics${c.reset}\n`);

  for (const fr of bundle.files) {
    const active = [];
    const suppressedCount = fr.results.reduce((n, r) => n + r.findings.filter(f => f.suppressed).length, 0);
    for (const r of fr.results) {
      for (const f of r.findings) {
        if (!f.suppressed) active.push({ check: r, f });
      }
    }
    if (active.length === 0) {
      lines.push(`${c.green}✅ ${fr.file} — no fail/warn findings (${suppressedCount} known-benign signals suppressed, see JSON for detail)${c.reset}\n`);
      continue;
    }
    lines.push(`${c.bold}📄 ${fr.file}${c.reset}`);
    for (const { check, f } of active) {
      const icon = icons[f.severity === 'fail' ? 'fail' : f.severity === 'warn' ? 'warn' : 'info'];
      const statusStr = f.severity === 'fail' ? c.red + 'FAIL' : f.severity === 'warn' ? c.yellow + 'WARN' : c.blue + 'INFO';
      lines.push(`  ${icon} ${c.dim}[${check.id} · ${check.aisvs}]${c.reset} ${statusStr}${c.reset} ${c.bold}L${f.line}${c.reset}`);
      lines.push(`     ${f.message}`);
      if (f.snippet) lines.push(`     ${c.gray}${f.snippet}${c.reset}`);
      lines.push('');
    }
  }

  // Semi-automatic checks summary
  const semiIds = ['budget-limit', 'logging', 'version-pin', 'error-handling', 'output-validation'];
  lines.push(`${c.dim}── Semi-automatic checks (signals enumerated; conclusion needs manual review) ──${c.reset}`);
  for (const id of semiIds) {
    let n = 0;
    for (const fr of bundle.files) {
      const r = fr.results.find(x => x.id === id);
      if (r) n += r.findings.length;
    }
    lines.push(`  ${c.blue}ℹ${c.reset} ${c.dim}${id}: ${n} signal(s) listed in JSON output${c.reset}`);
  }

  lines.push('');
  lines.push(`${c.dim}Note: bundle mode is signal scanning over published/minified code. It locates every${c.reset}`);
  lines.push(`${c.dim}risk-bearing string/API call with file+line; it does not prove reachability or intent —${c.reset}`);
  lines.push(`${c.dim}fail/warn items and the semi-automatic signals are the input for manual deep review.${c.reset}`);

  lines.push('');
  lines.push(`${c.dim}── Upgrade ─────────────────────────────────${c.reset}`);
  if (stats.fail > 0 || stats.score < 60) {
    lines.push(`${c.yellow}${c.bold}⚡ Critical findings present. CCS Pro generates formal compliance reports.${c.reset}`);
    lines.push(`${c.dim}   Enterprise: real-time runtime protection + Token guarantee${c.reset}`);
    lines.push(`${c.cyan}   → Upgrade: https://correctover.com/checkout${c.reset}`);
  } else {
    lines.push(`${c.green}✓ No critical signals! Get a formal compliance certificate with CCS Pro.${c.reset}`);
    lines.push(`${c.cyan}  → https://correctover.com/checkout${c.reset}`);
  }
  lines.push(`${c.dim}Manual bundle audit (116-rule deep review): https://dshcorrectover.github.io/agent-audit/${c.reset}`);
  lines.push('');
  lines.push(`${c.dim}Web: https://correctover.com/scan/ | GitHub: https://github.com/DSHCorrectover${c.reset}`);
  return lines.join('\n');
}

function formatBundleJSON(bundle, target) {
  return JSON.stringify({
    scanner: 'correctover-scan', version: VERSION, mode: 'bundle', target,
    stats: bundle.stats,
    files: bundle.files.map(fr => ({
      file: fr.file,
      results: fr.results.map(r => ({
        id: r.id, name: r.name, category: r.category, aisvs: r.aisvs,
        severity: r.severity, status: r.status, fix: r.fix,
        findings: r.findings.map(f => ({ line: f.line, severity: f.severity, suppressed: f.suppressed, message: f.message, snippet: f.snippet })),
      })),
    })),
  }, null, 2);
}

function formatBundleSARIF(bundle, target) {
  const rules = [];
  const results = [];
  for (const fr of bundle.files) {
    for (const r of fr.results) {
      if (!rules.some(x => x.id === r.id)) {
        rules.push({
          id: r.id, name: r.name,
          shortDescription: { text: `${r.category}: ${r.name}` },
          helpUri: `https://correctover.com/scan/#check-${r.id}`,
          properties: { aisvs: r.aisvs, severity: r.severity, mode: 'bundle' },
        });
      }
      for (const f of r.findings) {
        if (f.suppressed || f.severity === 'info') continue;
        results.push({
          ruleId: r.id,
          level: f.severity === 'fail' ? 'error' : 'warning',
          message: { text: f.message },
          locations: [{ physicalLocation: {
            artifactLocation: { uri: fr.file },
            region: f.line ? { startLine: f.line } : undefined,
          } }],
        });
      }
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'correctover-scan', version: VERSION, informationUri: 'https://correctover.com', rules } },
      results,
    }],
  };
}

function formatSARIF(results, filename) {
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'correctover-scan',
          version: VERSION,
          informationUri: 'https://correctover.com',
          rules: results.map(r => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: `${r.category}: ${r.name}` },
            helpUri: `https://correctover.com/scan/#check-${r.id}`,
            properties: { aisvs: r.aisvs, severity: r.severity }
          }))
        }
      },
      results: results.filter(r => r.status === 'fail' || r.status === 'warn').map(r => ({
        ruleId: r.id,
        level: r.status === 'fail' ? 'error' : 'warning',
        message: { text: r.fix },
        locations: [{ physicalLocation: { artifactLocation: { uri: filename } } }]
      }))
    }]
  };
}

function formatJSON(results, stats, filename) {
  return JSON.stringify({ scanner: 'correctover-scan', version: VERSION, file: filename, stats, results }, null, 2);
}

/* ------------------------------------------------------------------ */
/* HTML shareable report (verification-as-acquisition funnel)          */
/* ------------------------------------------------------------------ */

function defaultReportPath() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const base = `correctover-scan-report-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
  let p = path.join(process.cwd(), `${base}.html`);
  let n = 2;
  while (fs.existsSync(p)) p = path.join(process.cwd(), `${base}-${n++}.html`);
  return p;
}

function runBundleMode(target, format, outFile) {
  // All diagnostics/banners go to stderr so that stdout carries only the
  // machine-readable payload for json/sarif consumers.
  const diag = (...a) => console.error(...a);
  printBanner(format === 'text' && !outFile ? 'stdout' : 'stderr');

  // License check (same 50/day free tier counting as config mode)
  const status = recordCall(PRODUCT);
  if (!status.authorized) {
    diag(getUpgradeMessage(status));
    process.exit(1);
  }
  if (status.tier === 'free') {
    diag(`${c.dim}📊 Free tier: ${status.calls_remaining} scans remaining today (${status.calls_today}/${status.limit})${c.reset}`);
    diag(`${c.dim}   Upgrade: https://correctover.com/checkout${c.reset}\n`);
  } else if (status.tier === 'pro') {
    diag(`${c.green}✅ Pro license active — unlimited scans${c.reset}\n`);
  }

  if (!fs.existsSync(target)) {
    diag(`${c.red}Error: path not found: ${target}${c.reset}`);
    process.exit(1);
  }

  const abs = path.resolve(target);
  const isDir = fs.statSync(abs).isDirectory();
  const baseDir = isDir ? abs : path.dirname(abs);
  let files;
  try {
    files = discoverBundleFiles(abs);
  } catch (e) {
    diag(`${c.red}Error discovering bundle files: ${e.message}${c.reset}`);
    process.exit(1);
  }
  if (files.length === 0) {
    diag(`${c.yellow}No JavaScript files (.js/.mjs/.cjs) found under ${target}.${c.reset}`);
    process.exit(0);
  }
  diag(`${c.dim}Bundle mode: ${files.length} JS file(s) under ${target}${c.reset}\n`);

  const bundle = runBundleScan(files, baseDir);
  const label = path.relative(process.cwd(), abs) || abs;

  let payload;
  let htmlDefault = false;
  if (format === 'json') {
    payload = formatBundleJSON(bundle, label);
  } else if (format === 'sarif') {
    payload = JSON.stringify(formatBundleSARIF(bundle, label), null, 2);
  } else if (format === 'html') {
    const labelCounts = {
      pass: bundle.stats.pass, warn: bundle.stats.warn, fail: bundle.stats.fail, info: bundle.stats.info,
      score: bundle.stats.score,
    };
    payload = formatHTMLReport({
      mode: 'bundle/code scan', target: label,
      items: normalizeBundleFindings(bundle), totals: labelCounts,
      checksLabel: '12 automatic + 5 semi-automatic code-layer checks',
      version: VERSION,
    });
    if (!outFile) { outFile = defaultReportPath(); htmlDefault = true; }
  } else {
    payload = formatBundleResults(bundle, label);
  }
  if (outFile) {
    try {
      fs.writeFileSync(outFile, payload + '\n');
      diag(`${c.green}✅ Report written to ${outFile}${c.reset}`);
      if (htmlDefault) {
        diag(`${c.dim}Shareable HTML report — forward it to your team. ${failHint(bundle.stats.findings.fail)}${c.reset}`);
      }
    } catch (e) {
      console.error(`${c.red}Error writing output file: ${e.message}${c.reset}`);
      process.exit(1);
    }
  } else {
    console.log(payload);
  }

  // Exit code: 1 if any check has fail-level findings
  if (bundle.stats.findings.fail > 0) process.exit(1);
}

function main() {
  const args = process.argv.slice(2);
  let configPath = null;
  let bundlePath = null;
  let format = 'text'; // text, json, sarif
  let scanDir = process.cwd();
  let recursive = false;
  let outFile = null;

  // Parse args
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--version' || arg === '-v') {
      console.log(`correctover-scan v${VERSION}`);
      process.exit(0);
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Usage: correctover-scan [target] [options]

MCP config mode (default for .json/.yaml/mcp.json):
  correctover-scan mcp.json                    Scan a specific MCP config
  correctover-scan -d ./project                Auto-detect configs in directory
  correctover-scan -d ./project -r             Recursively find config files

Bundle / published-package code mode (v1.4.0+):
  correctover-scan --bundle ./pkg              Audit an unpacked npm package
                                               (reads package.json entry + all .js/.mjs/.cjs)
  correctover-scan --bundle dist/app.min.js    Audit a single minified/bundled JS file
  correctover-scan ./cli.js                    Auto-detected: .js/.mjs/.cjs target → bundle mode
  correctover-scan --bundle ./pkg -f sarif     SARIF with file+line locations

Options:
  --bundle <path>       Explicitly run bundle/code scan on a JS file or directory
  -f, --format <type>   Output format: text, json, sarif, html (default: text)
                        html writes a self-contained shareable report file
                        (correctover-scan-report-<date>.html if no -o given)
  -d, --dir <path>      Directory to scan for MCP configs (default: cwd)
  -r, --recursive       Recursively find MCP config files
  -o, --output <file>   Write the report to a file (text/json/sarif) instead of stdout
  -v, --version         Show version
  -h, --help            Show this help

Bundle mode performs signal scanning of shipped/minified code (hardcoded secrets,
plaintext endpoints, cloud metadata/SSRF, shell:true/exec, eval/Function/vm, env
credential flow, permission gates, MCP transport auth, timeouts, kill switch,
sandbox, input validation) with context-based false-positive suppression. It
locates signals at file+line; reachability/intent conclusions need manual review.

Examples:
  npx correctover-scan                         Auto-detect MCP configs in cwd
  npx correctover-scan --bundle .              Audit the current package's code
`);
      process.exit(0);
    } else if (arg === '--format' || arg === '-f') {
      format = args[++i];
    } else if (arg === '--dir' || arg === '-d') {
      scanDir = args[++i];
    } else if (arg === '--recursive' || arg === '-r') {
      recursive = true;
    } else if (arg === '--bundle' || arg === '-b') {
      bundlePath = args[++i];
    } else if (arg === '--output' || arg === '-o') {
      outFile = args[++i] || null;
    } else if (!arg.startsWith('-')) {
      configPath = arg;
    }
  }

  // Auto-detect bundle mode: positional .js/.mjs/.cjs file, or a directory
  // that contains JS but no MCP config and looks like a package.
  if (!bundlePath && configPath && fs.existsSync(configPath)) {
    const st = fs.statSync(configPath);
    if (st.isFile() && JS_EXT.has(path.extname(configPath).toLowerCase())) {
      bundlePath = configPath;
      configPath = null;
    } else if (st.isDirectory() && !configPath.endsWith('.json')) {
      // directory positional: prefer config mode only if a known config exists
      const hasConfig = KNOWN_CONFIG_PATHS.some(rel => fs.existsSync(path.join(configPath, rel)));
      if (!hasConfig) {
        let hasJS = false;
        try { hasJS = fs.readdirSync(configPath).some(f => JS_EXT.has(path.extname(f).toLowerCase())); } catch (e) {}
        if (hasJS || fs.existsSync(path.join(configPath, 'package.json'))) {
          bundlePath = configPath;
          configPath = null;
        }
      }
    }
  }

  if (bundlePath) {
    return runBundleMode(bundlePath, format, outFile);
  }

  // In json/sarif mode all diagnostics go to stderr, keeping stdout clean.
  const diag = (format === 'text' && !outFile) ? console.log : (...a) => console.error(...a);
  printBanner(format === 'text' && !outFile ? 'stdout' : 'stderr');

  // Text-mode payload buffer: when -o writes a report file, the report text is
  // collected instead of being streamed to stdout (diagnostics stay on stderr).
  const textBuffer = outFile ? [] : null;
  const emit = textBuffer ? (s) => textBuffer.push(s) : (s) => console.log(s);

  // License check
  const status = recordCall(PRODUCT);
  if (!status.authorized) {
    diag(getUpgradeMessage(status));
    process.exit(1);
  }
  if (status.tier === 'free') {
    diag(`${c.dim}📊 Free tier: ${status.calls_remaining} scans remaining today (${status.calls_today}/${status.limit})${c.reset}`);
    diag(`${c.dim}   Upgrade: https://correctover.com/checkout${c.reset}\n`);
  } else if (status.tier === 'pro') {
    diag(`${c.green}✅ Pro license active — unlimited scans${c.reset}\n`);
  }

  const filesToScan = [];

  if (configPath) {
    // Specific file
    if (!fs.existsSync(configPath)) {
      console.error(`${c.red}Error: File not found: ${configPath}${c.reset}`);
      process.exit(1);
    }
    filesToScan.push(configPath);
  } else {
    // Auto-detect
    diag(`${c.dim}Auto-detecting MCP configs in ${scanDir}...${c.reset}\n`);
    const found = findConfigFiles(scanDir);
    if (recursive) {
      // Walk directory tree
      function walkDir(dir) {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.name.startsWith('.') && entry.name !== '.cursor' && entry.name !== '.claude' && entry.name !== '.vscode' && entry.name !== '.mcp') continue;
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory() && entry.name !== 'node_modules') {
              walkDir(fullPath);
            } else if (entry.isFile() && /mcp[_-]?.*\.(json|yaml|yml)$/.test(entry.name)) {
              if (!found.includes(fullPath)) found.push(fullPath);
            }
          }
        } catch (e) {}
      }
      walkDir(scanDir);
    }
    filesToScan.push(...found);
  }

  if (filesToScan.length === 0) {
    diag(`${c.yellow}No MCP configuration files found.${c.reset}`);
    diag(`${c.dim}Searched paths: ${KNOWN_CONFIG_PATHS.join(', ')}${c.reset}`);
    diag(`\n${c.dim}Config mode: correctover-scan path/to/mcp.json${c.reset}`);
    const cwdHasPkg = fs.existsSync(path.join(scanDir, 'package.json'));
    if (cwdHasPkg) {
      diag(`${c.cyan}Detected package.json here — audit published/bundled code with: correctover-scan --bundle ${scanDir}${c.reset}`);
    } else {
      diag(`${c.dim}Audit an npm package / JS bundle instead: correctover-scan --bundle <path-to-package-or-js>${c.reset}`);
    }
    process.exit(0);
  }

  diag(`${c.dim}Found ${filesToScan.length} config file(s)${c.reset}\n`);

  let totalPass = 0, totalWarn = 0, totalFail = 0, totalInfo = 0;
  let allResults = [];

  for (const fp of filesToScan) {
    try {
      const content = fs.readFileSync(fp, 'utf-8');
      const config = parseConfig(content, fp);
      const { results, stats } = runScan(config);
      const relPath = path.relative(process.cwd(), fp) || fp;

      if (format === 'text') {
        emit(formatResults(results, stats, relPath));
        emit('');
      }

      totalPass += stats.pass;
      totalWarn += stats.warn;
      totalFail += stats.fail;
      totalInfo += stats.info;
      allResults.push({ file: relPath, results, stats });
    } catch (e) {
      console.error(`${c.red}Error scanning ${fp}: ${e.message}${c.reset}\n`);
    }
  }

  // JSON/SARIF/HTML output
  let machinePayload = null;
  let htmlDefault = false;
  if (format === 'json') {
    const output = allResults.map(r => formatJSON(r.results, r.stats, r.file));
    machinePayload = output.join('\n');
  } else if (format === 'sarif') {
    const sarifResults = allResults.map(r => formatSARIF(r.results, r.file));
    machinePayload = JSON.stringify(sarifResults.length === 1 ? sarifResults[0] : { runs: sarifResults.flatMap(s => s.runs) }, null, 2);
  } else if (format === 'html') {
    const totals = { pass: totalPass, warn: totalWarn, fail: totalFail, info: totalInfo };
    const denom = (totalPass + totalWarn + totalFail + totalInfo) * 10;
    totals.score = denom === 0 ? 100 : Math.round(((totalPass * 10 + totalWarn * 5 + totalInfo * 7) / denom) * 100);
    machinePayload = formatHTMLReport({
      mode: 'MCP config scan',
      target: filesToScan.length === 1 ? path.relative(process.cwd(), filesToScan[0]) || filesToScan[0] : `${filesToScan.length} config file(s)`,
      items: normalizeConfigFindings(allResults), totals,
      checksLabel: '14 config checks mapped to OWASP AISVS 1.0',
      version: VERSION,
    });
    if (!outFile) { outFile = defaultReportPath(); htmlDefault = true; }
  }

  // Summary
  if (filesToScan.length > 1 && format === 'text') {
    const totalScore = Math.round(((totalPass * 10 + totalWarn * 5 + totalInfo * 7) / ((totalPass + totalWarn + totalFail + totalInfo) * 10)) * 100);
    emit(`${c.bold}═══ Summary ═══${c.reset}`);
    emit(`  Files scanned: ${filesToScan.length}`);
    emit(`  Total score: ${totalScore}/100`);
    emit(`  ${c.green}✓ ${totalPass}${c.reset}  ${c.yellow}⚠ ${totalWarn}${c.reset}  ${c.red}✗ ${totalFail}${c.reset}  ${c.blue}ℹ ${totalInfo}${c.reset}`);
  }

  // -o: write the report payload to a file; otherwise stream to stdout
  if (outFile) {
    const payload = machinePayload || textBuffer.join('\n');
    try {
      fs.writeFileSync(outFile, payload + '\n');
      diag(`${c.green}✅ Report written to ${outFile}${c.reset}`);
      if (htmlDefault) {
        diag(`${c.dim}Shareable HTML report — forward it to your team. ${failHint(totalFail)}${c.reset}`);
      }
    } catch (e) {
      console.error(`${c.red}Error writing output file: ${e.message}${c.reset}`);
      process.exit(1);
    }
  } else if (machinePayload) {
    console.log(machinePayload);
  }

  // Exit code: 1 if any critical failures
  if (totalFail > 0) process.exit(1);
}

main();
