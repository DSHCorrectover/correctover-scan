/**
 * Correctover CCS Security Scanner — Bundle / published-package code scanner
 * v1.4.0
 *
 * Signal-based static review of minified/bundled JavaScript as shipped in npm
 * packages. Minifiers (esbuild/terser/webpack) rename local variables but keep
 * property names, string literals, URLs, env var names and error messages —
 * the attack-surface signals the 14 CCS/AISVS checks rely on survive bundling.
 *
 * This module does NOT attempt to "understand code intent". Every finding is
 * grounded at file + line with a snippet; context heuristics suppress known
 * benign patterns (e.g. AWS SDK IMDS credential providers) and report them as
 * info. Conclusions on semi-automatic checks remain a manual-review job.
 *
 * Zero runtime dependencies (same constraint as the config scanner).
 */

'use strict';

const fs = require('fs');
const path = require('path');

const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.ts']);
const MAX_SNIPPET = 220;
const MAX_FINDINGS_PER_CHECK = 40;
const WINDOW = 6; // lines of context around a hit for semantic classification

/* ------------------------------------------------------------------ */
/* Lightweight beautifier (no js-beautify dependency)                  */
/* ------------------------------------------------------------------ */

/**
 * Best-effort reformatting of minified JS: inserts newlines after ; { } and
 * before } so that line numbers become useful. Not a parser — the scanner
 * always works on raw text for findings; beautified text is only used to
 * widen semantic context windows.
 */
function beautifySource(src) {
  let out = '';
  let inS = null; // quote char: ' " `
  let inLineComment = false;
  let inBlockComment = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const nxt = src[i + 1];
    if (inLineComment) {
      out += ch;
      if (ch === '\n') inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      out += ch;
      if (ch === '*' && nxt === '/') { out += '/'; i++; inBlockComment = false; }
      continue;
    }
    if (inS) {
      out += ch;
      if (ch === '\\') { out += nxt; i++; continue; }
      if (ch === inS) inS = null;
      continue;
    }
    if (ch === '/' && nxt === '/') { inLineComment = true; out += ch; continue; }
    if (ch === '/' && nxt === '*') { inBlockComment = true; out += ch; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { inS = ch; out += ch; continue; }
    if (ch === ';' || ch === '{' || ch === '}') {
      out += ch + '\n';
      if (ch === '}') out += '\n';
      continue;
    }
    out += ch;
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* File discovery                                                      */
/* ------------------------------------------------------------------ */

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'dist-node-modules']);

/**
 * Build the list of JS files to audit for a bundle target.
 *  - .js/.mjs/.cjs file  -> [that file]
 *  - directory           -> package.json entry (main/module/bin) + all JS
 *                           files in the tree (node_modules skipped), capped.
 */
function discoverBundleFiles(target, opts = {}) {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [path.resolve(target)];

  const files = [];
  const entries = [];
  let pkg = null;
  const pkgPath = path.join(target, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); } catch (e) { pkg = null; }
  }

  function walk(dir, depth) {
    if (depth > (opts.maxDepth ?? 8)) return;
    let names;
    try { names = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const ent of names) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name) || ent.name.startsWith('.')) continue;
        walk(full, depth + 1);
      } else if (ent.isFile() && JS_EXT.has(path.extname(ent.name))) {
        entries.push(full);
      }
    }
  }
  walk(target, 0);

  if (pkg) {
    const candidates = [];
    if (pkg.main) candidates.push(pkg.main);
    if (pkg.module) candidates.push(pkg.module);
    if (typeof pkg.bin === 'string') candidates.push(pkg.bin);
    else if (pkg.bin && typeof pkg.bin === 'object') {
      for (const k of Object.keys(pkg.bin)) candidates.push(pkg.bin[k]);
    }
    for (const c of candidates) {
      const full = path.resolve(target, c);
      if (fs.existsSync(full) && fs.statSync(full).isFile()) files.push(full);
    }
  }
  for (const f of entries) {
    if (!files.includes(f)) files.push(f);
  }
  return files;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function snippet(line) {
  const t = line.trim();
  return t.length > MAX_SNIPPET ? t.slice(0, MAX_SNIPPET) + ' …' : t;
}

function lineWindow(rawLines, idx, radius = WINDOW) {
  const lo = Math.max(0, idx - radius);
  const hi = Math.min(rawLines.length, idx + radius + 1);
  return rawLines.slice(lo, hi).join('\n');
}

function countMatches(re, text) {
  const m = text.match(re);
  return m ? m.length : 0;
}

/** Distinct values of a regex across a text (global regex), with counts. */
function tally(re, text, limit = 60) {
  const map = new Map();
  let m;
  let guard = 0;
  while ((m = re.exec(text)) !== null) {
    const v = m[1] || m[0];
    map.set(v, (map.get(v) || 0) + 1);
    if (++guard > 200000) break;
  }
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([value, n]) => ({ value, count: n }));
}

/* ------------------------------------------------------------------ */
/* Check definitions — ids/names/aisvs continue the config scanner's   */
/* 14-check scheme so text/json/sarif outputs stay aligned.            */
/* ------------------------------------------------------------------ */

const SECRET_PATTERNS = [
  { name: 'OpenAI-style key sk-', re: /\bsk-[A-Za-z0-9_-]{20,}/ },
  { name: 'GitHub token ghp_', re: /\bghp_[A-Za-z0-9]{36}/ },
  { name: 'AWS access key AKIA', re: /\bAKIA[0-9A-Z]{16}/ },
  { name: 'Google API key AIza', re: /\bAIza[0-9A-Za-z_-]{35}/ },
  { name: 'GitHub gho_/github_pat_', re: /\b(?:gho_|github_pat_)[A-Za-z0-9_]{20,}/ },
  { name: 'Slack xox token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
];

// Strings that look like secrets in examples/docs/tests — not real leaks.
const PLACEHOLDER_CTX = /(sk-?your|your-?sk|example|placeholder|xxxx+|<[^>]*>|REDACTED|dummy|fake|sample|test[_-]?key|sk-box-|sk-again-)/i;

// Hosts that routinely appear over http:// but are not plaintext outbound
// traffic (spec namespaces, localhost, placeholders).
const DOC_HOSTS = /^(www\.)?w3\.org$|^(www\.)?json-schema\.org$|^(www\.)?ibm\.com$|^(www\.)?apple\.com$|^schema\./i;
const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)(:\d+)?$/i;
const PLACEHOLDER_HOSTS = /^(www\.)?example\.(com|org|net)$|^dogs\.are\.great$|^x$|^\.$|^foo\.|^bar\./i;
// Cloud metadata endpoints (IPs, IPv6 link-local, GCP hostname) — assessed
// with context by the ssrf check instead of the plain-TLS check.
const METADATA_HOSTS = /metadata\.google(?:\.internal)?|169\.254\.|fd00:ec2/i;

// Context that proves a 169.254/private address is a cloud SDK credential
// provider (normal) rather than business-code SSRF (finding).
const SDK_CTX = /(aws|amazon|ec2|ecs|eks|imds|metadata\s*(service|endpoint|host)|credentialprovider|container\s*credentials|ecr|sts\.)/i;
// Context that proves the address sits inside an SSRF guard / blocklist.
// Actual guard constructs (a bare "ssrf" word in a comment is not a guard).
const GUARD_CTX = /(no_?proxy|blocklist|block_list|denylist|deny_list|allowlist|preflight|isPrivate|private[_-]?ip|loopback|metadata.{0,30}(block|deny|filter|redirect))/i;

const CHECKS = [
  {
    id: 'cred-exposure', category: 'C5 访问控制', name: '硬编码凭证 (code)', severity: 'critical', aisvs: 'C5.1',
    fix: '移除发布包中的硬编码密钥，改用环境变量/密钥管理服务；确认为示例字符串则忽略',
    run: checkHardcodedSecrets,
  },
  {
    id: 'mcp-tls', category: 'C10 MCP安全', name: '明文HTTP出站端点 (code)', severity: 'high', aisvs: 'C10.1',
    fix: '出站端点应使用 https://；http:// 仅允许 localhost/文档命名空间等非传输场景',
    run: checkPlaintextHttp,
  },
  {
    id: 'ssrf-protection', category: 'C10 MCP安全', name: '云元数据/内网地址 (code)', severity: 'critical', aisvs: 'C10.3',
    fix: '业务代码不得直接访问云元数据(169.254.169.254等)或内网地址；需有SSRF预检/白名单',
    run: checkMetadataIntranet,
  },
  {
    id: 'command-exec', category: 'C4 基础设施', name: '子进程执行 shell:true/exec (code)', severity: 'high', aisvs: 'C4.1',
    fix: 'spawn 优先 shell:false + 参数数组；shell:true/exec 路径必须有命令白名单/权限门与转义',
    run: checkCommandExec,
  },
  {
    id: 'dynamic-eval', category: 'C4 基础设施', name: '动态代码执行 eval/Function/vm (code)', severity: 'high', aisvs: 'C4.1',
    fix: '避免 eval/new Function/vm 执行动态字符串；第三方库内的已知用法需人工确认参数不可控',
    run: checkDynamicEval,
  },
  {
    id: 'env-secrets', category: 'C5 访问控制', name: '环境变量与凭证流 (code)', severity: 'medium', aisvs: 'C5.1',
    fix: '凭证类环境变量应仅被读取、不得回退到硬编码默认值或被记录到日志',
    run: checkEnvVars,
  },
  {
    id: 'allowed-tools', category: 'C9 Agent安全', name: '权限模式与工具门 (code)', severity: 'high', aisvs: 'C9.3',
    fix: '保留 allowedTools/disallowedTools 白名单；dangerously-skip-permissions 需有 root/沙箱护栏',
    run: checkPermissionModes,
  },
  {
    id: 'mcp-auth', category: 'C10 MCP安全', name: 'MCP传输鉴权 (code)', severity: 'high', aisvs: 'C10.2',
    fix: '远程 MCP 传输(sse/http/ws)必须注入 Authorization/Bearer 等鉴权头；stdio 本地传输不适用',
    run: checkMcpTransportAuth,
  },
  {
    id: 'mcp-timeout', category: 'C9 Agent安全', name: '超时与中断信号 (code)', severity: 'medium', aisvs: 'C9.1',
    fix: '出站请求/子进程应配置超时（AbortSignal.timeout / timeout 选项）',
    run: checkTimeout,
  },
  {
    id: 'kill-switch', category: 'C9 Agent安全', name: '紧急终止 AbortController (code)', severity: 'high', aisvs: 'C9.5',
    fix: 'fetch/spawn 应贯穿 AbortController/AbortSignal，支持异常时终止',
    run: checkKillSwitch,
  },
  {
    id: 'sandbox', category: 'C4 基础设施', name: '沙箱隔离机制 (code)', severity: 'medium', aisvs: 'C4.1',
    fix: '命令执行应置于沙箱（bwrap/容器）中，文件系统默认只读、网络经代理',
    run: checkSandbox,
  },
  {
    id: 'input-validation', category: 'C2 输入验证', name: '输入校验/Schema (code)', severity: 'high', aisvs: 'C2.1',
    fix: '对外部输入（工具参数/MCP消息/URL）应有 schema 校验或规范化逻辑',
    run: checkInputValidation,
  },
  // --- 半自动检查：信号枚举，结论留给人工深审 ---
  {
    id: 'budget-limit', category: 'C9 Agent安全', name: 'Token预算 (code, 半自动)', severity: 'high', aisvs: 'C9.1',
    fix: '确认 MAX_*_TOKENS/budget 常量被实际强制执行（信号可见，强制语义需人工确认）',
    run: (f) => semiAuto(f, /MAX_[A-Z_]*TOKENS?|token[_-]?budget|cost[_-]?limit|maxOutputTokens/i,
      'token 预算/上限常量', 'budget-limit'),
  },
  {
    id: 'logging', category: 'C12 监控', name: '审计日志/遥测 (code, 半自动)', severity: 'medium', aisvs: 'C12.1',
    fix: '确认日志/遥测端点不携带凭证且敏感字段已脱敏（信号可见，脱敏语义需人工确认）',
    run: (f) => semiAuto(f, /\/metrics|telemetry|audit[_-]?log|claude_cli_feedback|OTEL_|opentelemetry/i,
      '日志/遥测信号', 'logging'),
  },
  {
    id: 'version-pin', category: 'C6 供应链', name: '供应链/Vendor SBOM (code, 半自动)', severity: 'medium', aisvs: 'C6.1',
    fix: '零依赖 bundle 下审计面转为 vendor 件版本（.node/.jar/wasm）；建议人工核对 SBOM',
    run: checkSupplyChain,
  },
  {
    id: 'error-handling', category: 'C12 监控', name: '错误处理/重试 (code, 半自动)', severity: 'medium', aisvs: 'C12.2',
    fix: '确认 retry/fallback 不掩盖安全错误（信号可见，降级语义需人工确认）',
    run: (f) => semiAuto(f, /fallback[_-]?model|retry[A-Z]|backoff|maxRetries/i,
      'retry/fallback 信号', 'error-handling'),
  },
  {
    id: 'output-validation', category: 'C7 输出控制', name: '输出截断/过滤 (code, 半自动)', severity: 'medium', aisvs: 'C7.1',
    fix: '确认输出截断/HTML转换不会丢弃安全相关内容（信号可见，过滤语义需人工确认）',
    run: (f) => semiAuto(f, /content truncated|truncat|turndown|sanitize/i,
      '输出截断/过滤信号', 'output-validation'),
  },
];

function semiAuto(file, re, label, checkId) {
  const findings = [];
  const lineRe = new RegExp(re.source, 'i');
  let firstLine = 0;
  file.lines.forEach((line, i) => { if (!firstLine && lineRe.test(line)) firstLine = i + 1; });
  const hits = tally(new RegExp(re.source, 'gi'), file.text, 12);
  for (const h of hits) {
    findings.push(mkFinding(file, firstLine, 'info', `${label}: "${h.value}" ×${h.count}（半自动：信号在，判定需人工）`, { suppressed: true, checkId }));
  }
  return findings;
}

function mkFinding(file, line, severity, message, extra = {}) {
  return {
    file: file.rel,
    line,
    severity, // fail | warn | info
    suppressed: !!extra.suppressed,
    message,
    snippet: extra.snippet || '',
    checkId: extra.checkId,
  };
}

/* ---- check 1: hardcoded secrets ---- */
function checkHardcodedSecrets(file) {
  const findings = [];
  file.lines.forEach((line, i) => {
    for (const p of SECRET_PATTERNS) {
      const m = line.match(p.re);
      if (!m) continue;
      if (PLACEHOLDER_CTX.test(line)) {
        findings.push(mkFinding(file, i + 1, 'info',
          `${p.name} 模式命中但位于示例/占位上下文（已降噪）: ${m[0].slice(0, 18)}…`,
          { suppressed: true, snippet: snippet(line), checkId: 'cred-exposure' }));
        continue;
      }
      findings.push(mkFinding(file, i + 1, 'fail',
        `${p.name} 疑似硬编码密钥: ${m[0].slice(0, 10)}…（${m[0].length} 字符）`,
        { snippet: snippet(line), checkId: 'cred-exposure' }));
    }
    if (findings.filter(f => !f.suppressed).length >= MAX_FINDINGS_PER_CHECK) return;
  });
  return findings;
}

/* ---- check 2: plaintext http:// endpoints ---- */
function checkPlaintextHttp(file) {
  const findings = [];
  const seen = new Set();
  const re = /\bhttp:\/\/([a-zA-Z0-9.\-]+|\[[^\]]+\])(?::\d+)?(?:\/[^\s"'`)<>]*)?/g;
  file.lines.forEach((line, i) => {
    let m;
    while ((m = re.exec(line)) !== null) {
      const host = m[1];
      const url = m[0];
      const key = host + '|' + (i + 1);
      if (seen.has(key)) continue;
      seen.add(key);
      let sev, msg, suppressed = false;
      if (LOCAL_HOSTS.test(host)) {
        sev = 'info'; suppressed = true;
        msg = `http://${host} 本地回环地址（非出站明文流量，已降噪）`;
      } else if (DOC_HOSTS.test(host)) {
        sev = 'info'; suppressed = true;
        msg = `http://${host} 规范/文档命名空间 URL（非业务端点，已降噪）`;
      } else if (PLACEHOLDER_HOSTS.test(host)) {
        sev = 'info'; suppressed = true;
        msg = `http://${host} 占位/示例域名（已降噪）`;
      } else if (METADATA_HOSTS.test(host)) {
        // metadata endpoints are assessed with context by ssrf-protection
        // (covers both IPs and hostnames like metadata.google.internal)
        continue;
      } else {
        sev = 'warn';
        msg = `明文 HTTP 出站端点: ${url.length > 80 ? url.slice(0, 80) + '…' : url}`;
      }
      findings.push(mkFinding(file, i + 1, sev, msg, { suppressed, snippet: snippet(line), checkId: 'mcp-tls' }));
    }
  });
  return findings.slice(0, MAX_FINDINGS_PER_CHECK);
}

/* ---- check 3: cloud metadata / intranet addresses ---- */
function checkMetadataIntranet(file) {
  const findings = [];
  const seen = new Set();
  // 169.254.x.x (cloud link-local/metadata), RFC1918 private literals,
  // GCP metadata hostname, or IPv6 cloud link-local (fd00:ec2::*).
  const re = /\b(169\.254\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|metadata\.google(?:\.internal)?\.?|\[?fd00:ec2[0-9a-f:]*\]?)\b/gi;
  file.lines.forEach((line, i) => {
    let m;
    while ((m = re.exec(line)) !== null) {
      const target = m[1];
      if (seen.has(target + ':' + i)) continue;
      seen.add(target + ':' + i);
      const ctx = lineWindow(file.lines, i);
      const isMetadata = /^169\.254\./.test(target) || /metadata\.google/i.test(target) || /fd00:ec2/i.test(target);
      const inSdk = SDK_CTX.test(ctx) || /SECONDARY_HOST_ADDRESS|gcp|google/i.test(ctx);
      const inGuard = GUARD_CTX.test(ctx);
      let sev, msg, suppressed = false;
      if (inSdk) {
        sev = 'info'; suppressed = true;
        msg = `${target} 位于云 SDK 凭证提供者上下文（AWS IMDS / GCP metadata 正常用法，非业务 SSRF，已降噪）`;
      } else if (inGuard) {
        sev = 'info'; suppressed = true;
        msg = `${target} 位于 SSRF 防护/代理黑名单上下文（NO_PROXY/blocklist 等防护信号，已降噪）`;
      } else if (isMetadata) {
        sev = 'fail';
        msg = `云元数据地址 ${target} 出现在业务代码中且无 SDK/防护上下文 — 疑似 SSRF（需人工确认可达性）`;
      } else {
        sev = 'warn';
        msg = `内网地址 ${target} 硬编码于代码中且无防护上下文 — 检查是否可被外部输入触达（SSRF）`;
      }
      findings.push(mkFinding(file, i + 1, sev, msg, { suppressed, snippet: snippet(line), checkId: 'ssrf-protection' }));
    }
  });
  return findings.slice(0, MAX_FINDINGS_PER_CHECK);
}

/* ---- check 4: child_process shell:true / exec ---- */
function checkCommandExec(file) {
  const findings = [];
  const shellTrue = /shell\s*:\s*(?:!0|true)/;
  const execCall = /(^|[^.\w$])(?:exec|execSync)\s*\(/;
  const gatedRe = /(permission[A-Z]|permission[ _-]?(?:check|mode|behavior|behaviour|prompt|decision|system|gate)|allowedTools|disallowedTools|shell-quote|shellQuote|\.quote\(|PreToolUse|PostToolUse|hookEventName|"Bash"|Bash tool|isCommandAllowed|canUseBash|checkPermissions|permissionRule|toolPermission)/i;
  const buildRe = /(node-gyp|npm install|install script|spawnSync\(\s*["'`])(?:[a-z\-]+ )?[a-z\-]+(?:\s|["'`])/i;
  // call site where the command arg is a fixed literal ("cmd ...")
  const staticCallRe = /(?:spawn|spawnSync|exec|execSync)(?:\s*\.\w+)?\s*\(\s*[A-Za-z_$][\w$]*\s*,?[^)]{0,40}shell\s*:\s*(?:!0|true)|(?:spawnSync|execSync)\s*\(\s*["'`][a-zA-Z0-9_\-./ ]+["'`]/;
  // build/install tooling or fixed-command env probes in the vicinity
  const buildWideRe = /(node-gyp|gyp rebuild|npm[ _-]?install|prebuild-install|sharp:|Installation error|spawnSync\(\s*["'`][a-zA-Z0-9_\-. ]+["'`])/i;
  const dynamicCmd = /\$\{|`[^`]*\$\{|\+\s*[A-Za-z_$][\w$]*\s*\)/;
  const seen = new Set();

  // Wide context (±250 lines) catches permission gates/hook dispatchers
  // defined far above the spawn call site in bundled tool implementations.
  function isGated(i) {
    const lo = Math.max(0, i - 250);
    const hi = Math.min(file.lines.length, i + 15);
    return gatedRe.test(file.lines.slice(lo, hi).join('\n'));
  }

  file.lines.forEach((line, i) => {
    if (shellTrue.test(line)) {
      if (seen.has('shell:' + i)) return;
      seen.add('shell:' + i);
      const gated = isGated(i);
      const buildCtx = buildWideRe.test(lineWindow(file.lines, i, 120));
      const staticCmd = staticCallRe.test(line) || buildCtx;
      const sev = gated || staticCmd ? 'info' : 'warn';
      const why = gated
        ? '邻近上下文可见权限门/hook 分发/转义（permission/quote/PreToolUse），降级 info'
        : staticCmd
          ? '命令为固定字面量（构建/环境探测脚本），外部输入不可控，降级 info'
          : '未见邻近权限门且命令可能动态构造 — warn';
      findings.push(mkFinding(file, i + 1, sev,
        `child_process spawn/spawnSync 使用 shell:true — 命令注入面存在；${why}；仍建议人工确认参数来源`,
        { suppressed: sev === 'info', snippet: snippet(line), checkId: 'command-exec' }));
    }
    if (execCall.test(line)) {
      if (seen.has('exec:' + i)) return;
      seen.add('exec:' + i);
      const ctx = lineWindow(file.lines, i);
      const looksDynamic = dynamicCmd.test(line) || /\$\{/.test(ctx);
      findings.push(mkFinding(file, i + 1, looksDynamic ? 'warn' : 'info',
        `child_process exec/execSync 调用（始终经 shell）${looksDynamic ? '，参数疑似动态拼接 — 检查注入面' : '，参数为静态/库内字符串'}`,
        { suppressed: !looksDynamic, snippet: snippet(line), checkId: 'command-exec' }));
    }
  });
  return findings.slice(0, MAX_FINDINGS_PER_CHECK);
}

/* ---- check 5: eval / new Function / vm ---- */
function checkDynamicEval(file) {
  const findings = [];
  const knownBenign = [
    { re: /new Function\([^)]*RULES|ajv|ValidationError/i, why: 'ajv/JSON-schema 库编译校验函数（第三方库常见模式，参数为库内数据）' },
    { re: /eval\(\s*["']quire["']|quire["']\s*\.replace|lazy.*require/i, why: '惰性 require shim（字符串拆分拼接 require，try/catch 包裹、失败返回 null）' },
    { re: /eval\s+\$\{|shell-quote|\.quote\(/i, why: '沙箱脚本内 eval 经 shell-quote 转义的参数（bwrap/socat 包装）' },
    { re: /hardenVMIntrinsics|harden[a-zA-Z]*[Ii]ntrinsics|createContext\s*\(|repl-tool-code|REPL (?:code|replay|execution)|runInContext|new [A-Za-z_$][\w$]*\.Script\(/, why: 'VM 沙箱自身实现（createContext/冻结 intrinsics/隔离 REPL 与插件代码）—— 属于安全控制原语而非风险，参数为库内模板' },
  ];
  const patterns = [
    { re: /(^|[^.\w$])eval\s*\(/g, label: 'eval(' },
    { re: /new\s+Function\s*\(/g, label: 'new Function(' },
    { re: /\b(?:runInNewContext|runInThisContext|runInContext)\s*\(/g, label: 'vm.runIn*Context' },
    { re: /new\s+vm\.\w+\s*\(|require\(\s*["']node:vm["']\s*\)|from\s*["']node:vm["']/g, label: 'node:vm 原语' },
  ];
  const seen = new Set();
  for (const p of patterns) {
    // non-stateful test regex (global flags would carry lastIndex across lines)
    const testRe = new RegExp(p.re.source, p.re.flags.replace('g', ''));
    file.lines.forEach((line, i) => {
      if (!testRe.test(line)) return;
      // skip method definitions like "eval(r) {" and member calls ".eval("
      if (/\beval\s*\([^)]*\)\s*\{/.test(line) && p.label === 'eval(') return;
      const key = p.label + ':' + i;
      if (seen.has(key)) return;
      seen.add(key);
      // wide window: vm.runInContext template bodies and hardening calls
      // span many beautified lines
      const ctx = lineWindow(file.lines, i, 30) + '\n' + lineWindow(file.lines, i, 6);
      const benign = knownBenign.find(b => b.re.test(ctx) || b.re.test(line));
      if (benign) {
        findings.push(mkFinding(file, i + 1, 'info',
          `${p.label} 动态代码执行点 — ${benign.why}（判据：上下文模式匹配，已降噪为 info；建议人工复核参数可控性）`,
          { suppressed: true, snippet: snippet(line), checkId: 'dynamic-eval' }));
      } else {
        findings.push(mkFinding(file, i + 1, 'warn',
          `${p.label} 动态代码执行原语 — 未见已知良性上下文，需人工确认参数字符串是否外部可控`,
          { snippet: snippet(line), checkId: 'dynamic-eval' }));
      }
    });
  }
  return findings.slice(0, MAX_FINDINGS_PER_CHECK);
}

/* ---- check 6: env vars / credential flow ---- */
function checkEnvVars(file) {
  const findings = [];
  const envRe = /process\.env\.([A-Z][A-Z0-9_]{2,})/g;
  const credRe = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/;
  const tallyMap = new Map();
  const credLines = new Map();
  let m;
  while ((m = envRe.exec(file.text)) !== null) {
    const name = m[1];
    tallyMap.set(name, (tallyMap.get(name) || 0) + 1);
    if (credRe.test(name) && !credLines.has(name)) {
      const idx = file.text.slice(0, m.index).split('\n').length - 1;
      credLines.set(name, idx);
    }
  }
  // Hardcoded fallback defaults for credential env vars: process.env.X || "literal"
  const hardcodeRe = /process\.env\.([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*["'`]([A-Za-z0-9_\-./+]{8,})["'`]/g;
  while ((m = hardcodeRe.exec(file.text)) !== null) {
    const idx = file.text.slice(0, m.index).split('\n').length - 1;
    findings.push(mkFinding(file, idx + 1, 'fail',
      `凭证环境变量 ${m[1]} 带有硬编码回退默认值 "${m[2].slice(0, 6)}…" — 疑似后门/泄漏`,
      { snippet: snippet(file.lines[idx] || ''), checkId: 'env-secrets' }));
  }
  const credNames = [...tallyMap.entries()].filter(([n]) => credRe.test(n)).sort((a, b) => b[1] - a[1]);
  for (const [name, n] of credNames.slice(0, 20)) {
    const idx = credLines.get(name) ?? 0;
    findings.push(mkFinding(file, idx + 1, 'info',
      `凭证类环境变量 process.env.${name}（读取 ${n} 处）— 追踪其流向：不得入日志/不得硬编码回退`,
      { suppressed: true, snippet: snippet(file.lines[idx] || ''), checkId: 'env-secrets' }));
  }
  findings.unshift(mkFinding(file, 0, 'info',
    `共枚举到 ${tallyMap.size} 个不同环境变量名，其中凭证类 ${credNames.length} 个（信号全保留，可用于凭证流向审计）`,
    { suppressed: true, checkId: 'env-secrets' }));
  return findings;
}

/* ---- check 7: permission modes ---- */
function checkPermissionModes(file) {
  const findings = [];
  const hasAllow = /allowedTools|disallowedTools|allowed_tools|permission[-_ ]?mode/i.test(file.text);
  const skipRe = /dangerously-skip-permissions|dangerouslySkipPermissions|--no-sandbox|skipPermissions/i;
  const rootGuard = /getuid\(\)\s*===?\s*0|cannot be used with root|IS_SANDBOX/i;
  let skipLine = 0;
  file.lines.forEach((line, i) => {
    if (skipRe.test(line) && !skipLine) skipLine = i + 1;
  });
  if (hasAllow) {
    const idx = file.text.search(/allowedTools|disallowedTools|allowed_tools/i);
    const ln = idx >= 0 ? file.text.slice(0, idx).split('\n').length : 0;
    findings.push(mkFinding(file, ln, 'info',
      '检测到工具白名单/权限模式（allowedTools/disallowedTools/permissionMode）— 权限门存在',
      { suppressed: true, snippet: snippet(file.lines[ln - 1] || ''), checkId: 'allowed-tools' }));
  }
  if (skipLine) {
    const guarded = rootGuard.test(file.text);
    findings.push(mkFinding(file, skipLine, guarded ? 'info' : 'warn',
      guarded
        ? '检测到 --dangerously-skip-permissions 旁路开关，但同包内存在 root/沙箱护栏（uid=0 拒绝）— 已降噪为 info'
        : '检测到 --dangerously-skip-permissions/--no-sandbox 旁路开关且未见 root/沙箱护栏 — 确认其默认不可达',
      { suppressed: guarded, snippet: snippet(file.lines[skipLine - 1] || ''), checkId: 'allowed-tools' }));
  }
  if (!hasAllow && !skipLine) {
    findings.push(mkFinding(file, 0, 'warn', '未检测到工具白名单/权限模式字符串 — 若该包执行 Agent 工具调用，需人工确认权限控制', { checkId: 'allowed-tools' }));
  }
  return findings;
}

/* ---- check 8: MCP transport auth ---- */
function checkMcpTransportAuth(file) {
  const findings = [];
  const transportRe = /["'](stdio|sse|sse-ide|http|streamable-?http|ws|wss)["']/g;
  const transports = new Set();
  let m;
  while ((m = transportRe.exec(file.text)) !== null) transports.add(m[1]);
  const hasRemote = [...transports].some(t => t !== 'stdio');
  const authSignal = /Authorization\s*[:=]|Bearer\s+[$`"']|authProvider|X-Claude-Code-Ide-Authorization|getAccessToken|oauth/i.test(file.text);
  const mcpSignal = /mcpServers|tools\/call|notifications\/initialized|ModelContextProtocol|@modelcontextprotocol/i.test(file.text);
  if (transports.size > 0 && (mcpSignal || transports.has('sse-ide'))) {
    const idx = file.text.search(transportRe);
    const ln = idx >= 0 ? file.text.slice(0, idx).split('\n').length : 0;
    findings.push(mkFinding(file, ln, 'info',
      `MCP 传输类型: ${[...transports].join('/')}${hasRemote ? '（含远程传输）' : '（仅本地 stdio）'}`,
      { suppressed: true, snippet: snippet(file.lines[ln - 1] || ''), checkId: 'mcp-auth' }));
    if (hasRemote && authSignal) {
      const aidx = file.text.search(/Authorization\s*[:=]|Bearer\s+[$`"']|authProvider|X-Claude-Code-Ide-Authorization/);
      const aln = aidx >= 0 ? file.text.slice(0, aidx).split('\n').length : 0;
      findings.push(mkFinding(file, aln, 'info',
        '远程传输分支检测到鉴权头注入（Authorization/Bearer/authProvider/IDE 鉴权头）— 鉴权机制存在',
        { suppressed: true, snippet: snippet(file.lines[aln - 1] || ''), checkId: 'mcp-auth' }));
    } else if (hasRemote) {
      findings.push(mkFinding(file, ln, 'warn',
        '检测到远程 MCP 传输(sse/http/ws)但全包未见 Authorization/Bearer/authProvider 鉴权信号 — 确认远程连接是否鉴权',
        { checkId: 'mcp-auth' }));
    }
  }
  return findings;
}

/* ---- check 9: timeout ---- */
function checkTimeout(file) {
  const findings = [];
  const re = /AbortSignal\.timeout\s*\(\s*(\d+)\s*\)|timeout\s*:\s*(\d+[A-Za-z_]*|\d{3,})/g;
  let m;
  let n = 0;
  while ((m = re.exec(file.text)) !== null && n < 8) {
    const idx = file.text.slice(0, m.index).split('\n').length - 1;
    findings.push(mkFinding(file, idx + 1, 'info',
      `超时信号: ${m[0].slice(0, 60)}`,
      { suppressed: true, snippet: snippet(file.lines[idx] || ''), checkId: 'mcp-timeout' }));
    n++;
  }
  if (!findings.length) {
    findings.push(mkFinding(file, 0, 'warn', '未检测到 AbortSignal.timeout/timeout 选项 — 出站请求/子进程可能无超时', { checkId: 'mcp-timeout' }));
  }
  return findings;
}

/* ---- check 10: kill switch ---- */
function checkKillSwitch(file) {
  const n = countMatches(/AbortController|AbortSignal|\.abort\(\)/g, file.text);
  if (n > 0) {
    const idx = file.text.search(/AbortController|AbortSignal/);
    const ln = idx >= 0 ? file.text.slice(0, idx).split('\n').length : 0;
    return [mkFinding(file, ln, 'info',
      `检测到 AbortController/AbortSignal 信号 ${n} 处 — fetch/spawn 可被终止的基础设施存在`,
      { suppressed: true, snippet: snippet(file.lines[ln - 1] || ''), checkId: 'kill-switch' })];
  }
  return [mkFinding(file, 0, 'warn', '未检测到 AbortController/AbortSignal — 缺少紧急终止信号', { checkId: 'kill-switch' })];
}

/* ---- check 11: sandbox ---- */
function checkSandbox(file) {
  const re = /\b(bwrap|bubblewrap|--ro-bind|IS_SANDBOX|SandboxManager|sandbox)\b/i;
  const m = file.text.match(re);
  if (m) {
    const idx = file.text.search(re);
    const ln = idx >= 0 ? file.text.slice(0, idx).split('\n').length : 0;
    return [mkFinding(file, ln, 'info',
      `检测到沙箱机制信号 "${m[0]}"（bwrap/只读绑定/沙箱管理器等）— 隔离机制存在`,
      { suppressed: true, snippet: snippet(file.lines[ln - 1] || ''), checkId: 'sandbox' })];
  }
  return [mkFinding(file, 0, 'info', '未检测到 bwrap/sandbox 信号 — 若该包执行外部命令，建议人工确认隔离方式', { suppressed: true, checkId: 'sandbox' })];
}

/* ---- check 12: input validation ---- */
function checkInputValidation(file) {
  const re = /\.describe\s*\(|zod|Invalid name|sanitize|validateUrl|new URL\(/i;
  const m = file.text.match(re);
  if (m) {
    const idx = file.text.search(re);
    const ln = idx >= 0 ? file.text.slice(0, idx).split('\n').length : 0;
    return [mkFinding(file, ln, 'info',
      `检测到输入校验信号 "${m[0]}"（schema describe/URL 解析/校验错误串等）— 校验逻辑存在`,
      { suppressed: true, snippet: snippet(file.lines[ln - 1] || ''), checkId: 'input-validation' })];
  }
  return [mkFinding(file, 0, 'warn', '未检测到 schema/validate 类输入校验信号', { checkId: 'input-validation' })];
}

/* ---- check 13 (semi): supply chain / vendor SBOM ---- */
function checkSupplyChain(file) {
  const findings = [];
  // vendor native artifacts named in strings
  const re = /\b(napi-[0-9.]+|[a-z0-9_-]+-\d+\.\d+\.\d+\.jar|ripgrep|@anthropic-ai[\\/][a-z0-9-]+)/gi;
  const hits = tally(re, file.text, 10);
  for (const h of hits) {
    findings.push(mkFinding(file, 0, 'info',
      `vendor/原生件 SBOM 信号: "${h.value}" ×${h.count}（零依赖 bundle 下供应链审计转为核对 vendor 件版本，半自动）`,
      { suppressed: true, checkId: 'version-pin' }));
  }
  if (!findings.length) {
    findings.push(mkFinding(file, 0, 'info', '未从代码字符串提取到 vendor 件版本信号（若包内含 .node/.jar/wasm，请人工核对 SBOM）', { suppressed: true, checkId: 'version-pin' }));
  }
  return findings;
}

/* ------------------------------------------------------------------ */
/* Scan orchestration                                                  */
/* ------------------------------------------------------------------ */

function scanFile(filePath, baseDir) {
  const raw = fs.readFileSync(filePath, 'utf-8');
  const rel = path.relative(baseDir, filePath) || path.basename(filePath);
  // Lightweight internal reformat for minified bundles: if the file is
  // dominated by very long lines, expand ; { } so findings carry useful line
  // numbers. Already-formatted source is scanned untouched (beautify would
  // only churn line numbers of normal multi-line files).
  const firstLines = raw.split('\n');
  const longest = firstLines.slice(0, 50).reduce((m, l) => Math.max(m, l.length), 0);
  const avgLen = raw.length / Math.max(1, firstLines.length);
  // Minified = very long lines, or a small file that is just one/few dense
  // lines (multiple statement separators on a single physical line).
  const denseOneliners = firstLines.filter(l => (l.match(/[;{}]/g) || []).length >= 3 && l.length > 80).length;
  const looksMinified = avgLen > 200 || (firstLines.length < 20 && longest > 800) ||
    (firstLines.length <= 3 && denseOneliners >= 1);
  const text = looksMinified ? beautifySource(raw) : raw;
  const lines = text.split('\n');
  const file = { path: filePath, rel, text, lines, minified: looksMinified };
  const results = [];
  for (const check of CHECKS) {
    let findings = [];
    try { findings = check.run(file) || []; } catch (e) { findings = []; }
    const active = findings.filter(f => !f.suppressed);
    let status = 'pass';
    if (active.some(f => f.severity === 'fail')) status = 'fail';
    else if (active.some(f => f.severity === 'warn')) status = 'warn';
    else if (findings.length > 0) status = 'info';
    results.push({
      id: check.id,
      category: check.category,
      name: check.name,
      severity: check.severity,
      aisvs: check.aisvs,
      fix: check.fix,
      status,
      findings,
    });
  }
  return { file: rel, results };
}

function summarize(fileResults) {
  let pass = 0, warn = 0, fail = 0, info = 0;
  let findingsFail = 0, findingsWarn = 0, findingsInfo = 0, findingsSuppressed = 0;
  for (const fr of fileResults) {
    for (const r of fr.results) {
      if (r.status === 'pass') pass++;
      else if (r.status === 'warn') warn++;
      else if (r.status === 'fail') fail++;
      else info++;
      for (const f of r.findings) {
        if (f.suppressed) findingsSuppressed++;
        else if (f.severity === 'fail') findingsFail++;
        else if (f.severity === 'warn') findingsWarn++;
        else findingsInfo++;
      }
    }
  }
  const total = pass + warn + fail + info;
  const score = total ? Math.round(((pass * 10 + warn * 5 + info * 7) / (total * 10)) * 100) : 100;
  return {
    pass, warn, fail, info, total, score,
    findings: { fail: findingsFail, warn: findingsWarn, info: findingsInfo, suppressed: findingsSuppressed },
  };
}

/**
 * Run a bundle scan.
 * @param {string[]} files  - absolute JS file paths
 * @param {string} baseDir  - for relative display names
 * @returns {{ files: Array, stats: Object, checks: Array }}
 */
function runBundleScan(files, baseDir) {
  const fileResults = files.map(f => scanFile(f, baseDir));
  const stats = summarize(fileResults);
  return { files: fileResults, stats, checks: CHECKS.map(c => ({ id: c.id, name: c.name, aisvs: c.aisvs })) };
}

module.exports = {
  runBundleScan,
  discoverBundleFiles,
  beautifySource,
  BUNDLE_CHECKS: CHECKS,
};
