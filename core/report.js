/**
 * Correctover CCS Security Scanner - HTML report generator
 * Zero dependencies (browser-compatible). Shared by CLI / GitHub Action /
 * browser build (https://dshcorrectover.github.io/agent-audit/scan.html).
 */

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function failHint(failCount) {
  return failCount > 0
    ? 'Critical findings are the entry point for the 116-check manual deep audit — see the report footer.'
    : 'Clean snapshot — re-run on every change.';
}

function normalizeConfigFindings(allResults) {
  const items = [];
  for (const r of allResults) {
    for (const chk of r.results) {
      items.push({
        file: r.file, checkId: chk.id || '', checkName: chk.name, category: chk.category || '',
        aisvs: chk.aisvs || '', status: chk.status, severity: chk.severity || chk.status,
        line: null, message: chk.status === 'pass' ? 'Check passed.' : (chk.fix || chk.name),
        snippet: '', fix: chk.fix || '',
      });
    }
  }
  return items;
}

function normalizeBundleFindings(bundle) {
  const items = [];
  for (const fr of bundle.files) {
    for (const r of fr.results) {
      for (const f of r.findings) {
        if (f.suppressed) continue;
        items.push({
          file: fr.file, checkId: r.id, checkName: r.name, category: r.category || '',
          aisvs: r.aisvs || '', status: f.severity === 'fail' ? 'fail' : f.severity === 'warn' ? 'warn' : 'info',
          severity: f.severity, line: f.line || null, message: f.message,
          snippet: f.snippet || '', fix: r.fix || '',
        });
      }
    }
  }
  return items;
}

function formatHTMLReport(opts) {
  const { mode, target, items, totals, checksLabel, version } = opts;
  const ver = version || '0.0.0';
  const { score, pass, warn, fail, info } = totals;
  const grade = fail > 0 || score < 60 ? ['CRITICAL RISK', '#ff5d5d']
    : warn > 0 || score < 85 ? ['REVIEW RECOMMENDED', '#f0b955']
    : ['NO CRITICAL FINDINGS', '#37d0a0'];
  const when = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

  const sevRank = { fail: 0, critical: 0, high: 1, warn: 2, medium: 2, low: 3, info: 4, pass: 5 };
  const sorted = [...items].sort((a, b) => (sevRank[a.status] ?? 9) - (sevRank[b.status] ?? 9));
  const active = sorted.filter(i => i.status === 'fail' || i.status === 'warn');
  const infos = sorted.filter(i => i.status === 'info');
  const passed = sorted.filter(i => i.status === 'pass');

  const card = (i) => `
      <div class="finding sev-${esc(i.status)}">
        <div class="f-head">
          <span class="badge b-${esc(i.status)}">${i.status === 'fail' ? 'CRITICAL' : i.status === 'warn' ? 'WARNING' : 'INFO'}</span>
          <span class="f-title">${esc(i.checkName)}</span>
          <span class="f-loc">${esc(i.file)}${i.line ? ':' + esc(i.line) : ''}</span>
        </div>
        <div class="f-meta">${i.checkId ? '<code>' + esc(i.checkId) + '</code> · ' : ''}${esc(i.category)}${i.aisvs ? ' · maps to <code>' + esc(i.aisvs) + '</code>' : ''}</div>
        <div class="f-msg">${esc(i.message)}</div>
        ${i.snippet ? `<pre class="f-snip">${esc(i.snippet)}</pre>` : ''}
        ${i.fix && i.status !== 'pass' ? `<div class="f-fix"><strong>Fix:</strong> ${esc(i.fix)}</div>` : ''}
      </div>`;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Security Scan Report — ${esc(target)}</title>
<meta name="description" content="Correctover agent security scan report for ${esc(target)}">
<style>
  :root{--bg:#0b1020;--card:#141d38;--line:#263156;--text:#e8ecf8;--muted:#9aa7c7;--accent:#4f7cff;--ok:#37d0a0;--warn:#f0b955;--bad:#ff5d5d;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:32px 16px}
  .wrap{max-width:880px;margin:0 auto}
  .hero{background:linear-gradient(135deg,#16203f,#101736);border:1px solid var(--line);border-radius:16px;padding:28px 30px;margin-bottom:20px}
  .brand{font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:700}
  .brand span{color:var(--muted);font-weight:400;letter-spacing:.05em;text-transform:none}
  h1{font-size:24px;margin:10px 0 4px}
  .sub{color:var(--muted);font-size:14px}
  .score-row{display:flex;align-items:center;gap:28px;margin-top:22px;flex-wrap:wrap}
  .score{font-size:56px;font-weight:800;line-height:1}
  .grade{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:700;font-size:13px;margin-top:8px;color:#0b1020}
  .counts{display:flex;gap:18px;flex-wrap:wrap;font-size:14px}
  .counts b{font-size:20px;display:block}
  .c-pass b{color:var(--ok)}.c-warn b{color:var(--warn)}.c-fail b{color:var(--bad)}.c-info b{color:var(--accent)}
  h2{font-size:16px;margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
  .finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:10px;padding:14px 16px;margin-bottom:10px}
  .finding.sev-fail{border-left-color:var(--bad)}.finding.sev-warn{border-left-color:var(--warn)}.finding.sev-info{border-left-color:var(--accent)}
  .f-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
  .f-title{font-weight:700;font-size:15px}
  .f-loc{margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:12px}
  .badge{padding:2px 9px;border-radius:6px;font-size:11px;font-weight:700;color:#0b1020}
  .b-fail{background:var(--bad)}.b-warn{background:var(--warn)}.b-info{background:var(--accent);color:#fff}
  .f-meta{color:var(--muted);font-size:12px;margin:4px 0}
  code{font-family:var(--mono);background:#0d1430;padding:1px 6px;border-radius:4px;font-size:12px}
  .f-msg{font-size:14px;margin-top:6px}
  .f-snip{background:#080d1f;border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:var(--mono);font-size:12px;color:#c7d2f0;overflow-x:auto;margin-top:8px;white-space:pre-wrap;word-break:break-all}
  .f-fix{margin-top:8px;font-size:13px;color:var(--ok)}
  .note{background:#101736;border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-size:13px;color:var(--muted);margin:18px 0}
  .next{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-top:12px}
  .next a{text-decoration:none;color:inherit;display:block}
  .next .card2{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;transition:border-color .15s}
  .next .card2:hover{border-color:var(--accent)}
  .next h3{font-size:15px;color:var(--accent);margin-bottom:6px}
  .next p{font-size:13px;color:var(--muted)}
  footer{margin-top:28px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;text-align:center}
  details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:13px}
  .pass-list{font-size:13px;color:var(--muted);columns:2;margin-top:10px}
  .pass-list div{break-inside:avoid;padding:2px 0}
  .gateway{background:rgba(79,124,255,.08);border:1px solid var(--accent);border-radius:12px;padding:14px 18px;margin-bottom:20px;font-size:14px}
  .gateway a{color:var(--accent);font-weight:700;text-decoration:none;white-space:nowrap}
  .disclaimer{background:rgba(240,185,85,.06);border:1px solid rgba(240,185,85,.4);border-radius:12px;padding:18px 20px;margin:22px 0;font-size:12.5px;color:var(--muted)}
  .disclaimer h2{font-size:14px;color:var(--warn);border:none;margin:0 0 10px;padding:0}
  .disclaimer p{margin-bottom:8px}
  .disclaimer p:last-child{margin-bottom:0}
  .disclaimer strong{color:var(--text)}
  .printbtn{position:fixed;top:14px;right:14px;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 16px;font-size:13px;font-weight:700;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.35);z-index:10}
  @media print{
    :root{--bg:#ffffff;--card:#ffffff;--line:#bbbbbb;--text:#111111;--muted:#333333;--accent:#0a4dd6;--ok:#0a7a52;--warn:#8a6100;--bad:#b32020}
    body{background:#fff;padding:0}
    .printbtn{display:none !important}
    .hero,.finding,.note,.gateway,.disclaimer,.next .card2{break-inside:avoid}
    .disclaimer{background:#fffbe8 !important;border-color:#999 !important;color:#000 !important}
    .disclaimer h2{color:#000 !important}.disclaimer strong{color:#000 !important}
    .f-snip{background:#f6f6f6 !important;color:#111 !important}
    code{background:#f0f0f0 !important}
    .next a{text-decoration:none}
  }
</style></head>
<body><div class="wrap">

  <button class="printbtn" onclick="window.print()">🖨 Print / Save as PDF</button>

  <div class="gateway">
    This automated scan maps surface patterns to <strong>OWASP AISVS 1.0</strong> controls — it is not a certification or an audit opinion.
    Need an <strong>official compliance report for vendor acceptance</strong>, an AISVS mapping workbook, or signed version-provenance records?
    👉 <a href="https://dshcorrectover.github.io/agent-audit/scan.html#enterprise">Enterprise report &amp; provenance options (official entry)</a>
  </div>

  <div class="hero">
    <div class="brand">Correctover <span>· AI Reliability™ — Agent Runtime Assurance</span></div>
    <h1>Agent Security Scan Report</h1>
    <div class="sub">Target: <strong>${esc(target)}</strong> &nbsp;·&nbsp; Mode: ${esc(mode)} &nbsp;·&nbsp; correctover-scan v${esc(ver)} (${esc(checksLabel)}) &nbsp;·&nbsp; ${esc(when)}</div>
    <div class="score-row">
      <div>
        <div class="score">${score}<span style="font-size:24px;color:var(--muted)">/100</span></div>
        <div class="grade" style="background:${grade[1]}">${grade[0]}</div>
      </div>
      <div class="counts">
        <div class="c-pass"><b>${pass}</b>passed</div>
        <div class="c-warn"><b>${warn}</b>warnings</div>
        <div class="c-fail"><b>${fail}</b>critical</div>
        <div class="c-info"><b>${info}</b>info</div>
      </div>
    </div>
  </div>

  <h2>Critical &amp; warning findings (${active.length})</h2>
  ${active.length ? active.map(card).join('') : '<div class="note">✅ No fail- or warning-level findings. This is a signal scan over the current snapshot — keep scanning on every change.</div>'}

  ${infos.length ? `<h2>Informational signals (${infos.length})</h2>${infos.map(card).join('')}` : ''}

  ${passed.length ? `<details><summary>${passed.length} checks passed — expand to list</summary><div class="pass-list">${passed.map(i => `<div>✓ ${esc(i.checkName)} <code>${esc(i.checkId)}</code></div>`).join('')}</div></details>` : ''}

  <div class="note">
    <strong>Scope &amp; limits:</strong> this report is produced by static signal scanning (${esc(checksLabel)}).
    It locates risk-bearing patterns with file/line locations; it does not execute code, prove reachability or
    exploitability, or judge semantic intent. Fail/warn items are the input for manual deep review, not a verdict
    of compromise. Nothing in this scan leaves your machine — no network calls, no telemetry.
  </div>

  <div class="disclaimer">
    <h2>⚠ Important notice — read before sharing or filing this report</h2>
    <p><strong>1. Not an audit, certification, or compliance attestation.</strong> This document is output of an automated static signal scan (${esc(checksLabel)}). It is <strong>not</strong> a security audit, penetration test, certification, or statement of compliance with any standard or regulation. A score of 100 or the absence of critical findings does <strong>not</strong> mean the code is vulnerability-free, secure, or compliant — it means only that the listed patterns were not detected in the scanned snapshot. Static analysis cannot prove the absence of reachable vulnerabilities; semantic intent, reachability, exploitability, and runtime behavior are not determined.</p>
    <p><strong>2. AISVS mapping is navigational only.</strong> OWASP® and AISVS are trademarks of the OWASP Foundation. Correctover is not affiliated with or endorsed by OWASP. References such as <code>C10.1</code> are our own mapping of checks to control families in OWASP AISVS v1.0 (June 2026), provided as a navigation aid; OWASP does not certify products or vendors, and this report must not be presented as an OWASP or AISVS certification.</p>
    <p><strong>3. Not a substitute for professional review.</strong> Do not rely on this document as the sole basis for acceptance, procurement, release, insurance, regulatory, or other consequential decisions. High-assurance use cases require an engagement performed by qualified personnel under an agreed scope and terms (such as Correctover's 116-check manual deep audit, delivered under a signed agreement).</p>
    <p><strong>4. Transparency-log anchors prove existence, not safety.</strong> Sigstore Rekor entries and any content-addressed manifest attest only that a byte-for-byte snapshot existed at a point in time. They make no statement about code safety, quality, ownership, or legal rights.</p>
    <p><strong>5. AS-IS.</strong> The scan and report are provided "as is", without warranty of any kind, express or implied, including merchantability or fitness for a particular purpose. To the maximum extent permitted by law, Correctover shall not be liable for any damages arising from their use. You are responsible for independently verifying findings before acting on them. Automated results may include false positives and false negatives.</p>
  </div>

  <h2>Go further</h2>
  <div class="next">
    <a href="https://dshcorrectover.github.io/agent-audit/scan.html"><div class="card2">
      <h3>Free deep scan in your browser →</h3>
      <p>Want the same scan as an <strong>instant, shareable report</strong> for any project? The <strong>free online scanner</strong> runs 100% in your browser — nothing is uploaded. Scan MCP configs or entire codebases, download the branded report, forward it to your team.</p>
    </div></a>
    <a href="https://dshcorrectover.github.io/agent-audit/"><div class="card2">
      <h3>116-check manual deep audit →</h3>
      <p>Automated scanning covers surface signals. A Correctover manual audit applies the <strong>116-check semantic-intent methodology</strong> over 5 days, tracing reachability and exploit paths in the real code. If we find no critical-severity issue, you pay nothing.</p>
    </div></a>
    <a href="https://github.com/DSHCorrectover/correctover-scan-action"><div class="card2">
      <h3>Scan on every push →</h3>
      <p>The <strong>correctover-scan GitHub Action</strong> runs this scan in CI, fails the build on critical findings, and uploads SARIF to GitHub code scanning — so regressions never reach production.</p>
    </div></a>
    <a href="https://github.com/DSHCorrectover/code-birth-certificate"><div class="card2">
      <h3>Anchor what shipped →</h3>
      <p>The <strong>Code Birth Certificate</strong> action signs a content-addressed manifest and anchors it in the Sigstore Rekor transparency log — public, independently verifiable proof of exactly what shipped and when. No account needed to verify.</p>
    </div></a>
  </div>

  <footer>
    Generated by <strong>correctover-scan</strong> v${esc(ver)} · static analysis, runs entirely locally ·
    <a href="https://correctover.com" style="color:var(--accent)">correctover.com</a> ·
    <a href="https://github.com/DSHCorrectover" style="color:var(--accent)">github.com/DSHCorrectover</a>
  </footer>
</div>
</body></html>`;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { esc, failHint, normalizeConfigFindings, normalizeBundleFindings, formatHTMLReport };
}
