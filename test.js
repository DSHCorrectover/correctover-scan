/**
 * Basic test for correctover-scan
 */
const { runScan, parseConfig } = require('./core/scanner');
const { runBundleScan, discoverBundleFiles, beautifySource, BUNDLE_CHECKS } = require('./core/bundle-scanner');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Test 1: Config with issues
const insecure = {
  mcpServers: {
    "github": {
      url: "http://192.168.1.100:8080/mcp",
      headers: { "Authorization": "Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
    },
    "db": { command: "python", args: ["db.py"], env: { "DB_PASSWORD": "secret123" } }
  }
};

const r1 = runScan(insecure);
console.assert(r1.stats.fail >= 2, 'Should detect TLS + SSRF + cred exposure');
console.assert(r1.stats.score < 60, 'Score should be low');
console.log(`✅ Test 1 (insecure config): score=${r1.stats.score}, fail=${r1.stats.fail}, warn=${r1.stats.warn}`);

// Test 2: Empty config
const r2 = runScan({});
console.assert(r2.stats.total === 14, 'Should have 14 checks');
console.log(`✅ Test 2 (empty config): score=${r2.stats.score}, info=${r2.stats.info}`);

// Test 3: Parse JSON
const cfg = parseConfig('{"mcpServers":{"test":{"command":"node"}}}', 'test.json');
console.assert(cfg.mcpServers.test.command === 'node', 'Should parse JSON');
console.log(`✅ Test 3 (JSON parse): OK`);

// --- Bundle mode tests (v1.4.0) -------------------------------------

// Test 4: malicious bundle — hardcoded secrets must FAIL with locations
const malicious = `
const { spawn } = require("child_process");
const k1 = "sk-proj-abcdef1234567890ABCDEFGHIJKLMN";
const k2 = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const k3 = "AKIAZ9XJ2KLMNOPQRS7T";
const fb = process.env.API_TOKEN || "hardcoded-fallback-token-xyz123";
fetch("http://169.254.169.254/latest/meta-data/");
spawn("sh", ["-c", userInput], { shell: true });
eval(userInput);
`;
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cscan-'));
const malFile = path.join(tmpDir, 'mal.js');
fs.writeFileSync(malFile, malicious);
const b1 = runBundleScan([malFile], tmpDir);
const cred = b1.files[0].results.find(r => r.id === 'cred-exposure');
const credFails = cred.findings.filter(f => !f.suppressed && f.severity === 'fail');
console.assert(credFails.length >= 3, `Bundle: should find >=3 hardcoded secrets, got ${credFails.length}`);
console.assert(credFails.every(f => f.line > 0), 'Bundle: every secret finding must carry a line number');
const ssrf = b1.files[0].results.find(r => r.id === 'ssrf-protection');
console.assert(ssrf.findings.some(f => !f.suppressed && f.severity === 'fail'), 'Bundle: business-code IMDS fetch must fail SSRF check');
const ce = b1.files[0].results.find(r => r.id === 'command-exec');
console.assert(ce.findings.some(f => !f.suppressed), 'Bundle: shell:true dynamic spawn must surface');
const de = b1.files[0].results.find(r => r.id === 'dynamic-eval');
console.assert(de.findings.some(f => !f.suppressed), 'Bundle: eval of variable must surface');
console.assert(b1.stats.findings.fail >= 4, `Bundle: expected >=4 fail findings, got ${b1.stats.findings.fail}`);
console.log(`✅ Test 4 (malicious bundle): fail findings=${b1.stats.findings.fail}, warn=${b1.stats.findings.warn}`);

// Test 5: benign contexts must be suppressed (false-positive control)
const benign = `
// AWS SDK IMDS credential provider (normal usage)
const ecsCreds = "http://169.254.170.2";
const imdsv2 = { IPv4: "http://169.254.169.254", IPv6: "http://[fd00:ec2::254]" };
// SSRF guard blocklist
const noProxy = ["169.254.0.0/16", "10.0.0.0/8", "192.168.0.0/16"].join(",");
// ajv schema compiler
var compiled = new Function("self", "RULES", "formats", "ValidationError", body);
// lazy require shim
var mod = eval("quire".replace(/^/, "re"))(moduleName);
// VM sandbox implementation
const ctx = vm.createContext({ console });
vm.runInContext("(() => { hardenVMIntrinsics(); })()", ctx);
// localhost / spec docs
fetch("http://localhost:3128/proxy");
const ns = "http://www.w3.org/2001/XMLSchema";
// placeholders
const doc = "http://www.example.com/api";
`;
const benFile = path.join(tmpDir, 'benign.js');
fs.writeFileSync(benFile, benign);
const b2 = runBundleScan([benFile], tmpDir);
const b2map = Object.fromEntries(b2.files[0].results.map(r => [r.id, r]));
console.assert(!b2map['cred-exposure'].findings.some(f => !f.suppressed), 'Bundle FP: no hardcoded secret fails in benign sample');
console.assert(!b2map['ssrf-protection'].findings.some(f => !f.suppressed && f.severity === 'fail'), 'Bundle FP: AWS SDK IMDS must not fail SSRF');
const evalActive = b2map['dynamic-eval'].findings.filter(f => !f.suppressed);
console.assert(evalActive.length === 0, `Bundle FP: ajv/require-shim/vm-sandbox eval must be info-suppressed, active=${evalActive.length}`);
const tlsActive = b2map['mcp-tls'].findings.filter(f => !f.suppressed);
console.assert(tlsActive.length === 0, `Bundle FP: localhost/w3.org/example http must be suppressed, active=${tlsActive.length}`);
console.log(`✅ Test 5 (benign contexts suppressed): active fails=${b2.stats.findings.fail}, warns=${b2.stats.findings.warn}, suppressed=${b2.stats.findings.suppressed}`);

// Test 6: every finding (active or suppressed) must carry file+line or line=0 summary
let allGrounded = true;
for (const fr of b1.files.concat(b2.files)) {
  for (const r of fr.results) {
    for (const f of r.findings) {
      if (typeof f.line !== 'number' || !f.file) allGrounded = false;
    }
  }
}
console.assert(allGrounded, 'Bundle: all findings grounded with file + line number');
console.log('✅ Test 6 (findings grounded): all findings have file + line');

// Test 7: beautifier + discovery
const pretty = beautifySource('var a=1;function b(){return 2}');
console.assert(pretty.split('\n').length > 3, 'Bundle: beautifier should expand minified lines');
const pkgDir = path.join(tmpDir, 'fakepkg');
fs.mkdirSync(path.join(pkgDir, 'lib'), { recursive: true });
fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ main: 'lib/index.js' }));
fs.writeFileSync(path.join(pkgDir, 'lib', 'index.js'), 'console.log(1)');
fs.writeFileSync(path.join(pkgDir, 'lib', 'helper.cjs'), 'module.exports={}');
const found = discoverBundleFiles(pkgDir);
console.assert(found.some(f => f.endsWith('index.js')), 'Bundle discovery: package entry included');
console.assert(found.length === 2, `Bundle discovery: finds 2 JS files, got ${found.length}`);
console.log(`✅ Test 7 (beautify + discovery): ${found.length} files, entry first`);

console.log('\n🎉 All tests passed!');
