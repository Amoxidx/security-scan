#!/usr/bin/env node
/**
 * Phase 0 — measurement harness for the security gate.
 *
 * Every corpus case is a before/ and an after/ tree. The runner builds a throwaway git
 * repository, commits before/, commits after/ on top, and points the gate at that diff — the
 * same shape a pull request has. Then it compares what the gate said against ground truth.
 *
 * Four numbers come out, and all four matter:
 *   detection rate   caught / must_detect cases
 *   FALSE POSITIVE   benign cases that were blocked   <- the acceptance criterion
 *   wall clock       p95 per case
 *   stages run       which stages actually executed (the AI stage skips without a provider)
 *
 * Usage:
 *   node security/eval/run.mjs [--only <substring>] [--out <dir>] [--keep]
 *                              [--no-scan] [--no-ai] [--config <harness config>]
 *                              [--min-detection <percent>] [--max-fp <percent>]
 *                              [--corpus <dir>]
 *
 * Three stages run per case: the static gate, the scanners (Semgrep, OSV, Gitleaks via
 * SARIF), and the AI review. --no-scan and --no-ai switch a stage off, which is how the
 * contribution of each one is isolated.
 *
 * Use --no-ai whenever a coding agent CLI happens to be on PATH — the harness would
 * otherwise fire real agent calls for every case, which takes minutes each.
 *
 * Exit code: non-zero when detection falls below --min-detection, when the false-positive
 * rate exceeds --max-fp, or when the corpus is empty / one-sided (vacuous pass).
 * p95 is reported but never gates the exit code — see DEFAULT_MIN_DETECTION below.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, cpSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, homedir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../..');

// Documented Phase-0 targets (implementation-plan §3). Enforced at process exit.
// Override with --min-detection / --max-fp. Do NOT add a p95 wall-clock threshold:
// the same revision measures 1.3 s–1.8 s depending on machine load; a time gate in CI
// would be a flaky detector, not a regression signal.
const DEFAULT_MIN_DETECTION = 50;
const DEFAULT_MAX_FP = 5;

const args = {};
for (let i = 2; i < process.argv.length; i += 1) {
  const a = process.argv[i];
  if (a === '--keep') args.keep = true;
  else if (a === '--no-ai') args.noAi = true;
  else if (a === '--no-scan') args.noScan = true;
  else if (a.startsWith('--')) { args[a.slice(2)] = process.argv[i + 1]; i += 1; }
}
const outDir = args.out || join(HERE, 'results');
const CORPUS = args.corpus ? resolve(args.corpus) : join(HERE, 'corpus');
const minDetection = Number(args['min-detection'] ?? DEFAULT_MIN_DETECTION);
const maxFp = Number(args['max-fp'] ?? DEFAULT_MAX_FP);

// ---------------------------------------------------------------- corpus loading

function loadCases() {
  const cases = [];
  for (const kind of ['vuln', 'benign']) {
    const dir = join(CORPUS, kind);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).sort()) {
      const caseDir = join(dir, name);
      const metaPath = join(caseDir, 'meta.json');
      if (!existsSync(metaPath)) continue;
      const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
      cases.push({ ...meta, kind, dir: caseDir, name });
    }
  }
  return args.only ? cases.filter((c) => c.id.includes(args.only)) : cases;
}

// ---------------------------------------------------------------- scaffolding

function sh(cmd, cmdArgs, cwd, env = {}) {
  return spawnSync(cmd, cmdArgs, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    maxBuffer: 32 * 1024 * 1024,
  });
}

/** before/ as the base commit, after/ as the PR commit. Returns the base SHA. */
function buildRepo(testCase, work) {
  mkdirSync(work, { recursive: true });
  cpSync(join(testCase.dir, 'before'), work, { recursive: true });

  sh('git', ['init', '-q', '-b', 'main'], work);
  sh('git', ['config', 'user.email', 'eval@local'], work);
  sh('git', ['config', 'user.name', 'eval'], work);
  sh('git', ['add', '-A'], work);
  sh('git', ['commit', '-q', '-m', 'base'], work);
  const base = sh('git', ['rev-parse', 'HEAD'], work).stdout.trim();

  // after/ replaces before/ wholesale, so deletions show up in the diff too.
  for (const entry of readdirSync(work)) {
    if (entry !== '.git') rmSync(join(work, entry), { recursive: true, force: true });
  }
  cpSync(join(testCase.dir, 'after'), work, { recursive: true });
  sh('git', ['add', '-A'], work);
  sh('git', ['commit', '-q', '-m', 'pull request'], work);

  return base;
}

// ---------------------------------------------------------------- the gate under test

function runStaticGate(work, base) {
  const res = sh('bash', [join(REPO, 'security/gate/static-checks.sh'), base], work);
  const output = `${res.stdout}${res.stderr}`;
  // Match the BLOCK marker only. The final "Static security gate: BLOCKED" verdict line also
  // contains the word and would otherwise be counted as a reason of its own.
  const blocks = output
    .split('\n')
    .map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''))
    .filter((l) => /^\s+BLOCK\s{2}/.test(l))
    .map((l) => l.replace(/^\s+BLOCK\s+/, '').trim());
  return { blocked: res.status === 1, blocks, output };
}

function runScanners(work, base, caseOut) {
  if (args.noScan) return { skipped: true, blocked: false, findings: [], scanners: [] };

  const sarifDir = join(caseOut, 'sarif');
  sh('bash', [join(REPO, 'security/scanners/run-scanners.sh'), work, sarifDir], work);

  const res = sh('node', [
    join(REPO, 'security/scanners/normalize.mjs'),
    '--sarif', sarifDir,
    '--diff', join(caseOut, 'pr.diff'),
    '--out', join(caseOut, 'findings.json'),
  ], work);

  const path = join(caseOut, 'findings.json');
  const data = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : { findings: [], scanners: [] };
  return {
    skipped: false,
    blocked: res.status === 1,
    findings: data.findings || [],
    scanners: data.scanners || [],
    output: `${res.stdout}${res.stderr}`,
  };
}

function writeDiff(work, base, caseOut) {
  const diffPath = join(caseOut, 'pr.diff');
  writeFileSync(diffPath, sh('git', ['diff', `${base}...HEAD`], work).stdout);
  return diffPath;
}

/**
 * Same wiring check-pr.mjs's stageEnv() does for the AI stages: the CLI
 * providers' subscription OAuth lives in the login keychain, which a plain
 * non-interactive SSH child can't read, and codex lives under a PATH entry
 * this process doesn't inherit by default. Without both, every hunt lens
 * fails silently (measured: all 17 corpus cases, 3/3 lenses each, before
 * this fix) and the eval's "AI stage" numbers are actually the static-only
 * baseline in disguise.
 */
function aiStageEnv() {
  const env = {};
  const claudeWrap = join(REPO, 'security/studio/claude-via-gui.sh');
  if (existsSync(claudeWrap)) env.SECURITY_CLAUDE_WRAPPER = claudeWrap;
  env.PATH = [
    join(REPO, 'security/studio'),
    `${homedir()}/.local/bin`,
    `${homedir()}/.local/node/bin`,
    '/usr/local/bin',
    '/opt/homebrew/bin',
    process.env.PATH || '',
  ].join(':');
  return env;
}

function runAiStage(work, base, caseOut) {
  const diffPath = join(caseOut, 'pr.diff');

  if (args.noAi) return { skipped: true, blocked: false, findings: [], output: '(--no-ai)' };

  const res = sh('node', [
    join(REPO, 'security/redteam/harness.mjs'),
    '--diff', diffPath,
    ...(args.config ? ['--config', args.config] : []),
    '--out', join(caseOut, 'ai'),
  ], work, aiStageEnv());

  const output = `${res.stdout}${res.stderr}`;
  const skipped = output.includes('No model provider is reachable');
  const findingsPath = join(caseOut, 'ai', 'findings.json');
  const findings = existsSync(findingsPath) ? JSON.parse(readFileSync(findingsPath, 'utf8')) : [];
  return { skipped, blocked: res.status === 1, findings, output };
}

// ---------------------------------------------------------------- scoring

/** A vuln case counts as detected only if the gate pointed at the right place. */
function locatedCorrectly(testCase, aiFindings, scanFindings, staticBlocked) {
  const gt = testCase.ground_truth;
  if (!gt) return staticBlocked;

  const [lo, hi] = gt.lines || [0, Number.MAX_SAFE_INTEGER];
  const sameFile = (f) =>
    f.file && (gt.file.endsWith(f.file.replace(/^.*?([^/]+)$/, '$1')) || f.file.endsWith(gt.file));
  const inRange = (f) => Number(f.line) >= lo - 5 && Number(f.line) <= hi + 5;

  const hit =
    aiFindings.some((f) => f.survived && sameFile(f) && inRange(f)) ||
    scanFindings.some((f) => sameFile(f) && inRange(f));
  // The static gate is file-level by design; a block on a case whose ground truth is a
  // workflow or manifest file is a legitimate detection, elsewhere it is not location proof.
  const staticCounts = staticBlocked && /(\.github\/|package\.json)/.test(gt.file);
  return hit || staticCounts;
}

function score(testCase, staticResult, scanResult, aiResult) {
  const blocked = staticResult.blocked || scanResult.blocked || aiResult.blocked;
  if (testCase.must_detect) {
    const located = locatedCorrectly(testCase, aiResult.findings, scanResult.findings, staticResult.blocked);
    return {
      outcome: located ? 'TP' : blocked ? 'BLOCKED_WRONG_REASON' : 'FN',
      blocked,
    };
  }
  return { outcome: blocked ? 'FP' : 'TN', blocked };
}

// ---------------------------------------------------------------- main

const cases = loadCases();
if (!cases.length) {
  console.error('No corpus cases found.');
  process.exit(1);
}

// Vacuous-pass protection: a gate whose input set can be empty must fail when empty.
// Missing either side makes the rates meaningless (0/0 would look like a pass).
const foundVuln = cases.filter((c) => c.kind === 'vuln').length;
const foundBenign = cases.filter((c) => c.kind === 'benign').length;
if (foundVuln === 0 || foundBenign === 0) {
  console.error(
    `Corpus incomplete: found ${foundVuln} vuln case(s) and ${foundBenign} benign case(s); need at least one of each.`
  );
  process.exit(1);
}

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const runDir = join(outDir, stamp);
mkdirSync(runDir, { recursive: true });

console.log(`Running ${cases.length} cases\n`);
const rows = [];
let aiEverRan = false;
let scanEverRan = false;

for (const testCase of cases) {
  const work = join(tmpdir(), `sec-eval-${testCase.id}-${process.pid}`);
  rmSync(work, { recursive: true, force: true });
  const caseOut = join(runDir, testCase.id);
  mkdirSync(caseOut, { recursive: true });

  const started = Date.now();
  const base = buildRepo(testCase, work);
  const staticResult = runStaticGate(work, base);
  writeDiff(work, base, caseOut);
  const scanResult = runScanners(work, base, caseOut);
  const aiResult = runAiStage(work, base, caseOut);
  const elapsed = Date.now() - started;

  if (!aiResult.skipped) aiEverRan = true;
  if (!scanResult.skipped) scanEverRan = true;
  const result = score(testCase, staticResult, scanResult, aiResult);

  writeFileSync(join(caseOut, 'static.log'), staticResult.output);
  writeFileSync(join(caseOut, 'ai.log'), aiResult.output);

  const mark = { TP: 'PASS', TN: 'PASS', FN: 'MISS', FP: 'FALSE ALARM', BLOCKED_WRONG_REASON: 'WRONG REASON' }[result.outcome];
  console.log(
    `${result.outcome.padEnd(22)} ${mark.padEnd(13)} ${testCase.id}` +
      (result.outcome === 'FP'
        ? `\n    blocked by: ${[...staticResult.blocks, ...scanResult.findings.map((f) => `${f.ruleId} @${f.file}:${f.line}`)].join('; ')}`
        : '')
  );

  rows.push({
    id: testCase.id,
    kind: testCase.kind,
    class: testCase.class || testCase.decoy,
    severity: testCase.severity || null,
    outcome: result.outcome,
    blocked: result.blocked,
    staticBlocks: staticResult.blocks,
    scanSkipped: scanResult.skipped,
    scanFindings: scanResult.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`),
    aiSkipped: aiResult.skipped,
    aiFindings: aiResult.findings.length,
    ms: elapsed,
  });

  if (!args.keep) rmSync(work, { recursive: true, force: true });
}

// ---------------------------------------------------------------- report

if (rows.length !== cases.length) {
  console.error(
    `Case count mismatch: ran ${rows.length} case(s) but loaded ${cases.length}.`
  );
  process.exit(1);
}

const vuln = rows.filter((r) => r.kind === 'vuln');
const benign = rows.filter((r) => r.kind === 'benign');
const tp = vuln.filter((r) => r.outcome === 'TP').length;
const wrong = vuln.filter((r) => r.outcome === 'BLOCKED_WRONG_REASON').length;
const fp = benign.filter((r) => r.outcome === 'FP').length;
const times = rows.map((r) => r.ms).sort((a, b) => a - b);
const p95 = times[Math.min(times.length - 1, Math.floor(times.length * 0.95))];

const detection = (tp / vuln.length) * 100;
const fpRate = (fp / benign.length) * 100;

const summary = {
  timestamp: stamp,
  scannerStageRan: scanEverRan,
  aiStageRan: aiEverRan,
  cases: rows.length,
  detectionRate: Number(detection.toFixed(1)),
  falsePositiveRate: Number(fpRate.toFixed(1)),
  blockedForWrongReason: wrong,
  p95Ms: p95,
  targets: { detectionRate: minDetection, falsePositiveRate: maxFp },
  rows,
};
writeFileSync(join(runDir, 'summary.json'), JSON.stringify(summary, null, 2));

const md = [
  `# Gate measurement — ${stamp}`,
  '',
  aiEverRan
    ? ''
    : '> **The AI stage did not run** (no model provider reachable). These numbers measure the static gate alone.',
  '',
  '| Metric | Value | Target |',
  '|---|---|---|',
  `| Detection rate | ${detection.toFixed(1)} % (${tp}/${vuln.length}) | ≥ ${minDetection} % |`,
  `| **False positive rate** | **${fpRate.toFixed(1)} % (${fp}/${benign.length})** | **≤ ${maxFp} %** |`,
  `| Blocked for the wrong reason | ${wrong} | 0 |`,
  // p95 target is informational only — never enforced (see DEFAULT_MIN_DETECTION comment).
  `| p95 wall clock | ${(p95 / 1000).toFixed(1)} s | ≤ 480 s |`,
  '',
  '## Cases',
  '',
  '| Case | Class | Outcome |',
  '|---|---|---|',
  ...rows.map((r) => `| \`${r.id}\` | ${r.class || ''} | ${r.outcome} |`),
].join('\n');
writeFileSync(join(runDir, 'summary.md'), md);

console.log(`\nDetection ${detection.toFixed(1)} % (${tp}/${vuln.length}) · False positives ${fpRate.toFixed(1)} % (${fp}/${benign.length}) · p95 ${(p95 / 1000).toFixed(1)} s`);
if (!aiEverRan) console.log('NOTE: AI stage never ran — static gate only.');
console.log(`\nResults: ${runDir}`);

// Enforce documented thresholds. --no-ai does not relax them: they apply to whatever
// static stage combination this run actually measured.
let exitCode = 0;
if (detection < minDetection) {
  console.error(
    `THRESHOLD FAIL: detection rate ${detection.toFixed(1)} % is below minimum ${minDetection} %`
  );
  exitCode = 1;
}
if (fpRate > maxFp) {
  console.error(
    `THRESHOLD FAIL: false positive rate ${fpRate.toFixed(1)} % exceeds maximum ${maxFp} %`
  );
  exitCode = 1;
}
process.exit(exitCode);
