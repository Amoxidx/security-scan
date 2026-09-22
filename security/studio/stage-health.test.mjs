#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const NODE = process.execPath;
const ROOT = new URL('../..', import.meta.url).pathname;
const ACTUAL_CHECK_PR = join(ROOT, 'security/studio/check-pr.mjs');
const FIXTURE_ROOT = mkdtempSync(join(tmpdir(), 'studio-stage-fixture-'));
const CHECK_PR = join(FIXTURE_ROOT, 'security/studio/check-pr.mjs');
const HARNESS = join(ROOT, 'security/redteam/harness.mjs');

const WORK = mkdtempSync(join(tmpdir(), 'studio-stage-health-'));
cpSync(join(ROOT, 'security'), join(FIXTURE_ROOT, 'security'), { recursive: true });
const FAKE_HARNESS = join(FIXTURE_ROOT, 'security/redteam/harness.mjs');
const FAKE_LAB = join(FIXTURE_ROOT, 'security/lab/run.mjs');
const FAKE_SCANNERS = join(FIXTURE_ROOT, 'security/scanners/run-scanners.sh');
const FAKE_PROVIDER = join(WORK, 'fake-provider.mjs');
const FAKE_TRIAGE_PROVIDER = join(WORK, 'fake-triage-provider.mjs');

writeFileSync(FAKE_HARNESS, `
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import process from 'node:process';
const args = process.argv.slice(2);
const prompt = readFileSync(0, 'utf8');
const out = args[args.indexOf('--out') + 1];
const mode = process.env.FAKE_HARNESS_MODE;
mkdirSync(out, { recursive: true });
const finding = [{ file: 'src/synthetic.js', line: 1, severity: 'high', title: 'Synthetic finding', survived: true }];
const sameLocation = [{ file: 'src.js', line: 1, severity: 'high', title: 'Finding A', ruleId: 'A', root_cause: 'first cause', survived: true }, { file: 'src.js', line: 1, severity: 'high', title: 'Finding B', ruleId: 'B', root_cause: 'second cause', survived: true }];
const identicalLocation = [{ file: 'src.js', line: 1, severity: 'high', title: 'Same finding', ruleId: 'A', root_cause: 'first cause', survived: true }, { file: 'src.js', line: 1, severity: 'high', title: 'Same finding', ruleId: 'B', root_cause: 'second cause', survived: true }];
const sameTitle = [{ file: 'a.js', line: 1, severity: 'high', title: 'Same title', survived: true }, { file: 'b.js', line: 2, severity: 'high', title: 'Same title', survived: true }];
const write = (name, value) => writeFileSync(out + '/' + name, JSON.stringify(value, null, 2));
if (mode === 'terminated') process.kill(process.pid, 'SIGTERM');
if (mode === 'setup') { write('findings.json', []); process.exit(3); }
if (mode === 'missing') { write('findings.json', []); process.exit(0); }
if (mode === 'malformed') { writeFileSync(out + '/execution.json', '{'); write('findings.json', []); process.exit(0); }
if (mode === 'stale') { write('execution.json', { schemaVersion: 1, stage: 'harness', runId: 'old-run', status: 'complete', outcome: 'pass', exit: 0, reasonCodes: [] }); write('findings.json', []); process.exit(0); }
if (mode === 'semantic') { write('execution.json', { schemaVersion: 1, stage: 'harness', runId: process.env.SECURITY_STUDIO_RUN_ID, status: 'complete', outcome: 'pass', exit: 3, reasonCodes: [] }); write('findings.json', []); process.exit(3); }
if (mode === 'block-empty') { write('execution.json', { schemaVersion: 1, stage: 'harness', runId: process.env.SECURITY_STUDIO_RUN_ID, status: 'complete', outcome: 'block', exit: 1, reasonCodes: [] }); write('findings.json', []); process.exit(1); }
if (mode === 'partial-block') { write('execution.json', { schemaVersion: 1, stage: 'harness', runId: process.env.SECURITY_STUDIO_RUN_ID, status: 'incomplete', outcome: 'block', exit: 1, reasonCodes: ['hunt_failed'] }); write('findings.json', finding); process.exit(1); }
const hasFinding = mode === 'finding' || mode === 'failed-finding' || mode === 'refute-both' || mode === 'refute-one-error' || mode === 'same-location' || mode === 'identical-location' || mode === 'same-title-missing-report';
const findings = mode === 'same-location' ? sameLocation
  : mode === 'identical-location' ? identicalLocation
  : mode === 'same-title-missing-report' ? sameTitle
  : finding;
write('findings.json', hasFinding ? findings : []);
writeFileSync(out + '/report.md', '## AI security review\\n');
write('execution.json', { schemaVersion: 1, stage: 'harness', runId: process.env.SECURITY_STUDIO_RUN_ID, status: mode === 'failed-finding' ? 'incomplete' : 'complete', outcome: hasFinding ? 'block' : 'pass', exit: mode === 'failed-finding' ? 3 : hasFinding ? 1 : 0, reasonCodes: mode === 'failed-finding' ? ['hunt_failed'] : [] });
process.exit(mode === 'failed-finding' ? 3 : hasFinding ? 1 : 0);
`);

writeFileSync(FAKE_LAB, `
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import process from 'node:process';
const args = process.argv.slice(2);
const out = args[args.indexOf('--out') + 1];
const finding = JSON.parse(readFileSync(args[args.indexOf('--finding') + 1], 'utf8'));
mkdirSync(out, { recursive: true });
if (process.env.FAKE_LAB_MODE === 'missing-second-report' && finding.file === 'b.js') process.exit(0);
const verdict = process.env.FAKE_LAB_MODE === 'reproduced' ? 'reproduced' : 'not-reproduced';
writeFileSync(out + '/report.json', JSON.stringify({ verdict, reasoning: 'independent deterministic result' }));
process.exit(0);
`);

writeFileSync(FAKE_TRIAGE_PROVIDER, `
import process from 'node:process';
const mode = process.env.FAKE_TRIAGE_MODE;
if (mode === 'invalid-verdict') {
  process.stdout.write(JSON.stringify({ verdict: 'bogus', severity: 'low', reason: 'invalid test verdict', reachable_from: null, what_would_change_my_mind: 'never' }));
} else if (mode === 'invalid-severity') {
  process.stdout.write(JSON.stringify({ verdict: 'false_positive', severity: 'warning', reason: 'invalid test severity', reachable_from: null, what_would_change_my_mind: 'never' }));
} else if (mode === 'true-positive') {
  process.stdout.write(JSON.stringify({ verdict: 'true_positive', severity: 'high', reason: 'bounded true positive fixture', reachable_from: 'src.js:1', what_would_change_my_mind: 'remove the finding', file: 'attacker.js', line: 99, ruleId: 'evil', tool: 'evil' }));
} else {
  process.stdout.write(JSON.stringify({ verdict: 'false_positive', severity: 'low', reason: 'bounded false positive fixture', reachable_from: null, what_would_change_my_mind: 'show the unsafe path' }));
}
`);

writeFileSync(FAKE_PROVIDER, `
import { readFileSync } from 'node:fs';
import process from 'node:process';
const prompt = readFileSync(0, 'utf8');
if (process.env.FAKE_PROVIDER_MODE === 'malformed') {
  process.stdout.write('THIS IS NOT JSON');
} else if ((process.env.FAKE_PROVIDER_MODE === 'refute-both' || process.env.FAKE_PROVIDER_MODE === 'refute-one-error') && prompt.includes('Stage 3')) {
  const modelIndex = process.argv.indexOf('--model');
  const model = modelIndex >= 0 ? process.argv[modelIndex + 1] : '';
  if (process.env.FAKE_PROVIDER_MODE === 'refute-one-error' && model === 'one') {
    process.stdout.write('THIS IS NOT JSON');
  } else {
    process.stdout.write(JSON.stringify({ refuted: true }));
  }
} else if (process.env.FAKE_PROVIDER_MODE === 'bogus-verdict' && prompt.includes('Stage 3')) {
  process.stdout.write(JSON.stringify({ refuted: false, severity: 'bogus', model: 'attacker-controlled' }));
} else if (process.env.FAKE_PROVIDER_MODE === 'bogus-verdict') {
  process.stdout.write(JSON.stringify({ findings: [{
    title: 'Synthetic provider finding',
    file: 'src.js',
    line: 1,
    severity: 'high',
    root_cause: 'synthetic test cause',
    attacker_model: 'synthetic input controller',
    attack_path: ['provide the changed input'],
    impact: 'synthetic impact',
    guarantee_broken: 'synthetic guarantee',
    confidence: 'high',
    how_to_disprove: 'inspect the changed input',
  }] }));
} else if (process.env.FAKE_PROVIDER_MODE === 'wrong-shape') {
  process.stdout.write(JSON.stringify({ findings: null }));
} else if (process.env.FAKE_PROVIDER_MODE === 'invalid-entry') {
  process.stdout.write(JSON.stringify({ findings: [{}] }));
} else if (['finding', 'refute-both', 'refute-one-error'].includes(process.env.FAKE_PROVIDER_MODE)) {
  process.stdout.write(JSON.stringify({ findings: [{
    title: 'Synthetic provider finding',
    file: 'src.js',
    line: 1,
    severity: 'high',
    root_cause: 'synthetic test cause',
    attacker_model: 'synthetic input controller',
    attack_path: ['provide the changed input'],
    impact: 'synthetic impact',
    guarantee_broken: 'synthetic guarantee',
    confidence: 'high',
    how_to_disprove: 'inspect the changed input',
  }] }));
} else {
  process.stdout.write(JSON.stringify({ findings: [] }));
}
`);

writeFileSync(FAKE_SCANNERS, `#!/bin/sh
mkdir -p "$2"
if [ "$FAKE_SCANNERS_MODE" = malformed-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{malformed' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = structural-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = result-empty ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake"}},"results":[{}]}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = degraded-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"degraded","reasonCode":"semgrep_rule_parse_error","detail":"rule parse error"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[]}},"results":[{"ruleId":"R1","level":"error","message":{"text":"partial scanner finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src.js"},"region":{"startLine":1}}}]}]}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = skipped-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"skipped","reasonCode":"not_applicable_no_lockfile","detail":"no lockfile"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = skipped-unknown ]; then
  printf '%s' '[{"tool":"fake","status":"skipped","reasonCode":"not_installed","detail":"not installed"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = skipped-missing-code ]; then
  printf '%s' '[{"tool":"fake","status":"skipped","detail":"not installed"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-missing-tool ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"executable_missing","detail":"not installed"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-backend ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"osv_backend_unreachable","detail":"backend unavailable"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-scanner-exit ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"scanner_exit_failure","detail":"exit 2"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-report-missing ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"report_missing","detail":"report absent"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-report-malformed ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"report_malformed","detail":"report malformed"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = error-report-invalid-shape ]; then
  printf '%s' '[{"tool":"fake","status":"error","reasonCode":"report_invalid_shape","detail":"report shape invalid"}]' > "$2/scanners.json"
elif [ "$FAKE_SCANNERS_MODE" = blocking-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","reasonCode":"completed","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake"}},"results":[{"ruleId":"R-block","level":"error","message":{"text":"blocking scanner finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src.js"},"region":{"startLine":1}}}]}]}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = warning-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","reasonCode":"completed","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake"}},"results":[{"ruleId":"R-warning","level":"warning","message":{"text":"nonblocking scanner finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src.js"},"region":{"startLine":1}}}]}]}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = empty-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = locationless-sarif ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[{"id":"R1","defaultConfiguration":{"level":"error"}}]}}, "results":[{"ruleId":"R1","message":{"text":"global scanner finding"}}]}]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = empty-metadata ]; then
  printf '%s' '[]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = unknown-status ]; then
  printf '%s' '[{"tool":"fake","status":"mystery","detail":"unknown"}]' > "$2/scanners.json"
  printf '%s' '{"version":"2.1.0","runs":[]}' > "$2/fake.sarif"
elif [ "$FAKE_SCANNERS_MODE" = ok-missing ]; then
  printf '%s' '[{"tool":"fake","status":"ok","detail":"scanned"}]' > "$2/scanners.json"
else
  printf '%s' '{malformed' > "$2/scanners.json"
fi
exit 0
`);
chmodSync(FAKE_SCANNERS, 0o755);

function git(cwd, ...args) {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' });
}

function makeSubject({ large = false } = {}) {
  const dir = mkdtempSync(join(WORK, 'subject-'));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'user.email', 'stage-health@example.invalid');
  git(dir, 'config', 'user.name', 'stage-health');
  writeFileSync(join(dir, 'base.txt'), 'base\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'base');
  git(dir, 'update-ref', 'refs/remotes/origin/main', 'refs/heads/main');
  const payload = large ? 'x'.repeat(500_000) : 'changed\n';
  writeFileSync(join(dir, 'src.js'), payload);
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'change');
  return dir;
}

function makeBrokenSubject() {
  const dir = makeSubject();
  git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/broken');
  return dir;
}

function makeFarChangeSubject() {
  const dir = mkdtempSync(join(WORK, 'subject-far-'));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'user.email', 'stage-health@example.invalid');
  git(dir, 'config', 'user.name', 'stage-health');
  writeFileSync(join(dir, 'src.js'), 'base\n'.repeat(50));
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'base');
  git(dir, 'update-ref', 'refs/remotes/origin/main', 'refs/heads/main');
  writeFileSync(join(dir, 'src.js'), 'base\n'.repeat(49) + 'changed\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'change');
  return dir;
}

function runCheck(subject, out, mode, extra = {}) {
  const env = { ...process.env };
  // These are intentionally ignored by the production CLI. Fixture stages
  // live at the canonical paths inside the copied tool tree below.
  env.SECURITY_STUDIO_HARNESS = join(WORK, 'ignored-harness.mjs');
  env.SECURITY_STUDIO_LAB = join(WORK, 'ignored-lab.mjs');
  env.SECURITY_STUDIO_SCANNERS = join(WORK, 'ignored-scanners.sh');
  env.SECURITY_STUDIO_CONFIG = join(WORK, 'ignored-config.json');
  if (mode !== 'real') {
    env.FAKE_HARNESS_MODE = mode;
  }
  if (extra.lab) env.FAKE_LAB_MODE = extra.labMode || 'not-reproduced';
  if (extra.labMode) env.FAKE_LAB_MODE = extra.labMode;
  if (extra.scannerMode) env.FAKE_SCANNERS_MODE = extra.scannerMode;
  if (extra.triageMode) env.FAKE_TRIAGE_MODE = extra.triageMode;
  const args = [CHECK_PR, '--target', 'generic', '--dir', subject, '--mode', 'local', '--base', 'main', '--out', out];
  if (extra.skipStatic !== false) args.push('--skip-static');
  if (extra.skipScanners !== false) args.push('--skip-scanners');
  if (extra.noLab) args.push('--no-lab');
  if (extra.maxLab) args.push('--max-lab', String(extra.maxLab));
  if (extra.skipAI) args.push('--skip-ai');
  try {
    const entrypoint = mode === 'real' ? ACTUAL_CHECK_PR : CHECK_PR;
    args[0] = entrypoint;
    const cwd = mode === 'real' ? ROOT : FIXTURE_ROOT;
    return { rc: 0, output: execFileSync(NODE, args, { cwd, env, encoding: 'utf8' }) };
  } catch (error) {
    return { rc: error.status, output: (error.stdout || '') + (error.stderr || '') };
  }
}

function artifacts(out) {
  return {
    gate: JSON.parse(readFileSync(join(out, 'gate.json'), 'utf8')),
    report: readFileSync(join(out, 'report.md'), 'utf8'),
  };
}

function withFixtureBlockOn(blockOn, callback) {
  const configPath = join(FIXTURE_ROOT, 'security/redteam/config.json');
  const original = readFileSync(configPath);
  const config = JSON.parse(original);
  config.gate.blockOn = blockOn;
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  try {
    return callback();
  } finally {
    writeFileSync(configPath, original);
  }
}

function withFixtureTriageConfig(callback) {
  const configPath = join(FIXTURE_ROOT, 'security/redteam/config.json');
  const original = readFileSync(configPath);
  const config = JSON.parse(original);
  config.defaultProvider = 'fake';
  config.providers = {
    fake: { type: 'cli', command: [NODE, FAKE_TRIAGE_PROVIDER], promptArg: false, modelFlag: '--model', timeoutMs: 5000 },
  };
  config.triage = { model: 'fake:triage' };
  config.report = { model: 'fake:triage' };
  config.hunt = { ...(config.hunt || {}), lenses: [] };
  config.verify = { models: [], refuteThreshold: 2 };
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  try {
    return callback();
  } finally {
    writeFileSync(configPath, original);
  }
}

function withFixtureFalsePositiveTriage(callback) {
  const triagePath = join(FIXTURE_ROOT, 'security/redteam/triage.mjs');
  const original = readFileSync(triagePath);
  const fakeTriage = [
    "#!/usr/bin/env node",
    "import { readFileSync, writeFileSync } from 'node:fs';",
    "const args = process.argv.slice(2);",
    "const findings = JSON.parse(readFileSync(args[args.indexOf('--findings') + 1], 'utf8'));",
    "const out = args[args.indexOf('--out') + 1];",
    "const triaged = findings.findings.map((finding) => ({ ...finding, scannerSeverity: finding.scannerSeverity || finding.severity, verdict: 'false_positive', reason: 'bounded Studio control fixture' }));",
    "const dropped = triaged.filter((finding) => finding.verdict === 'false_positive').length;",
    "const blocking = triaged.filter((finding) => ['critical', 'high', 'error'].includes(finding.scannerSeverity)).length;",
    "writeFileSync(out, JSON.stringify({ schemaVersion: 1, stage: 'triage', runId: process.env.SECURITY_STUDIO_RUN_ID, status: 'complete', outcome: blocking ? 'block' : 'pass', exit: blocking ? 1 : 0, reasonCodes: [], triaged, dropped, blocking, dismissedButBlocked: blocking }, null, 2));",
    "process.exit(blocking ? 1 : 0);",
  ].join("\n") + "\n";
  writeFileSync(triagePath, fakeTriage);
  try {
    return callback(original);
  } finally {
    writeFileSync(triagePath, original);
  }
}

test.after(() => {
  rmSync(WORK, { recursive: true, force: true });
  rmSync(FIXTURE_ROOT, { recursive: true, force: true });
});

test('fixture entrypoint is byte-identical to production check-pr', () => {
  assert.deepEqual(readFileSync(CHECK_PR), readFileSync(ACTUAL_CHECK_PR));
});

test('real oversized diff cannot pass through an empty findings file', () => {
  const out = mkdtempSync(join(WORK, 'oversized-'));
  const result = runCheck(makeSubject({ large: true }), out, 'real', { noLab: true });
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(report, /harness execution failed: diff_too_large/);
  assert.equal(JSON.parse(readFileSync(join(out, 'harness/execution.json'))).status, 'failed');
});

test('failed git diff cannot become an empty clean scan', () => {
  const out = mkdtempSync(join(WORK, 'diff-failure-'));
  const result = runCheck(makeBrokenSubject(), out, 'clean', { skipAI: true });
  assert.equal(result.rc, 3);
  assert.match(result.output, /git diff failed/);
});

for (const mode of ['setup', 'terminated', 'malformed', 'missing', 'stale']) {
  test(`harness ${mode} is incomplete even with empty findings`, () => {
    const out = mkdtempSync(join(WORK, `${mode}-`));
    const result = runCheck(makeSubject(), out, mode, { noLab: true });
    const { gate } = artifacts(out);
    assert.equal(result.rc, 2);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /harness execution incomplete/);
  });
}

test('scanner normalization failure blocks with no findings', () => {
  const out = mkdtempSync(join(WORK, 'scanner-failure-'));
  const result = runCheck(makeSubject(), out, 'clean', { skipScanners: false, scanners: true, noLab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /scanners execution failed/);
});

for (const scannerMode of ['malformed-sarif', 'structural-sarif', 'result-empty']) {
  test(`${scannerMode} cannot pass as an empty scanner result`, () => {
    const out = mkdtempSync(join(WORK, `scanner-${scannerMode}-`));
    const result = runCheck(makeSubject(), out, 'clean', {
      skipScanners: false,
      scanners: true,
      scannerMode,
      noLab: true,
    });
    const { gate } = artifacts(out);
    assert.equal(result.rc, 1);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /scanners execution failed/);
    assert.match(gate.reasons.join(';'), /normalization_failed/);
  });
}

for (const scannerMode of ['empty-metadata', 'unknown-status', 'ok-missing']) {
  test(scannerMode + ' scanner metadata cannot produce a clean result', () => {
    const out = mkdtempSync(join(WORK, 'scanner-' + scannerMode + '-'));
    const result = runCheck(makeSubject(), out, 'clean', {
      skipScanners: false,
      scanners: true,
      scannerMode,
      noLab: true,
    });
    const { gate } = artifacts(out);
    assert.equal(result.rc, 1);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /scanners execution failed/);
    assert.match(gate.reasons.join(';'), /normalization_failed/);
  });
}

test('locationless SARIF findings survive diff normalization', () => {
  const out = mkdtempSync(join(WORK, 'scanner-locationless-'));
  const result = runCheck(makeFarChangeSubject(), out, 'clean', {
    skipScanners: false,
    scanners: true,
    scannerMode: 'locationless-sarif',
    skipAI: true,
    noLab: true,
  });
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  const { gate } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.equal(normalized.findings.length, 1);
  assert.equal(normalized.findings[0].file, '');
  assert.equal(normalized.findings[0].message, 'global scanner finding');
});

test('blocking scanner finding remains blocking when AI is explicitly skipped', () => {
  const out = mkdtempSync(join(WORK, 'scanner-blocking-skip-ai-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'blocking-sarif',
    skipAI: true,
    noLab: true,
  });
  const { gate } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.equal(normalized.blocking, 1);
  assert.match(gate.reasons.join(';'), /scanner error: R-block/);
});

test('configured warning severity blocks under AI skip even when normalize default does not', () => {
  const out = mkdtempSync(join(WORK, 'scanner-warning-configured-block-'));
  const configPath = join(FIXTURE_ROOT, 'security/redteam/config.json');
  const originalConfig = readFileSync(configPath);
  const result = withFixtureBlockOn(['critical', 'high', 'error', 'warning'], () => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    skipAI: true,
    noLab: true,
  }));
  const { gate } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  assert.deepEqual(readFileSync(configPath), originalConfig);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.equal(normalized.blocking, 0);
  assert.equal(normalized.findings[0].severity, 'warning');
  assert.match(gate.reasons.join(';'), /scanner warning: R-warning/);
});

function withFixtureEmptyTriage(callback) {
  const triagePath = join(FIXTURE_ROOT, 'security/redteam/triage.mjs');
  const original = readFileSync(triagePath);
  const fakeTriage = [
    '#!/usr/bin/env node',
    "import { writeFileSync } from 'node:fs';",
    "const out = process.argv[process.argv.indexOf('--out') + 1];",
    "writeFileSync(out, JSON.stringify({ schemaVersion: 1, stage: 'triage', runId: process.env.SECURITY_STUDIO_RUN_ID, status: 'complete', outcome: 'pass', exit: 0, reasonCodes: [], triaged: [], dropped: 0, blocking: 0, dismissedButBlocked: 0 }, null, 2));",
    'process.exit(0);',
  ].join('\n') + '\n';
  writeFileSync(triagePath, fakeTriage);
  try {
    return callback();
  } finally {
    writeFileSync(triagePath, original);
  }
}

test('normal triage false-positive clears raw warning scanner finding', () => {
  const out = mkdtempSync(join(WORK, 'scanner-triage-warning-false-positive-'));
  const originalTriage = readFileSync(join(FIXTURE_ROOT, 'security/redteam/triage.mjs'));
  const result = withFixtureFalsePositiveTriage(() => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    noLab: true,
  }));
  assert.deepEqual(readFileSync(join(FIXTURE_ROOT, 'security/redteam/triage.mjs')), originalTriage);
  const { gate, report } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  const triaged = JSON.parse(readFileSync(join(out, 'triaged.json'), 'utf8'));
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
  assert.equal(normalized.blocking, 0);
  assert.equal(triaged.dropped, 1);
  assert.equal(triaged.blocking, 0);
  assert.equal(triaged.triaged[0].scannerSeverity, 'warning');
  assert.match(report, /triage \| ok 0 \| 0 kept/);
});

test('normal triage false-positive keeps raw error scanner finding blocked', () => {
  const out = mkdtempSync(join(WORK, 'scanner-triage-error-false-positive-'));
  const originalTriage = readFileSync(join(FIXTURE_ROOT, 'security/redteam/triage.mjs'));
  const result = withFixtureFalsePositiveTriage(() => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'blocking-sarif',
    noLab: true,
  }));
  assert.deepEqual(readFileSync(join(FIXTURE_ROOT, 'security/redteam/triage.mjs')), originalTriage);
  const { gate, report } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  const triaged = JSON.parse(readFileSync(join(out, 'triaged.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.equal(normalized.blocking, 1);
  assert.equal(triaged.dropped, 1);
  assert.equal(triaged.blocking, 1);
  assert.equal(triaged.dismissedButBlocked, 1);
  assert.doesNotMatch(gate.reasons.join('; '), /triage execution incomplete/);
  assert.equal(triaged.triaged[0].scannerSeverity, 'error');
  assert.match(report, /triage \| FAIL 1 \| 0 kept/);
});

for (const triageMode of ['invalid-verdict', 'invalid-severity']) {
  test('invalid triage ' + triageMode + ' is incomplete, never clean', () => {
    const out = mkdtempSync(join(WORK, 'triage-invalid-' + triageMode + '-'));
    const result = withFixtureTriageConfig(() => runCheck(makeSubject(), out, 'clean', {
      skipScanners: false,
      scannerMode: 'warning-sarif',
      triageMode,
      noLab: true,
    }));
    const { gate, report } = artifacts(out);
    const triaged = JSON.parse(readFileSync(join(out, 'triaged.json'), 'utf8'));
    assert.equal(result.rc, 2);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /invalid_model_output/);
    assert.equal(triaged.status, 'incomplete');
    assert.equal(triaged.outcome, 'inconclusive');
    assert.equal(triaged.exit, 3);
    assert.deepEqual(triaged.reasonCodes, ['invalid_model_output']);
    assert.equal(triaged.triaged.length, 1);
    assert.equal(triaged.triaged[0].verdict, 'needs_human');
    assert.equal(triaged.triaged[0].scannerSeverity, 'warning');
    assert.match(report, /triage execution incomplete/);
  });
}

test('complete triage artifact must account for every scanner finding', () => {
  const out = mkdtempSync(join(WORK, 'triage-coverage-mismatch-'));
  const result = withFixtureEmptyTriage(() => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    noLab: true,
  }));
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /triage_coverage_mismatch/);
  assert.match(report, /triage execution incomplete/);
});

test('normal triage true-positive remains blocking with complete artifact', () => {
  const out = mkdtempSync(join(WORK, 'triage-true-positive-'));
  const result = withFixtureTriageConfig(() => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    triageMode: 'true-positive',
    noLab: true,
  }));
  const { gate, report } = artifacts(out);
  const triaged = JSON.parse(readFileSync(join(out, 'triaged.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.equal(triaged.status, 'complete');
  assert.equal(triaged.outcome, 'block');
  assert.equal(triaged.exit, 1);
  assert.equal(triaged.blocking, 1);
  assert.equal(triaged.triaged[0].severity, 'high');
  assert.equal(triaged.triaged[0].scannerSeverity, 'warning');
  assert.doesNotMatch(gate.reasons.join(';'), /triage execution incomplete/);
  assert.match(report, /triage \| FAIL 1 \| 1 kept/);
});

test('triage preserves scanner identity when model supplies identity fields', () => {
  const out = mkdtempSync(join(WORK, 'triage-identity-'));
  const result = withFixtureTriageConfig(() => runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    triageMode: 'true-positive',
    noLab: true,
  }));
  const triaged = JSON.parse(readFileSync(join(out, 'triaged.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(triaged.triaged[0].file, 'src.js');
  assert.equal(triaged.triaged[0].line, 1);
  assert.equal(triaged.triaged[0].ruleId, 'R-warning');
  assert.equal(triaged.triaged[0].tool, 'fake');
});

test('list-targets registry failure exits without mutating scan artifacts', () => {
  const fixture = mkdtempSync(join(WORK, 'malformed-registry-'));
  cpSync(join(ROOT, 'security'), join(fixture, 'security'), { recursive: true });
  writeFileSync(join(fixture, 'security/studio/targets.json'), '{');
  const out = join(fixture, 'out');
  let result;
  try {
    execFileSync(NODE, [
      join(fixture, 'security/studio/check-pr.mjs'),
      '--list-targets',
      '--out', out,
    ], { cwd: fixture, encoding: 'utf8' });
    result = { rc: 0 };
  } catch (error) {
    result = { rc: error.status, output: (error.stdout || '') + (error.stderr || '') };
  }
  assert.equal(result.rc, 3);
  assert.equal(existsSync(join(out, 'gate.json')), false);
  assert.equal(existsSync(join(out, 'report.md')), false);
});

test('usage errors replace prior artifacts while omitted mode infers local', () => {
  const subject = makeSubject();
  const out = mkdtempSync(join(WORK, 'usage-stale-artifacts-'));
  const runActual = (extra) => {
    const args = [
      ACTUAL_CHECK_PR,
      '--dir', subject,
      '--base', 'main',
      '--skip-static',
      '--skip-scanners',
      '--skip-ai',
      '--no-lab',
      '--out', out,
      ...extra,
    ];
    try {
      return { rc: 0, output: execFileSync(NODE, args, { cwd: ROOT, encoding: 'utf8' }) };
    } catch (error) {
      return {
        rc: error.status,
        output: (error.stdout || '') + (error.stderr || ''),
      };
    }
  };

  const first = runActual([]);
  assert.equal(first.rc, 0);
  const previous = readFileSync(join(out, 'report.md'), 'utf8');
  const firstGate = JSON.parse(readFileSync(join(out, 'gate.json'), 'utf8'));
  let artifactsNow;

  const helpStray = runActual(['--help', 'stray']);
  assert.equal(helpStray.rc, 3);
  assert.match(helpStray.output, /unexpected argument: stray/);
  const afterHelpStray = artifacts(out);
  assert.equal(afterHelpStray.report, previous);
  assert.deepEqual(afterHelpStray.gate, firstGate);

  const listStray = runActual(['--list-targets', 'stray']);
  assert.equal(listStray.rc, 3);
  assert.match(listStray.output, /unexpected argument: stray/);
  const afterListStray = artifacts(out);
  assert.equal(afterListStray.report, previous);
  assert.deepEqual(afterListStray.gate, firstGate);

  const strayArgument = runActual(['--mode', 'local', 'stray']);
  assert.equal(strayArgument.rc, 3);
  artifactsNow = artifacts(out);
  assert.match(strayArgument.output, /unexpected argument: stray/);
  assert.match(artifactsNow.report, /unexpected argument: stray/);
  assert.notEqual(artifactsNow.report, previous);

  const missingPr = runActual(['--pr']);
  assert.equal(missingPr.rc, 3);
  artifactsNow = artifacts(out);
  assert.match(missingPr.output, /missing value for --pr/);
  assert.equal(artifactsNow.gate.blocked, true);
  assert.match(artifactsNow.report, /missing value for --pr/);
  assert.notEqual(artifactsNow.report, previous);

  const unknownTarget = runActual(['--mode', 'local', '--target', 'does-not-exist']);
  assert.equal(unknownTarget.rc, 3);
  artifactsNow = artifacts(out);
  assert.equal(artifactsNow.gate.blocked, true);
  assert.match(artifactsNow.report, /unknown --target/);
  assert.notEqual(artifactsNow.report, previous);

  const invalidMode = runActual(['--mode', 'typo']);
  assert.equal(invalidMode.rc, 3);
  artifactsNow = artifacts(out);
  assert.equal(artifactsNow.gate.blocked, true);
  assert.match(artifactsNow.report, /invalid --mode/);
  assert.notEqual(artifactsNow.report, previous);
  assert.notEqual(artifactsNow.gate.runId, firstGate.runId);

});

test('stale top-level artifacts are invalidated on an early pipeline failure', () => {
  const out = mkdtempSync(join(WORK, 'stale-top-level-'));
  const first = runCheck(makeSubject(), out, 'clean', { noLab: true });
  assert.equal(first.rc, 0);
  const previous = readFileSync(join(out, 'report.md'), 'utf8');
  const second = runCheck(makeBrokenSubject(), out, 'clean', { noLab: true });
  const { gate, report } = artifacts(out);
  assert.equal(second.rc, 3);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /pipeline_error/);
  assert.match(report, /pipeline did not produce a complete scan/);
  assert.notEqual(report, previous);
});

test('nonblocking scanner finding remains pass when AI is explicitly skipped', () => {
  const out = mkdtempSync(join(WORK, 'scanner-warning-skip-ai-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scannerMode: 'warning-sarif',
    skipAI: true,
    noLab: true,
  });
  const { gate, report } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
  assert.equal(normalized.blocking, 0);
  assert.equal(normalized.findings[0].severity, 'warning');
  assert.match(report, /configured gate passed; see executed and skipped stages below/);
  assert.doesNotMatch(report, /no blocking findings after verification/);
});

test('valid empty SARIF remains a clean scanner result', () => {
  const out = mkdtempSync(join(WORK, 'scanner-empty-sarif-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scanners: true,
    scannerMode: 'empty-sarif',
    noLab: true,
  });
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
  assert.match(report, /scanners \| ok 0 \| 0 finding\(s\)/);
});

test('degraded scanner report is incomplete while retaining findings', () => {
  const out = mkdtempSync(join(WORK, 'scanner-degraded-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scanners: true,
    scannerMode: 'degraded-sarif',
    skipAI: true,
    noLab: true,
  });
  const { gate } = artifacts(out);
  const normalized = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /scanners execution incomplete/);
  assert.match(gate.reasons.join(';'), /scanner_degraded/);
  assert.equal(normalized.findings.length, 1);
  assert.equal(normalized.findings[0].message, 'partial scanner finding');
});

test('only no-lockfile skip is neutral without SARIF', () => {
  const out = mkdtempSync(join(WORK, 'scanner-skipped-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipScanners: false,
    scanners: true,
    scannerMode: 'skipped-sarif',
    skipAI: true,
    noLab: true,
  });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
});

for (const scannerMode of ['skipped-unknown', 'skipped-missing-code']) {
  test(`${scannerMode} is incomplete rather than a clean skip`, () => {
    const out = mkdtempSync(join(WORK, `scanner-${scannerMode}-`));
    const result = runCheck(makeSubject(), out, 'clean', {
      skipScanners: false,
      scanners: true,
      scannerMode,
      skipAI: true,
      noLab: true,
    });
    const { gate } = artifacts(out);
    assert.equal(result.rc, 2);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /scanners execution incomplete/);
    assert.match(gate.reasons.join(';'), /scanner_metadata_incomplete/);
  });
}

for (const scannerMode of ['error-missing-tool', 'error-backend', 'error-scanner-exit', 'error-report-missing', 'error-report-malformed', 'error-report-invalid-shape']) {
  test(`${scannerMode} remains a failed scanner stage`, () => {
    const out = mkdtempSync(join(WORK, `scanner-${scannerMode}-`));
    const result = runCheck(makeSubject(), out, 'clean', {
      skipScanners: false,
      scanners: true,
      scannerMode,
      skipAI: true,
      noLab: true,
    });
    const { gate } = artifacts(out);
    assert.equal(result.rc, 1);
    assert.equal(gate.blocked, true);
    assert.match(gate.reasons.join(';'), /scanners execution failed/);
    assert.match(gate.reasons.join(';'), /normalization_failed/);
    const normalizeLog = readFileSync(join(out, 'normalize.log'), 'utf8');
    assert.match(normalizeLog, /Scanner tool failure: fake/);
    assert.doesNotMatch(normalizeLog, /unknown or missing reasonCode/);
  });
}

test('explicit --skip-scanners remains an operator-neutral skip', () => {
  const out = mkdtempSync(join(WORK, 'scanner-explicit-skip-'));
  const result = runCheck(makeSubject(), out, 'clean', {
    skipAI: true,
    noLab: true,
  });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
});

test('clean completed empty harness scan passes', () => {
  const out = mkdtempSync(join(WORK, 'clean-'));
  const result = runCheck(makeSubject(), out, 'clean', { noLab: true });
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
  assert.match(report, /harness \| ok 0/);
});

test('completed genuine finding blocks', () => {
  const out = mkdtempSync(join(WORK, 'finding-'));
  const result = runCheck(makeSubject(), out, 'finding', { noLab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness high/);
});

test('independent lab refutation clears only a completed finding', () => {
  const out = mkdtempSync(join(WORK, 'refuted-'));
  const result = runCheck(makeSubject(), out, 'finding', { lab: true });
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 0);
  assert.equal(gate.blocked, false);
  assert.match(report, /lab \| ok 0 \| 0 reproduced \/ 1 run/);
});

test('Lab verdict cannot alias an untested same-location finding', () => {
  const out = mkdtempSync(join(WORK, 'lab-same-location-'));
  const result = runCheck(makeSubject(), out, 'same-location', {
    lab: true,
    maxLab: 1,
  });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness high: Finding B/);
  assert.doesNotMatch(gate.reasons.join(';'), /lab cleared: Finding B/);
});

test('Lab verdict cannot alias identical title and location', () => {
  const out = mkdtempSync(join(WORK, 'lab-identical-location-'));
  const result = runCheck(makeSubject(), out, 'identical-location', {
    lab: true,
    maxLab: 1,
  });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness high: Same finding/);
  assert.equal(gate.reasons.filter((reason) => reason === 'lab cleared: Same finding').length, 1);
});

test('missing Lab report remains incomplete with isolated candidate paths', () => {
  const out = mkdtempSync(join(WORK, 'lab-missing-report-'));
  const result = runCheck(makeSubject(), out, 'same-title-missing-report', {
    lab: true,
    labMode: 'missing-second-report',
    maxLab: 2,
  });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /lab execution incomplete/);
});

test('lab refutation cannot clear an incomplete harness', () => {
  const out = mkdtempSync(join(WORK, 'failed-refuted-'));
  const result = runCheck(makeSubject(), out, 'failed-finding', { lab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness execution incomplete/);
});

test('execution artifact cannot call exit 3 a complete pass', () => {
  const out = mkdtempSync(join(WORK, 'semantic-'));
  const result = runCheck(makeSubject(), out, 'semantic', { noLab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness execution incomplete/);
  assert.match(gate.reasons.join(';'), /outcome_exit_mismatch/);
});

test('declared complete block must have a blocking finding', () => {
  const out = mkdtempSync(join(WORK, 'block-empty-'));
  const result = runCheck(makeSubject(), out, 'block-empty', { noLab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /outcome_findings_mismatch/);
});

test('incomplete blocking result remains a valid blocking outcome', () => {
  const out = mkdtempSync(join(WORK, 'partial-block-'));
  const result = runCheck(makeSubject(), out, 'partial-block', { noLab: true });
  const { gate } = artifacts(out);
  assert.equal(result.rc, 2);
  assert.equal(gate.blocked, true);
  assert.match(gate.reasons.join(';'), /harness high/);
  assert.doesNotMatch(gate.reasons.join(';'), /outcome_findings_mismatch/);
});

test('reproduced Lab result keeps complete health while blocking', () => {
  const out = mkdtempSync(join(WORK, 'reproduced-'));
  const result = runCheck(makeSubject(), out, 'finding', { lab: true, labMode: 'reproduced' });
  const { gate, report } = artifacts(out);
  assert.equal(result.rc, 1);
  assert.equal(gate.blocked, true);
  assert.match(report, /lab \| FAIL 1 \| 1 reproduced \/ 1 run/);
  assert.doesNotMatch(gate.reasons.join(';'), /lab execution incomplete/);
});

function runHarnessWithConfig({ models, verifyModels = [], providerMode = 'clean' }) {
  const out = mkdtempSync(join(WORK, 'direct-harness-'));
  const diff = join(out, 'diff.patch');
  const config = join(out, 'config.json');
  writeFileSync(diff, 'diff --git a/src.js b/src.js\n+changed\n');
  writeFileSync(config, JSON.stringify({
    defaultProvider: 'fake',
    providers: {
      fake: { type: 'cli', command: [NODE, FAKE_PROVIDER], promptArg: false, modelFlag: '--model', timeoutMs: 5000 },
    },
    hunt: {
      lenses: ['available', 'missing', 'skipped'],
      models,
      fallbackModels: [],
    },
    verify: { models: verifyModels, refuteThreshold: 2 },
    report: { model: 'fake:test' },
    gate: { blockOn: ['critical', 'high'], maxDiffBytes: 10000 },
  }, null, 2));
  let rc = 0;
  try {
    execFileSync(NODE, [HARNESS, '--diff', diff, '--out', out, '--config', config], {
      cwd: ROOT,
      env: { ...process.env, FAKE_PROVIDER_MODE: providerMode },
      encoding: 'utf8',
    });
  } catch (error) {
    rc = error.status;
  }
  return { out, rc, execution: JSON.parse(readFileSync(join(out, 'execution.json'), 'utf8')) };
}

test('partially unavailable requested lens is incomplete, while explicit skip is neutral', () => {
  const partial = runHarnessWithConfig({
    models: { available: 'fake:test', missing: 'unavailable:test' },
  });
  assert.equal(partial.rc, 3);
  assert.equal(partial.execution.status, 'incomplete');
  assert.equal(partial.execution.outcome, 'inconclusive');
  assert.ok(partial.execution.reasonCodes.includes('requested_lens_unavailable'));

  const skipped = runHarnessWithConfig({ models: { available: 'fake:test' } });
  assert.equal(skipped.rc, 0);
  assert.equal(skipped.execution.status, 'complete');
  assert.equal(skipped.execution.outcome, 'pass');
  assert.deepEqual(skipped.execution.reasonCodes, []);
});

for (const providerMode of ['malformed', 'wrong-shape', 'invalid-entry']) {
  test(`hunt provider ${providerMode} is incomplete, not a clean pass`, () => {
    const result = runHarnessWithConfig({
      models: { available: 'fake:test' },
      providerMode,
    });
    assert.equal(result.rc, 3);
    assert.equal(result.execution.status, 'incomplete');
    assert.equal(result.execution.outcome, 'inconclusive');
    assert.ok(result.execution.reasonCodes.includes('hunt_failed'));
  });
}

test('invalid verifier severity cannot downgrade a blocking finding', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:verifier'],
    providerMode: 'bogus-verdict',
  });
  const out = result.out;
  const execution = result.execution;
  const findings = JSON.parse(readFileSync(join(out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(execution.outcome, 'block');
  assert.equal(execution.exit, 1);
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].verdicts[0].reason, 'unparseable or invalid verdict');
  assert.equal(findings[0].verdicts[0].model, 'fake:verifier');
});

test('two independent refutations meet the configured quorum', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:one', 'fake:two'],
    providerMode: 'refute-both',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 0);
  assert.equal(result.execution.status, 'complete');
  assert.equal(result.execution.outcome, 'pass');
  assert.equal(findings[0].survived, false);
  assert.equal(findings[0].refutations, 2);
  assert.deepEqual(findings[0].verdicts.map((verdict) => verdict.model).sort(), ['fake:one', 'fake:two']);
});

test('duplicate verifier identities cannot satisfy two independent votes', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:one', 'fake:one'],
    providerMode: 'refute-both',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.equal(result.execution.outcome, 'block');
  assert.ok(result.execution.reasonCodes.includes('verification_incomplete'));
  assert.equal(findings[0].survived, true);
  assert.equal(findings[0].unverified, true);
  assert.equal(findings[0].verdicts.length, 1);
  assert.equal(findings[0].refutations, 1);
});

test('canonical provider identity deduplicates bare aliases', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:one', 'one'],
    providerMode: 'refute-both',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.ok(result.execution.reasonCodes.includes('verification_incomplete'));
  assert.equal(findings[0].verdicts.length, 1);
  assert.equal(findings[0].refutations, 1);
  assert.equal(findings[0].unverified, true);
});

test('hunter alias is excluded from independent verifier panel', () => {
  const result = runHarnessWithConfig({
    models: { available: 'one' },
    verifyModels: ['fake:one', 'fake:two'],
    providerMode: 'refute-both',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.ok(result.execution.reasonCodes.includes('verification_incomplete'));
  assert.deepEqual(findings[0].verdicts.map((verdict) => verdict.model), ['fake:two']);
  assert.equal(findings[0].refutations, 1);
  assert.equal(findings[0].unverified, true);
});

test('hunter identity alone cannot provide an independent refuter', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:test'],
    providerMode: 'refute-both',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.equal(result.execution.outcome, 'block');
  assert.ok(result.execution.reasonCodes.includes('verification_incomplete'));
  assert.equal(findings[0].survived, true);
  assert.equal(findings[0].unverified, true);
  assert.equal(findings[0].verdicts.length, 0);
});

test('one refuter plus one inconclusive verdict cannot meet the quorum', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    verifyModels: ['fake:one', 'fake:two'],
    providerMode: 'refute-one-error',
  });
  const findings = JSON.parse(readFileSync(join(result.out, 'findings.json'), 'utf8'));
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.equal(result.execution.outcome, 'block');
  assert.ok(result.execution.reasonCodes.includes('verification_incomplete'));
  assert.equal(findings[0].survived, true);
  assert.equal(findings[0].unverified, true);
  assert.equal(findings[0].refutations, 1);
  assert.equal(findings[0].verdicts.filter((verdict) => verdict.inconclusive).length, 1);
});

test('valid hunt finding keeps ordinary blocking behavior', () => {
  const result = runHarnessWithConfig({
    models: { available: 'fake:test' },
    providerMode: 'finding',
  });
  assert.equal(result.rc, 1);
  assert.equal(result.execution.status, 'incomplete');
  assert.equal(result.execution.outcome, 'block');
  assert.equal(result.execution.exit, 1);
});
