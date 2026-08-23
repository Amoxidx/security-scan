#!/usr/bin/env node
/**
 * Repro-stage measurement over the eval corpus — manual only, never CI.
 *
 * Drives security/lab/run.mjs as a child process (the same shape check-pr.mjs
 * uses). Does not talk to Docker, the sandbox, or a model provider itself.
 *
 * Two arms:
 *   vuln    finding from meta.summary + ground_truth; after/ staged as code-dir.
 *           reproduced = success.
 *   benign  finding from meta.adversarial_finding (the bug this clean case
 *           could be mistaken for). reproduced = false-repro.
 *           not-reproduced counts as clean discrimination only when at least
 *           one turn actually ran in the sandbox and failed with a normal
 *           program exit 1..125 (not timedOut). 0 is reproduced; 126/127
 *           are exec errors (script never ran); ≥128 is a signal death.
 *           A conclude-without-execute is not-reproduced-unfair.
 *
 * Fail-closed: inconclusive and setup-error never count as reproduced and
 * never count as clean discrimination.
 *
 * Usage:
 *   node security/eval/repro.mjs --only vuln-016-negative-amount,benign-011-amount-validated
 *   node security/eval/repro.mjs --kind vuln --model claude-cli:claude-opus-5
 *   node security/eval/repro.mjs --only <id[,id]> [--kind vuln|benign]
 *                              [--model <spec>] [--out <dir>] [--config <file>]
 *                              [--timeout-s <n>] [--max-turns <n>]
 *                              [--sandbox-timeout-s <n>] [--corpus <dir>]
 *
 * A full corpus run is ~60 min. Prefer --only / --kind.
 *
 * Exit: 0 wrote a report, 1 empty/invalid corpus or internal error, 3 usage.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  existsSync,
  cpSync,
  rmSync,
  statSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_LAB_MODEL } from '../studio/lab-model.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../..');
const LAB = join(REPO, 'security/lab/run.mjs');
const DEFAULT_CONFIG = join(REPO, 'security/redteam/config.json');
const DEFAULT_CORPUS = join(HERE, 'corpus');
const VALID_VERDICTS = new Set(['reproduced', 'not-reproduced', 'inconclusive']);
const ADV_FIELDS = ['title', 'file', 'line', 'severity', 'class', 'cwe', 'summary'];

// ---------------------------------------------------------------- args

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error(`unexpected argument: ${a}`);
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function usage(msg) {
  if (msg) console.error(msg);
  console.error(`Usage: node security/eval/repro.mjs [options]
  --only <id[,id]>           Restrict to these case ids (substring or exact)
  --kind vuln|benign         Restrict to one arm
  --model <spec>             Passed to lab/run.mjs (default: config.lab.model)
  --out <dir>                Report root (default: security/eval/results)
  --config <file>            Provider config (default: security/redteam/config.json)
  --corpus <dir>             Corpus root (default: security/eval/corpus)
  --timeout-s <n>            Lab wall-clock per case (default: config.lab.timeoutS)
  --max-turns <n>            Lab turn cap (default: config.lab.maxTurns)
  --sandbox-timeout-s <n>    Per-script sandbox timeout, passed through to lab`);
  process.exit(3);
}

// ---------------------------------------------------------------- finding construction

export function findingFromCase(testCase) {
  if (testCase.kind === 'benign') {
    const af = testCase.adversarial_finding;
    if (!af || typeof af !== 'object' || Array.isArray(af)) {
      throw new Error(`${testCase.id}: missing adversarial_finding`);
    }
    for (const field of ADV_FIELDS) {
      if (af[field] === undefined || af[field] === null || af[field] === '') {
        throw new Error(`${testCase.id}: adversarial_finding.${field} missing`);
      }
    }
    if (!Number.isInteger(af.line) || af.line < 1) {
      throw new Error(`${testCase.id}: adversarial_finding.line must be an integer ≥ 1`);
    }
    return {
      title: af.title,
      summary: af.summary,
      file: af.file,
      line: af.line,
      severity: af.severity,
      class: af.class,
      cwe: af.cwe,
    };
  }

  const gt = testCase.ground_truth;
  if (!gt || typeof gt.file !== 'string' || !gt.file) {
    throw new Error(`${testCase.id}: missing ground_truth.file`);
  }
  const line = Array.isArray(gt.lines) && gt.lines.length ? gt.lines[0] : null;
  if (!Number.isInteger(line) || line < 1) {
    throw new Error(`${testCase.id}: ground_truth.lines[0] must be an integer ≥ 1`);
  }
  const summary = String(testCase.summary || '');
  if (!summary) throw new Error(`${testCase.id}: missing summary`);
  return {
    title: summary,
    summary,
    file: gt.file,
    line,
    severity: testCase.severity,
    class: testCase.class,
    cwe: testCase.cwe,
  };
}

function assertFindingFile(finding, afterDir, id, { checkLine = false } = {}) {
  const target = join(afterDir, finding.file);
  if (!existsSync(target) || !statSync(target).isFile()) {
    throw new Error(`${id}: finding.file ${finding.file} is not a file under after/`);
  }
  if (!checkLine) return;
  const n = readFileSync(target, 'utf8').split('\n').length;
  if (finding.line > n) {
    throw new Error(`${id}: finding.line ${finding.line} is past end of ${finding.file} (${n} lines)`);
  }
}

// ---------------------------------------------------------------- fairness + aggregation

/**
 * A sandbox turn is a fair executed fail only when the script actually ran
 * and exited as a program: integer exitCode in 1..125, and not timedOut.
 * 0 means the exploit held (reproduced). 126/127 mean the binary/script
 * never executed (not executable / ENOENT). ≥128 is death by signal
 * (e.g. 137 = SIGKILL from the memory cap), not "defect absent".
 * A conclude-without-execute has no such turn.
 */
export function hasFairSandboxFail(report) {
  const turns = Array.isArray(report?.turns) ? report.turns : [];
  return turns.some((t) => {
    const sb = t?.sandbox;
    if (!sb || typeof sb !== 'object') return false;
    if (sb.timedOut) return false;
    const exitCode = sb.exitCode;
    if (!Number.isInteger(exitCode)) return false;
    return exitCode >= 1 && exitCode <= 125;
  });
}

export function labVerdict(report, labStatus) {
  if (report && VALID_VERDICTS.has(report.verdict)) return report.verdict;
  if (labStatus === 3) return 'setup-error';
  return 'inconclusive';
}

export function classifyCase(kind, report, labStatus) {
  const verdict = labVerdict(report, labStatus);
  if (verdict === 'setup-error' || verdict === 'inconclusive') {
    return { verdict, outcome: verdict, fair: false };
  }
  if (kind === 'vuln') {
    return { verdict, outcome: verdict, fair: verdict === 'reproduced' };
  }
  if (verdict === 'reproduced') {
    return { verdict, outcome: 'false-repro', fair: false };
  }
  if (verdict === 'not-reproduced') {
    const fair = hasFairSandboxFail(report);
    return {
      verdict,
      outcome: fair ? 'not-reproduced' : 'not-reproduced-unfair',
      fair,
    };
  }
  return { verdict: 'inconclusive', outcome: 'inconclusive', fair: false };
}

function rate(numer, denom) {
  if (!denom) return null;
  return Number(((numer / denom) * 100).toFixed(1));
}

export function aggregateRows(rows) {
  const vuln = rows.filter((r) => r.kind === 'vuln');
  const benign = rows.filter((r) => r.kind === 'benign');
  const vulnReproduced = vuln.filter((r) => r.outcome === 'reproduced').length;
  const falseRepro = benign.filter((r) => r.outcome === 'false-repro').length;
  const count = (list, outcome) => list.filter((r) => r.outcome === outcome).length;
  return {
    vuln: {
      total: vuln.length,
      reproduced: vulnReproduced,
      notReproduced: count(vuln, 'not-reproduced'),
      inconclusive: count(vuln, 'inconclusive'),
      setupError: count(vuln, 'setup-error'),
    },
    benign: {
      total: benign.length,
      reproduced: falseRepro,
      notReproduced: count(benign, 'not-reproduced'),
      notReproducedUnfair: count(benign, 'not-reproduced-unfair'),
      inconclusive: count(benign, 'inconclusive'),
      setupError: count(benign, 'setup-error'),
    },
    reproRate: rate(vulnReproduced, vuln.length),
    falseReproRate: rate(falseRepro, benign.length),
  };
}

// ---------------------------------------------------------------- corpus

export function loadCases(corpusDir, { only, kind } = {}) {
  const cases = [];
  for (const k of ['vuln', 'benign']) {
    const dir = join(corpusDir, k);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).sort()) {
      const caseDir = join(dir, name);
      const metaPath = join(caseDir, 'meta.json');
      if (!existsSync(metaPath)) continue;
      const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
      cases.push({ ...meta, kind: k, dir: caseDir, name, metaPath });
    }
  }

  let selected = cases;
  if (kind) {
    if (kind !== 'vuln' && kind !== 'benign') {
      throw new Error(`--kind must be vuln or benign, got ${kind}`);
    }
    selected = selected.filter((c) => c.kind === kind);
  }
  if (only && only.length) {
    selected = selected.filter((c) =>
      only.some((tok) => c.id === tok || c.id.includes(tok) || c.name === tok || c.name.includes(tok)),
    );
  }
  return selected;
}

function parseOnly(raw) {
  if (!raw || raw === true) return [];
  return String(raw)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// ---------------------------------------------------------------- lab child

function runLab({ findingPath, codeDir, outDir, model, configPath, timeoutS, maxTurns, sandboxTimeoutS }) {
  const labArgs = [
    LAB,
    '--finding', findingPath,
    '--code-dir', codeDir,
    '--out', outDir,
    '--model', model,
    '--config', configPath,
    '--timeout-s', String(timeoutS),
    '--max-turns', String(maxTurns),
  ];
  if (sandboxTimeoutS != null) {
    labArgs.push('--sandbox-timeout-s', String(sandboxTimeoutS));
  }

  const r = spawnSync('node', labArgs, {
    cwd: REPO,
    env: process.env,
    encoding: 'utf8',
    timeout: Math.max(400_000, (Number(timeoutS) + 60) * 1000),
    maxBuffer: 20 * 1024 * 1024,
  });

  const status = r.error
    ? 3
    : r.status === null
      ? (r.signal ? 128 : 3)
      : r.status;
  const reportPath = join(outDir, 'report.json');
  let report = null;
  if (existsSync(reportPath)) {
    try {
      report = JSON.parse(readFileSync(reportPath, 'utf8'));
    } catch {
      report = null;
    }
  }
  return {
    status,
    report,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    error: r.error?.message || null,
    signal: r.signal || null,
  };
}

function stageAfter(src, dest) {
  if (existsSync(dest)) rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  cpSync(src, dest, { recursive: true });
}

function writeSummary(runDir, summary) {
  writeFileSync(join(runDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  const v = summary.vuln;
  const b = summary.benign;
  const repro = summary.reproRate == null
    ? 'n/a (no vuln cases)'
    : `${summary.reproRate.toFixed(1)} % (${v.reproduced}/${v.total})`;
  const fp = summary.falseReproRate == null
    ? 'n/a (no benign cases)'
    : `${summary.falseReproRate.toFixed(1)} % (${b.reproduced}/${b.total})`;
  const md = [
    `# Repro eval — ${summary.timestamp}`,
    '',
    `**Model:** \`${summary.model}\``,
    `**Config:** \`${summary.config}\``,
    '',
    '| Metric | Value |',
    '|---|---|',
    `| Repro-Rate (reproduced / vuln) | ${repro} |`,
    `| **False-Repro-Rate** (reproduced / benign) | **${fp}** |`,
    `| vuln not-reproduced | ${v.notReproduced} |`,
    `| vuln inconclusive | ${v.inconclusive} |`,
    `| vuln setup-error | ${v.setupError} |`,
    `| benign not-reproduced (fair) | ${b.notReproduced} |`,
    `| benign not-reproduced-unfair | ${b.notReproducedUnfair} |`,
    `| benign inconclusive | ${b.inconclusive} |`,
    `| benign setup-error | ${b.setupError} |`,
    '',
    'inconclusive and setup-error never count as reproduced and never as clean discrimination.',
    'A benign not-reproduced without an executed sandbox fail is not-reproduced-unfair.',
    '',
    '## Cases',
    '',
    '| Case | Kind | Outcome | Lab verdict | Fair execute-fail |',
    '|---|---|---|---|---|',
    ...summary.rows.map(
      (r) =>
        `| \`${r.id}\` | ${r.kind} | ${r.outcome} | ${r.verdict} | ${r.fair ? 'yes' : 'no'} |`,
    ),
    '',
  ].join('\n');
  writeFileSync(join(runDir, 'summary.md'), md);
}

// ---------------------------------------------------------------- main

export function main(argv = process.argv.slice(2)) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    usage(err.message);
  }
  if (args.help) usage();

  const configPath = resolve(args.config || DEFAULT_CONFIG);
  if (!existsSync(configPath)) usage(`config not found: ${configPath}`);
  if (!existsSync(LAB)) {
    console.error(`lab runner not found: ${LAB}`);
    process.exit(1);
  }

  let config;
  try {
    config = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch (err) {
    console.error(`config unreadable: ${err.message}`);
    process.exit(1);
  }

  const labCfg = config.lab || {};
  const modelSpec = args.model || labCfg.model || DEFAULT_LAB_MODEL;
  const timeoutS = Math.max(1, Number(args['timeout-s'] ?? labCfg.timeoutS ?? 300));
  const maxTurns = Math.max(0, Number(args['max-turns'] ?? labCfg.maxTurns ?? 6));
  const sandboxTimeoutS = args['sandbox-timeout-s'] != null
    ? Math.max(1, Number(args['sandbox-timeout-s']))
    : null;
  const corpusDir = args.corpus ? resolve(args.corpus) : DEFAULT_CORPUS;
  const only = parseOnly(args.only);
  const kind = args.kind === true ? usage('--kind needs vuln or benign') : args.kind || null;

  let cases;
  try {
    cases = loadCases(corpusDir, { only, kind });
  } catch (err) {
    usage(err.message);
  }

  if (!cases.length) {
    console.error('No corpus cases matched.');
    process.exit(1);
  }

  if (!only.length && !kind) {
    const nV = cases.filter((c) => c.kind === 'vuln').length;
    const nB = cases.filter((c) => c.kind === 'benign').length;
    if (nV === 0 || nB === 0) {
      console.error(
        `Corpus incomplete: found ${nV} vuln case(s) and ${nB} benign case(s); need at least one of each (or pass --only / --kind).`,
      );
      process.exit(1);
    }
  }

  const stamp = `repro-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const outRoot = resolve(args.out || join(HERE, 'results'));
  const runDir = join(outRoot, stamp);
  mkdirSync(runDir, { recursive: true });

  console.error(`repro-eval: model=${modelSpec} cases=${cases.length} timeoutS=${timeoutS} maxTurns=${maxTurns}`);
  console.error(`repro-eval: out=${runDir}`);

  const rows = [];
  for (const testCase of cases) {
    const caseOut = join(runDir, testCase.id);
    mkdirSync(caseOut, { recursive: true });
    const started = Date.now();
    let finding;
    let classified;
    let labResult = { status: 3, report: null, stdout: '', stderr: '', error: null };

    try {
      finding = findingFromCase(testCase);
      const afterDir = join(testCase.dir, 'after');
      if (!existsSync(afterDir) || !statSync(afterDir).isDirectory()) {
        throw new Error(`${testCase.id}: after/ missing`);
      }
      assertFindingFile(finding, afterDir, testCase.id, { checkLine: testCase.kind === 'benign' });
      const codeDir = join(caseOut, 'code');
      stageAfter(afterDir, codeDir);
      const findingPath = join(caseOut, 'finding.json');
      writeFileSync(findingPath, JSON.stringify(finding, null, 2) + '\n');
      labResult = runLab({
        findingPath,
        codeDir,
        outDir: join(caseOut, 'lab'),
        model: modelSpec,
        configPath,
        timeoutS,
        maxTurns,
        sandboxTimeoutS,
      });
      classified = classifyCase(testCase.kind, labResult.report, labResult.status);
    } catch (err) {
      classified = { verdict: 'setup-error', outcome: 'setup-error', fair: false };
      labResult.error = err.message;
      labResult.status = 3;
    }

    writeFileSync(
      join(caseOut, 'runner.log'),
      `${labResult.stdout || ''}\n${labResult.stderr || ''}\n${labResult.error ? `error: ${labResult.error}\n` : ''}`,
    );

    const elapsed = Date.now() - started;
    const mark = {
      reproduced: 'REPRO',
      'not-reproduced': 'CLEAN',
      'false-repro': 'FALSE REPRO',
      'not-reproduced-unfair': 'UNFAIR',
      inconclusive: 'INCONCLUSIVE',
      'setup-error': 'SETUP',
    }[classified.outcome] || classified.outcome;

    console.error(
      `${classified.outcome.padEnd(24)} ${mark.padEnd(14)} ${testCase.id}` +
        (labResult.error && classified.outcome === 'setup-error' ? `  (${labResult.error})` : ''),
    );

    rows.push({
      id: testCase.id,
      kind: testCase.kind,
      outcome: classified.outcome,
      verdict: classified.verdict,
      fair: classified.fair,
      labStatus: labResult.status,
      finding: finding
        ? { title: finding.title, file: finding.file, line: finding.line }
        : null,
      ms: elapsed,
      error: labResult.error || null,
    });
  }

  const agg = aggregateRows(rows);
  const summary = {
    timestamp: stamp,
    model: modelSpec,
    config: configPath,
    flags: {
      only: only.length ? only : null,
      kind,
      timeoutS,
      maxTurns,
      sandboxTimeoutS,
    },
    cases: rows.length,
    ...agg,
    rows,
  };
  writeSummary(runDir, summary);

  const v = agg.vuln;
  const b = agg.benign;
  const reproLabel = agg.reproRate == null ? 'n/a' : `${agg.reproRate.toFixed(1)} % (${v.reproduced}/${v.total})`;
  const fpLabel = agg.falseReproRate == null ? 'n/a' : `${agg.falseReproRate.toFixed(1)} % (${b.reproduced}/${b.total})`;
  console.error(
    `\nRepro-Rate ${reproLabel} · False-Repro ${fpLabel}` +
      ` · unfair ${b.notReproducedUnfair} · inconclusive vuln ${v.inconclusive} benign ${b.inconclusive}` +
      ` · setup-error vuln ${v.setupError} benign ${b.setupError}`,
  );
  console.error(`Model: ${modelSpec}`);
  console.error(`Results: ${runDir}`);
  return summary;
}

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return resolve(entry) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main();
}
