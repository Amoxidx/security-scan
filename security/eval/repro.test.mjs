#!/usr/bin/env node
/**
 * Finding construction + fairness/aggregation math for security/eval/repro.mjs.
 * Mocked lab report.json objects only — no Docker, no model, no sandbox.
 *
 * Exit: 0 all passed, 1 one or more failed.
 */

import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findingFromCase,
  hasFairSandboxFail,
  classifyCase,
  aggregateRows,
  labVerdict,
  loadCases,
} from './repro.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, 'corpus');

let pass = 0;
let fail = 0;

function check(name, ok, detail = '') {
  if (ok) {
    pass += 1;
    console.log(`  PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function loadMeta(kind, name) {
  const dir = join(CORPUS, kind, name);
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  return { ...meta, kind, dir, name };
}

const executeFail = (exitCode = 1, timedOut = false) => ({
  turn: 1,
  action: 'execute',
  sandbox: { exitCode, timedOut, stdout: 'nope', stderr: 'guard' },
});

const conclude = (verdict) => ({
  turn: 2,
  action: 'conclude',
  verdict,
});

// ---------------------------------------------------------------- finding construction

{
  const vuln = loadMeta('vuln', '016-negative-amount');
  const f = findingFromCase(vuln);
  check(
    'vuln finding: summary → title+summary',
    f.title === vuln.summary && f.summary === vuln.summary,
    `title=${JSON.stringify(f.title)}`,
  );
  check(
    'vuln finding: ground_truth.file / lines[0]',
    f.file === vuln.ground_truth.file && f.line === vuln.ground_truth.lines[0],
    `file=${f.file} line=${f.line}`,
  );
  check(
    'vuln finding: severity/class/cwe',
    f.severity === vuln.severity && f.class === vuln.class && f.cwe === vuln.cwe,
    JSON.stringify({ severity: f.severity, class: f.class, cwe: f.cwe }),
  );
}

{
  const benign = loadMeta('benign', '011-amount-validated');
  const f = findingFromCase(benign);
  const af = benign.adversarial_finding;
  check(
    'benign finding: built from adversarial_finding',
    f.title === af.title
      && f.summary === af.summary
      && f.file === af.file
      && f.line === af.line
      && f.severity === af.severity
      && f.class === af.class
      && f.cwe === af.cwe,
    JSON.stringify(f),
  );
}

{
  let threw = false;
  try {
    findingFromCase({ id: 'benign-x', kind: 'benign' });
  } catch {
    threw = true;
  }
  check('benign without adversarial_finding throws', threw);
}

{
  const vuln = loadMeta('vuln', '011-idor-owner-check-removed');
  const f = findingFromCase(vuln);
  check(
    'vuln-011 finding line is ground_truth.lines[0]',
    f.line === 2 && f.file === 'src/docs.ts',
    `file=${f.file} line=${f.line}`,
  );
}

{
  const cases = loadCases(CORPUS);
  const vulnN = cases.filter((c) => c.kind === 'vuln').length;
  const benignN = cases.filter((c) => c.kind === 'benign').length;
  check(`corpus load: 20 vuln + 13 benign (got ${vulnN}+${benignN})`, vulnN === 20 && benignN === 13);
  let findingOk = true;
  let findingDetail = '';
  for (const c of cases) {
    try {
      const f = findingFromCase(c);
      const target = join(c.dir, 'after', f.file);
      if (!existsSync(target)) {
        findingOk = false;
        findingDetail = `${c.id}: ${f.file} missing under after/`;
        break;
      }
      if (c.kind === 'benign') {
        const n = readFileSync(target, 'utf8').split('\n').length;
        if (f.line < 1 || f.line > n) {
          findingOk = false;
          findingDetail = `${c.id}: line ${f.line} out of range (${n})`;
          break;
        }
      }
    } catch (err) {
      findingOk = false;
      findingDetail = err.message;
      break;
    }
  }
  check('every corpus case builds a finding that points at after/', findingOk, findingDetail);
}

// ---------------------------------------------------------------- fairness gate

{
  const fair = {
    verdict: 'not-reproduced',
    turns: [executeFail(1, false), conclude('not-reproduced')],
  };
  check(
    'fair: execute with exitCode !== 0, not timedOut',
    hasFairSandboxFail(fair) === true,
  );

  const concludeOnly = {
    verdict: 'not-reproduced',
    turns: [{ turn: 1, action: 'conclude', verdict: 'not-reproduced' }],
  };
  check(
    'unfair: conclude without execute is not a fair sandbox fail',
    hasFairSandboxFail(concludeOnly) === false,
  );

  const timedOut = {
    verdict: 'not-reproduced',
    turns: [executeFail(1, true), conclude('not-reproduced')],
  };
  check(
    'unfair: timedOut execute is not a fair sandbox fail',
    hasFairSandboxFail(timedOut) === false,
  );

  const exitZero = {
    verdict: 'not-reproduced',
    turns: [executeFail(0, false), conclude('not-reproduced')],
  };
  check(
    'unfair: exitCode 0 is not a failed exploit run',
    hasFairSandboxFail(exitZero) === false,
  );

  const missingCode = {
    verdict: 'not-reproduced',
    turns: [{ turn: 1, action: 'execute', sandbox: { timedOut: false } }],
  };
  check(
    'unfair: sandbox without exitCode',
    hasFairSandboxFail(missingCode) === false,
  );

  const exit127 = {
    verdict: 'not-reproduced',
    turns: [executeFail(127, false)],
  };
  check(
    'unfair: exit 127 (ENOENT / binary not found) is not a fair sandbox fail',
    hasFairSandboxFail(exit127) === false,
  );

  const exit137 = {
    verdict: 'not-reproduced',
    turns: [executeFail(137, false)],
  };
  check(
    'unfair: exit 137 (SIGKILL / memory cap) is not a fair sandbox fail',
    hasFairSandboxFail(exit137) === false,
  );
}

{
  const concludeOnly = {
    verdict: 'not-reproduced',
    turns: [{ turn: 1, action: 'conclude', verdict: 'not-reproduced' }],
  };
  const c = classifyCase('benign', concludeOnly, 0);
  check(
    'benign conclude-only → not-reproduced-unfair, not clean',
    c.outcome === 'not-reproduced-unfair' && c.verdict === 'not-reproduced' && c.fair === false,
    JSON.stringify(c),
  );
}

{
  const fair = {
    verdict: 'not-reproduced',
    turns: [executeFail(1, false), conclude('not-reproduced')],
  };
  const c = classifyCase('benign', fair, 0);
  check(
    'benign execute-fail → not-reproduced (fair)',
    c.outcome === 'not-reproduced' && c.fair === true,
    JSON.stringify(c),
  );
}

{
  const crashed = {
    verdict: 'not-reproduced',
    turns: [executeFail(127, false)],
  };
  const c = classifyCase('benign', crashed, 0);
  check(
    'benign exit-127-only → not-reproduced-unfair, not clean',
    c.outcome === 'not-reproduced-unfair' && c.verdict === 'not-reproduced' && c.fair === false,
    JSON.stringify(c),
  );
}

{
  const c = classifyCase('benign', { verdict: 'reproduced', turns: [executeFail(0, false)] }, 0);
  check(
    'benign reproduced → false-repro',
    c.outcome === 'false-repro' && c.verdict === 'reproduced',
    JSON.stringify(c),
  );
}

{
  const c = classifyCase('vuln', { verdict: 'reproduced', turns: [executeFail(0, false)] }, 0);
  check('vuln reproduced → reproduced', c.outcome === 'reproduced', JSON.stringify(c));
}

{
  const c = classifyCase('vuln', { verdict: 'inconclusive', turns: [] }, 2);
  check(
    'vuln inconclusive never counts as reproduced',
    c.outcome === 'inconclusive' && c.verdict === 'inconclusive',
    JSON.stringify(c),
  );
}

{
  check('missing report + exit 3 → setup-error', labVerdict(null, 3) === 'setup-error');
  const c = classifyCase('benign', null, 3);
  check(
    'benign setup-error is not clean discrimination',
    c.outcome === 'setup-error' && c.fair === false,
    JSON.stringify(c),
  );
  const v = classifyCase('vuln', null, 3);
  check(
    'vuln setup-error is not reproduced',
    v.outcome === 'setup-error',
    JSON.stringify(v),
  );
}

{
  const c = classifyCase('benign', null, 2);
  check(
    'missing report + non-3 exit → inconclusive (not a crash path)',
    c.outcome === 'inconclusive',
    JSON.stringify(c),
  );
}

// ---------------------------------------------------------------- aggregation

{
  const rows = [
    { kind: 'vuln', outcome: 'reproduced' },
    { kind: 'vuln', outcome: 'not-reproduced' },
    { kind: 'vuln', outcome: 'inconclusive' },
    { kind: 'vuln', outcome: 'setup-error' },
    { kind: 'benign', outcome: 'false-repro' },
    { kind: 'benign', outcome: 'not-reproduced' },
    { kind: 'benign', outcome: 'not-reproduced-unfair' },
    { kind: 'benign', outcome: 'inconclusive' },
    { kind: 'benign', outcome: 'setup-error' },
  ];
  const agg = aggregateRows(rows);
  check(
    'repro-rate = reproduced/vuln = 1/4',
    agg.vuln.total === 4
      && agg.vuln.reproduced === 1
      && agg.vuln.notReproduced === 1
      && agg.vuln.inconclusive === 1
      && agg.vuln.setupError === 1
      && agg.reproRate === 25,
    JSON.stringify(agg.vuln) + ` rate=${agg.reproRate}`,
  );
  check(
    'false-repro-rate = reproduced/benign = 1/5; unfair counted separately',
    agg.benign.total === 5
      && agg.benign.reproduced === 1
      && agg.benign.notReproduced === 1
      && agg.benign.notReproducedUnfair === 1
      && agg.benign.inconclusive === 1
      && agg.benign.setupError === 1
      && agg.falseReproRate === 20,
    JSON.stringify(agg.benign) + ` rate=${agg.falseReproRate}`,
  );
  check(
    'inconclusive/setup-error are not in reproduced numerators',
    agg.vuln.reproduced === 1 && agg.benign.reproduced === 1,
  );
}

{
  const agg = aggregateRows([{ kind: 'vuln', outcome: 'reproduced' }]);
  check(
    'benign denom 0 → falseReproRate null (not a vacuous 0%)',
    agg.falseReproRate === null && agg.reproRate === 100,
    JSON.stringify(agg),
  );
}

console.log(`${pass}/${pass + fail} repro-eval cases`);
process.exit(fail === 0 ? 0 : 1);
