#!/usr/bin/env node
/**
 * Stage 4 — proof.
 *
 * A probe is an executable claim: it runs the code and reports whether the defect is
 * actually present. Static analysis says "this pattern is dangerous"; a probe says "I ran it
 * and here is what happened".
 *
 * Two uses, and they must not be confused:
 *
 *   corpus mode (this runner)  Probes shipped alongside corpus cases independently confirm
 *                              that each ground truth describes a real defect. This validates
 *                              the CORPUS, not the gate. A probe written next to the answer
 *                              key proves nothing about what the gate can find on its own, so
 *                              probe results never enter the detection rate.
 *
 *   production                 The model writes a probe for a finding (prompts/04-repro.md)
 *                              and it runs in a sandbox — a CI job with no repository token
 *                              and no network. Model-generated code never runs in the job
 *                              that holds the checkout and the token.
 *
 * Usage:
 *   node security/prove/run-probes.mjs [--only <substring>] [--timeout <ms>]
 *
 * Exit: 0 when every probe confirms its case, 1 when one does not.
 */

import { readFileSync, readdirSync, existsSync, mkdtempSync, cpSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../..');
const CORPUS = join(REPO, 'security/eval/corpus');
const REDTEAM_CONFIG = JSON.parse(readFileSync(join(REPO, 'security/redteam/config.json'), 'utf8'));

/**
 * Minimal environment for probes — allowlist, not denylist.
 * Spreading process.env would hand the probe every secret the runner holds; clearing a few
 * known names is not enough when CI injects arbitrary SECRET_* variables.
 */
function probeEnv() {
  const keep = [
    'PATH',
    'HOME',
    'TMPDIR',
    'TEMP',
    'TMP',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'TERM',
    'USER',
    'LOGNAME',
    'NODE_OPTIONS',
    'npm_config_cache',
  ];
  const env = {};
  for (const k of keep) {
    if (process.env[k] !== undefined) env[k] = process.env[k];
  }
  // Never pass CI or model credentials, even if they appear in keep by misconfiguration.
  env.GITHUB_TOKEN = '';
  env.GH_TOKEN = '';
  env.NODE_OPTIONS = '';
  for (const p of Object.values(REDTEAM_CONFIG.providers || {})) {
    if (p.apiKeyEnv) env[p.apiKeyEnv] = '';
  }
  return env;
}

const args = {};
for (let i = 2; i < process.argv.length; i += 1) {
  const a = process.argv[i];
  if (a.startsWith('--')) { args[a.slice(2)] = process.argv[i + 1]; i += 1; }
}
const timeout = Number(args.timeout || 30000);

const cases = [];
for (const kind of ['vuln', 'benign']) {
  const dir = join(CORPUS, kind);
  if (!existsSync(dir)) continue;
  for (const name of readdirSync(dir).sort()) {
    const caseDir = join(dir, name);
    if (!existsSync(join(caseDir, 'probe.mjs'))) continue;
    const meta = JSON.parse(readFileSync(join(caseDir, 'meta.json'), 'utf8'));
    if (args.only && !meta.id.includes(args.only)) continue;
    cases.push({ ...meta, kind, dir: caseDir });
  }
}

if (!cases.length) {
  console.log('No probes found.');
  process.exit(0);
}

console.log(`Running ${cases.length} probe(s)\n`);
let failed = 0;

for (const c of cases) {
  // Probe against a copy, never the checked-in tree: a probe that mutates state must not
  // leave the corpus altered for the next run.
  const work = mkdtempSync(join(tmpdir(), 'probe-'));
  cpSync(join(c.dir, 'after'), work, { recursive: true });

  const res = spawnSync('node', [join(HERE, 'exec-probe.mjs'), join(c.dir, 'probe.mjs'), work], {
    encoding: 'utf8',
    timeout,
    // No repository token or model credentials reach the probe.
    env: probeEnv(),
  });
  rmSync(work, { recursive: true, force: true });

  const marker = (res.stdout || '').split('__PROBE__')[1];
  let verdict;
  try {
    verdict = JSON.parse((marker || '').split('\n')[0]);
  } catch {
    verdict = { error: res.error ? String(res.error.message) : `no verdict (exit ${res.status})` };
  }

  // A vuln case is confirmed when the probe finds the defect present; a benign case when it
  // does not.
  const want = c.kind === 'vuln';
  const ok = !verdict.error && verdict.present === want;
  if (!ok) failed += 1;

  const label = verdict.error ? 'ERROR' : ok ? 'CONFIRMED' : 'NOT CONFIRMED';
  console.log(`${label.padEnd(15)} ${c.id}`);
  if (verdict.describes) console.log(`                ${verdict.describes}`);
  if (verdict.evidence) console.log(`                ${verdict.evidence.replace(/\n/g, '\n                ')}`);
  if (verdict.error) console.log(`                ${verdict.error}`);
  console.log();
}

console.log(`${cases.length - failed}/${cases.length} probes confirmed their case.`);
console.log('Probe results validate the corpus. They are NOT part of the detection rate.');
process.exit(failed ? 1 : 0);
