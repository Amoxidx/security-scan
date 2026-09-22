#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const NODE = process.execPath;
const ROOT = new URL('../..', import.meta.url).pathname;
const TRIAGE = join(ROOT, 'security/redteam/triage.mjs');
const WORK = mkdtempSync(join(tmpdir(), 'triage-input-contract-'));
const CONFIG = join(WORK, 'unavailable.json');
writeFileSync(CONFIG, JSON.stringify({
  defaultProvider: 'missing',
  providers: {},
  triage: { model: 'missing:triage' },
  report: { model: 'missing:report' },
  gate: { blockOn: ['critical', 'high', 'error'] },
}));

function run(value, name) {
  const findings = join(WORK, name + '.json');
  const out = join(WORK, name, 'triaged.json');
  writeFileSync(findings, JSON.stringify(value));
  try {
    execFileSync(NODE, [
      TRIAGE, '--findings', findings, '--repo', ROOT, '--config', CONFIG, '--out', out,
    ], { cwd: ROOT, encoding: 'utf8' });
    return { status: 0, artifact: JSON.parse(readFileSync(out, 'utf8')) };
  } catch (error) {
    return {
      status: error.status,
      artifact: JSON.parse(readFileSync(out, 'utf8')),
      output: (error.stdout || '') + (error.stderr || ''),
    };
  }
}

test('literal empty array remains a complete clean result without a provider', () => {
  const result = run([], 'empty-array');
  assert.equal(result.status, 0);
  assert.equal(result.artifact.status, 'complete');
  assert.equal(result.artifact.outcome, 'pass');
  assert.equal(result.artifact.exit, 0);
});

test('object without findings array is incomplete before provider resolution', () => {
  const result = run({}, 'empty-object');
  assert.equal(result.status, 3);
  assert.equal(result.artifact.status, 'incomplete');
  assert.equal(result.artifact.outcome, 'inconclusive');
  assert.equal(result.artifact.exit, 3);
  assert.deepEqual(result.artifact.reasonCodes, ['invalid_input']);
});

test('malformed source row is incomplete before provider resolution', () => {
  const result = run([{}], 'malformed-row');
  assert.equal(result.status, 3);
  assert.equal(result.artifact.status, 'incomplete');
  assert.equal(result.artifact.outcome, 'inconclusive');
  assert.equal(result.artifact.exit, 3);
  assert.deepEqual(result.artifact.reasonCodes, ['invalid_input']);
});
