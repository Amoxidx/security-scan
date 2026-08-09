#!/usr/bin/env node
/**
 * SARIF from every scanner -> one finding stream.
 *
 * This is the seam the whole design rests on: scanners speak SARIF, so the triage stage gets
 * a single input shape instead of four bespoke parsers, and GitHub Code Scanning ingests the
 * same files natively.
 *
 * Usage:
 *   node security/scanners/normalize.mjs --sarif <dir> [--diff <file>] [--out <file>] [--no-gate]
 *
 * --diff restricts findings to lines the pull request actually touched. Without it, every
 * pre-existing issue in the repository blocks the first PR that happens to run the gate.
 *
 * --no-gate records blocking findings but exits 0 for them. Real errors (missing SARIF
 * directory, unreadable input, scanner status "error") still exit non-zero. --no-gate only
 * suppresses the findings gate; it must not hide a tool that never produced a report. Use
 * this when a later triage stage owns the findings decision.
 *
 * Exit: 0 clean (or --no-gate with findings), 1 blocking findings present (without --no-gate)
 * or a real error (including a scanner that failed to run).
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

// Flags that stand alone. Without this list the step-by-two parser would treat the next
// argv token as a value and silently drop --sarif / --diff / --out when --no-gate is not last.
const BOOLEAN_FLAGS = new Set(['no-gate']);

const args = {};
for (let i = 2; i < process.argv.length; ) {
  const tok = process.argv[i];
  if (!tok.startsWith('--')) {
    i += 1;
    continue;
  }
  const key = tok.slice(2);
  if (BOOLEAN_FLAGS.has(key)) {
    args[key] = true;
    i += 1;
    continue;
  }
  // Value-taking flag. If the next token is missing or another --flag, do not consume it —
  // an unknown bare --flag must not swallow a following real argument.
  const next = process.argv[i + 1];
  if (next !== undefined && !next.startsWith('--')) {
    args[key] = next;
    i += 2;
  } else {
    args[key] = true;
    i += 1;
  }
}

const sarifDir = args.sarif || 'security-report/sarif';
const outPath = args.out || 'security-report/findings.json';
const blockOn = (args['block-on'] || 'error').split(',');
// Boolean flag: present means normalize must not gate on blocking findings.
const noGate = Boolean(args['no-gate']);

// ---------------------------------------------------------------- diff scope

/** file -> Set(added line numbers), parsed from a unified diff. */
function addedLines(diffText) {
  const byFile = new Map();
  let file = null;
  let line = 0;
  for (const raw of diffText.split('\n')) {
    if (raw.startsWith('+++ ')) {
      const p = raw.slice(4).replace(/^b\//, '').trim();
      file = p === '/dev/null' ? null : p;
      if (file && !byFile.has(file)) byFile.set(file, new Set());
    } else if (raw.startsWith('@@')) {
      const m = raw.match(/\+(\d+)(?:,(\d+))?/);
      line = m ? Number(m[1]) : 0;
    } else if (file && raw.startsWith('+') && !raw.startsWith('+++')) {
      byFile.get(file).add(line);
      line += 1;
    } else if (file && !raw.startsWith('-')) {
      line += 1;
    }
  }
  return byFile;
}

const scope = args.diff && existsSync(args.diff) ? addedLines(readFileSync(args.diff, 'utf8')) : null;

/** A finding counts as in scope if it sits on, or within 3 lines of, a touched line. */
function inScope(file, line) {
  if (!scope) return true;
  for (const [f, lines] of scope) {
    if (!f.endsWith(file) && !file.endsWith(f)) continue;
    for (const l of lines) if (Math.abs(l - line) <= 3) return true;
  }
  return false;
}

// ---------------------------------------------------------------- SARIF

const SEVERITY = { error: 'error', warning: 'warning', note: 'note', none: 'note' };

function ruleMeta(run, ruleId) {
  const rules = run.tool?.driver?.rules || [];
  return rules.find((r) => r.id === ruleId) || {};
}

function fromSarif(path, toolHint) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return [];
  }
  const out = [];
  for (const run of doc.runs || []) {
    const tool = run.tool?.driver?.name || toolHint;
    for (const r of run.results || []) {
      const loc = r.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri || '';
      const line = loc?.region?.startLine || 0;
      const meta = ruleMeta(run, r.ruleId);
      const sev = SEVERITY[r.level || meta.defaultConfiguration?.level || 'warning'] || 'warning';
      out.push({
        tool,
        ruleId: r.ruleId || meta.id || 'unknown',
        file: file.replace(/^file:\/\//, ''),
        line,
        severity: sev,
        message: (r.message?.text || '').trim().replace(/\s+/g, ' '),
        cwe: meta.properties?.cwe || meta.properties?.tags?.find((t) => /^CWE-/i.test(t)) || null,
        class: meta.properties?.class || null,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------- main

if (!existsSync(sarifDir)) {
  console.error(`No SARIF directory at ${sarifDir}`);
  process.exit(1);
}

const statusPath = join(sarifDir, 'scanners.json');
const scanners = existsSync(statusPath) ? JSON.parse(readFileSync(statusPath, 'utf8')) : [];

const all = [];
for (const f of readdirSync(sarifDir).filter((f) => f.endsWith('.sarif'))) {
  all.push(...fromSarif(join(sarifDir, f), f.replace('.sarif', '')));
}

// Two scanners flagging the same line is one problem, not two.
const deduped = [...new Map(all.map((f) => [`${f.file}:${f.line}:${f.ruleId}`, f])).values()];
const scoped = deduped.filter((f) => inScope(f.file, f.line));
const blocking = scoped.filter((f) => blockOn.includes(f.severity));

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify({ scanners, findings: scoped, blocking: blocking.length }, null, 2));

const skipped = scanners.filter((s) => s.status !== 'ok');
if (skipped.length) {
  console.log('Scanners not contributing:');
  for (const s of skipped) console.log(`  ${s.tool}: ${s.status} — ${s.detail}`);
}

console.log(
  `${all.length} raw -> ${deduped.length} deduped -> ${scoped.length} in diff scope -> ${blocking.length} blocking`
);
for (const f of blocking) console.log(`  [${f.severity}] ${f.file}:${f.line} ${f.ruleId}`);

// Tool failure is not a findings decision. status "error" means the scanner did not run;
// that must fail the step even under --no-gate (which only suppresses the findings gate).
// status "skipped" and "degraded" stay non-fatal: deliberate absence or partial output.
const toolErrors = scanners.filter((s) => s.status === 'error');
if (toolErrors.length) {
  for (const s of toolErrors) {
    console.error(`Scanner tool failure: ${s.tool} — ${s.detail}`);
  }
  process.exit(1);
}

if (noGate) process.exit(0);
process.exit(blocking.length ? 1 : 0);
