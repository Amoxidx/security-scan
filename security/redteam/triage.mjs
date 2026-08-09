#!/usr/bin/env node
/**
 * Stage 2 — LLM triage over normalized scanner findings.
 *
 * This is the evidence-backed use of a model in this pipeline. As a *finder*, models score
 * 18-34% on the public benchmarks. As a *filter* on static analysis output they identify up
 * to 93% of false positives, and take the OWASP benchmark from over 92% FP down to 6%.
 *
 * Every dropped finding is written to the output with its reason. A filter whose decisions
 * nobody can read is not auditable, and an unauditable filter is a place for a real bug to
 * disappear quietly.
 *
 * Usage:
 *   node security/redteam/triage.mjs --findings <file> [--repo <dir>] [--out <file>]
 *
 * Exit: 0 when nothing blocking survives, 1 when something does, 3 on configuration error.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { complete, resolveModel, listUnavailable } from './providers.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].slice(2)] = process.argv[i + 1];

if (!args.findings) {
  console.error('--findings <file> is required');
  process.exit(3);
}

const config = JSON.parse(readFileSync(args.config || join(HERE, 'config.json'), 'utf8'));
const repoRoot = resolve(args.repo || '.');
const outPath = args.out || 'security-report/triaged.json';

const systemPrompt = readFileSync(join(HERE, 'prompts/00-system.md'), 'utf8');
const triagePrompt = readFileSync(join(HERE, 'prompts/06-triage.md'), 'utf8');

const input = JSON.parse(readFileSync(args.findings, 'utf8'));
const findings = input.findings || input;

if (!findings.length) {
  console.log('No scanner findings to triage.');
  writeFileSync(outPath, JSON.stringify({ triaged: [], blocking: 0 }, null, 2));
  process.exit(0);
}

const target = resolveModel(config, config.triage?.model || config.report.model);
if (!target) {
  // Untriaged findings are not dismissed. They pass through as needs_human so the scanner
  // stage's own blocking decision still stands.
  console.log('No model provider reachable — findings pass through untriaged.');
  for (const line of listUnavailable(config, [config.triage?.model || config.report.model])) {
    console.log(`  ${line}`);
  }
  // Passing through must preserve the scanner stage's decision, not escalate it. Without a
  // triage model the gate is exactly as strict as it was before this stage existed.
  const passthrough = findings.map((f) => ({ ...f, verdict: 'needs_human', reason: 'not triaged' }));
  const blockOn = config.gate.blockOn || ['critical', 'high', 'error'];
  const stillBlocking = passthrough.filter((f) => blockOn.includes(f.severity));
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify({ triaged: passthrough, blocking: stillBlocking.length }, null, 2));
  console.log(`${findings.length} findings pass through -> ${stillBlocking.length} blocking (unchanged)`);
  process.exit(stillBlocking.length ? 1 : 0);
}

/** The flagged line plus enough around it to judge reachability. */
function codeContext(file, line, radius = 25) {
  const path = join(repoRoot, file);
  if (!existsSync(path)) return '(file not found)';
  const lines = readFileSync(path, 'utf8').split('\n');
  const from = Math.max(0, line - radius);
  const to = Math.min(lines.length, line + radius);
  return lines
    .slice(from, to)
    .map((l, i) => `${String(from + i + 1).padStart(4)}${from + i + 1 === line ? ' >' : '  '} ${l}`)
    .join('\n');
}

const BLOCKING_VERDICTS = new Set(['true_positive', 'needs_human']);

const UNTRUSTED_BEGIN = '<<<UNTRUSTED_INPUT_BEGIN>>>';
const UNTRUSTED_END = '<<<UNTRUSTED_INPUT_END>>>';

/** Strip sentinel markers from untrusted content so an attacker cannot close the envelope. */
function wrapUntrusted(text) {
  const cleaned = String(text)
    .split(UNTRUSTED_BEGIN).join('')
    .split(UNTRUSTED_END).join('');
  return `${UNTRUSTED_BEGIN}\n${cleaned}\n${UNTRUSTED_END}`;
}

async function triage(finding) {
  const user = triagePrompt
    .replace('{{FINDING}}', wrapUntrusted(JSON.stringify(finding, null, 2)))
    .replace('{{CODE}}', wrapUntrusted(codeContext(finding.file, finding.line)))
    .replace('{{CONTEXT}}', wrapUntrusted(`Rule: ${finding.ruleId}\nCWE: ${finding.cwe || 'n/a'}\nScanner: ${finding.tool}`));

  try {
    const out = await complete(config, target, systemPrompt, user);
    const parsed = parseJson(out);
    if (!parsed || !parsed.verdict) {
      return {
        ...finding,
        verdict: 'needs_human',
        reason: 'unparseable triage response',
        scannerSeverity: finding.severity,
      };
    }
    // Model severity is a priority hint; the gate must never be weaker than the scanner.
    return {
      ...finding,
      ...parsed,
      scannerSeverity: finding.severity,
      severity: parsed.severity || finding.severity,
    };
  } catch (err) {
    // An error must never look like a dismissal.
    return {
      ...finding,
      verdict: 'needs_human',
      reason: `triage error: ${err.message}`,
      scannerSeverity: finding.severity,
    };
  }
}

function parseJson(text) {
  const cleaned = String(text).trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = cleaned.search(/[{[]/);
  if (start === -1) return null;
  try {
    return JSON.parse(cleaned.slice(start));
  } catch {
    return null;
  }
}

const triaged = await Promise.all(findings.map(triage));

const blockOn = config.gate.blockOn || ['critical', 'high', 'error'];
const dropped = triaged.filter((f) => f.verdict === 'false_positive');
const kept = triaged.filter((f) => BLOCKING_VERDICTS.has(f.verdict));
// Block if model severity OR original scanner severity is in blockOn — never weaker than
// the passthrough path that runs when no triage model is available.
const blocking = kept.filter(
  (f) => blockOn.includes(f.severity) || blockOn.includes(f.scannerSeverity || f.severity)
);

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify({ triaged, dropped: dropped.length, blocking: blocking.length }, null, 2));

console.log(`${findings.length} findings -> ${dropped.length} dismissed -> ${kept.length} kept -> ${blocking.length} blocking`);
if (dropped.length) {
  console.log('\nDismissed (recorded in the artifact, not discarded):');
  for (const f of dropped) console.log(`  ${f.file}:${f.line} ${f.ruleId}\n    ${f.reason}`);
}
if (blocking.length) {
  console.log('\nBLOCKING:');
  for (const f of blocking) console.log(`  [${f.severity}] ${f.file}:${f.line} ${f.ruleId} (${f.verdict})`);
}

process.exit(blocking.length ? 1 : 0);
