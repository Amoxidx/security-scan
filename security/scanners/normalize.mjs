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
  if (!scope || !file) return true;
  for (const [f, lines] of scope) {
    if (!f.endsWith(file) && !file.endsWith(f)) continue;
    for (const l of lines) if (Math.abs(l - line) <= 3) return true;
  }
  return false;
}

// ---------------------------------------------------------------- scanner metadata

const SCANNER_STATUSES = new Set(['ok', 'skipped', 'degraded', 'error']);
const SKIPPED_NEUTRAL_REASON = 'not_applicable_no_lockfile';
const REASON_CODES = {
  ok: new Set(['completed']),
  skipped: new Set([SKIPPED_NEUTRAL_REASON]),
  degraded: new Set(['semgrep_rule_parse_error']),
  error: new Set([
    'executable_missing',
    'osv_backend_unreachable',
    'report_missing',
    'scanner_exit_failure',
    'report_malformed',
    'report_invalid_shape',
  ]),
};

function readScannerMetadata(path, dir) {
  if (!existsSync(path)) throw new Error('malformed scanner metadata: missing scanners.json');
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error('malformed scanner metadata: ' + err.message);
  }
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('malformed scanner metadata: expected a non-empty scanner status array');
  }
  const seen = new Set();
  const sarifFiles = new Set(readdirSync(dir).filter((f) => f.endsWith('.sarif')));
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        typeof entry.tool !== 'string' || !entry.tool.trim() ||
        !SCANNER_STATUSES.has(entry.status) || seen.has(entry.tool)) {
      throw new Error('malformed scanner metadata: invalid or duplicate tool status');
    }
    seen.add(entry.tool);
    if (entry.reasonCode !== undefined &&
        (typeof entry.reasonCode !== 'string' || !entry.reasonCode.trim())) {
      throw new Error('malformed scanner metadata: ' + entry.tool + ' has an invalid reasonCode');
    }
    if ((entry.status !== 'ok' && !REASON_CODES[entry.status]?.has(entry.reasonCode)) ||
        (entry.status === 'ok' && entry.reasonCode !== undefined &&
          !REASON_CODES.ok.has(entry.reasonCode))) {
      throw new Error('malformed scanner metadata: ' + entry.tool + ' has an unknown or missing reasonCode');
    }
    if (entry.status === 'ok' && !sarifFiles.has(entry.tool + '.sarif')) {
      throw new Error('malformed scanner metadata: ' + entry.tool + ' is ok without ' + entry.tool + '.sarif');
    }
  }
  return value;
}

// ---------------------------------------------------------------- SARIF

const SEVERITY = { error: 'error', warning: 'warning', note: 'note', none: 'note' };

const SECURITY_SEVERITY_PROPERTY = 'security-severity';
function validRuleLevel(level) {
  return level === undefined || Object.hasOwn(SEVERITY, level);
}

function rulesFor(run, path) {
  const extensions = run.tool?.extensions;
  if (extensions !== undefined &&
      (!Array.isArray(extensions) || extensions.some((extension) => extension?.rules !== undefined))) {
    throw new Error(`malformed SARIF ${path}: extension rule components are unsupported for rule resolution`);
  }
  const rules = run.tool?.driver?.rules;
  if (rules !== undefined && !Array.isArray(rules)) {
    throw new Error(`malformed SARIF ${path}: tool driver rules must be an array`);
  }
  const list = Array.isArray(rules) ? rules : [];
  const seen = new Set();
  for (const rule of list) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule) ||
        typeof rule.id !== 'string' || !rule.id.trim() || seen.has(rule.id)) {
      throw new Error(`malformed SARIF ${path}: rules must have unique non-empty IDs`);
    }
    seen.add(rule.id);
    if (rule.properties !== undefined &&
        (!rule.properties || typeof rule.properties !== 'object' || Array.isArray(rule.properties))) {
      throw new Error(`malformed SARIF ${path}: rule ${rule.id} properties are not an object`);
    }
    if (rule.defaultConfiguration !== undefined &&
        (!rule.defaultConfiguration || typeof rule.defaultConfiguration !== 'object' ||
         Array.isArray(rule.defaultConfiguration) ||
         !validRuleLevel(rule.defaultConfiguration.level))) {
      throw new Error(`malformed SARIF ${path}: rule ${rule.id} default level is invalid`);
    }
  }
  return list;
}

function resultRuleReference(result, path) {
  if (!Object.hasOwn(result, 'rule')) return {};
  const reference = result.rule;
  if (!reference || typeof reference !== 'object' || Array.isArray(reference)) {
    throw new Error(`malformed SARIF ${path}: result.rule must be an object`);
  }
  for (const key of Object.keys(reference)) {
    if (key !== 'id' && key !== 'index') {
      throw new Error(`unsupported SARIF ${path}: result.rule.${key} is not supported`);
    }
  }
  if (reference.id !== undefined &&
      (typeof reference.id !== 'string' || !reference.id.trim())) {
    throw new Error(`malformed SARIF ${path}: result.rule.id is invalid`);
  }
  if (reference.index !== undefined &&
      (!Number.isInteger(reference.index) || reference.index < 0)) {
    throw new Error(`malformed SARIF ${path}: result.rule.index is invalid`);
  }
  if (reference.id === undefined && reference.index === undefined) {
    throw new Error(`malformed SARIF ${path}: result.rule has no id or index`);
  }
  return reference;
}

function ruleMeta(run, result, path) {
  const list = rulesFor(run, path);
  const reference = resultRuleReference(result, path);
  if (result.ruleId !== undefined && reference.id !== undefined &&
      result.ruleId !== reference.id) {
    throw new Error(`malformed SARIF ${path}: ruleId/rule.id reference different rules`);
  }
  if (result.ruleIndex !== undefined && reference.index !== undefined &&
      result.ruleIndex !== reference.index) {
    throw new Error(`malformed SARIF ${path}: ruleIndex/rule.index reference different rules`);
  }
  const ruleId = result.ruleId ?? reference.id;
  const ruleIndex = result.ruleIndex ?? reference.index;
  const byIndex = ruleIndex === undefined ? null : list[ruleIndex];
  const byId = ruleId === undefined ? null : list.find((rule) => rule && rule.id === ruleId) || null;
  if (ruleIndex !== undefined && !byIndex) {
    throw new Error(`malformed SARIF ${path}: ruleIndex ${ruleIndex} has no rule`);
  }
  if (ruleId !== undefined && ruleIndex !== undefined &&
      (!byIndex || byIndex.id !== ruleId)) {
    throw new Error(`malformed SARIF ${path}: ruleId/ruleIndex reference different rules`);
  }
  if (ruleId !== undefined && ruleIndex === undefined && list.length && !byId) {
    throw new Error(`malformed SARIF ${path}: ruleId ${ruleId} is not declared by the driver`);
  }
  return byIndex || byId || (ruleId === undefined ? {} : { id: ruleId });
}

function parseSecurityScore(meta, path, ruleId) {
  const properties = meta?.properties;
  if (properties === undefined) return null;
  if (typeof properties !== 'object' || Array.isArray(properties)) {
    throw new Error(`malformed SARIF ${path}: rule properties are not an object`);
  }
  if (!Object.hasOwn(properties, SECURITY_SEVERITY_PROPERTY)) return null;
  const raw = properties[SECURITY_SEVERITY_PROPERTY];
  const text = typeof raw === 'string' ? raw.trim() : raw;
  if ((typeof text !== 'string' && typeof text !== 'number') ||
      (typeof text === 'string' && !/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(text))) {
    throw new Error(`malformed SARIF ${path}: rule ${ruleId || 'unknown'} has invalid security-severity`);
  }
  const score = Number(text);
  if (!Number.isFinite(score) || score < 0 || score > 10) {
    throw new Error(`malformed SARIF ${path}: rule ${ruleId || 'unknown'} has invalid security-severity`);
  }
  return score;
}

function securityLevel(score) {
  if (score === null || score === 0) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function authoritiesForFinding(finding) {
  const authorities = new Set();
  if (finding.sarifLevel && Object.hasOwn(SEVERITY, finding.sarifLevel)) {
    authorities.add(SEVERITY[finding.sarifLevel]);
  } else if (finding.severity) {
    authorities.add(finding.severity);
  }
  if (finding.securitySeverity) authorities.add(finding.securitySeverity);
  if (finding.severity) authorities.add(finding.severity);
  return authorities;
}

function blocksByPolicy(finding, policy) {
  return [...authoritiesForFinding(finding)].some((authority) => policy.includes(authority));
}

function fromSarif(path, toolHint) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`malformed SARIF ${path}: ${err.message}`);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) ||
      doc.version !== '2.1.0' || !Array.isArray(doc.runs)) {
    throw new Error(`malformed SARIF ${path}: expected version 2.1.0 with runs[]`);
  }
  for (const run of doc.runs) {
    const driver = run?.tool?.driver;
    if (!run || typeof run !== 'object' || Array.isArray(run) ||
        !driver || typeof driver !== 'object' || Array.isArray(driver) ||
        typeof driver.name !== 'string' || !driver.name.trim() ||
        ('results' in run && (!Array.isArray(run.results) ||
          run.results.some((result) => !result || typeof result !== 'object' || Array.isArray(result))))) {
      throw new Error(`malformed SARIF ${path}: invalid run structure`);
    }
    rulesFor(run, path);
    if (run.invocations !== undefined &&
        (!Array.isArray(run.invocations) ||
         run.invocations.some((invocation) =>
           !invocation || typeof invocation !== 'object' || Array.isArray(invocation)))) {
      throw new Error(`malformed SARIF ${path}: run invocations are invalid`);
    }
    for (const invocation of run.invocations || []) {
      if (Object.hasOwn(invocation, 'ruleConfigurationOverrides')) {
        throw new Error(
          `unsupported SARIF ${path}: invocation.ruleConfigurationOverrides are not supported`,
        );
      }
    }
  }
  for (const run of doc.runs) {
    for (const result of run.results || []) {
      const message = result.message;
      const hasMessageText = message && typeof message === 'object' && !Array.isArray(message) &&
        ['text', 'markdown', 'id'].some((key) => typeof message[key] === 'string' && message[key].trim());
      if (!hasMessageText) {
        throw new Error('malformed SARIF ' + path + ': result is missing message');
      }
      if ('ruleId' in result && typeof result.ruleId !== 'string') {
        throw new Error('malformed SARIF ' + path + ': result ruleId is not a string');
      }
      if ('ruleIndex' in result &&
          (!Number.isInteger(result.ruleIndex) || result.ruleIndex < 0)) {
        throw new Error('malformed SARIF ' + path + ': result ruleIndex is invalid');
      }
      if ('level' in result && !Object.hasOwn(SEVERITY, result.level)) {
        throw new Error('malformed SARIF ' + path + ': result level is invalid');
      }
      if ('locations' in result &&
          (!Array.isArray(result.locations) ||
           result.locations.some((location) => !location || typeof location !== 'object' || Array.isArray(location)))) {
        throw new Error('malformed SARIF ' + path + ': result locations are invalid');
      }
    }
  }

  const out = [];
  for (const run of doc.runs || []) {
    const tool = run.tool?.driver?.name || toolHint;
    for (const r of run.results || []) {
      const loc = r.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri || '';
      const line = loc?.region?.startLine || 0;
      const meta = ruleMeta(run, r, path);
      const ruleId = r.ruleId || meta.id || 'unknown';
      const securitySeverityScore = parseSecurityScore(meta, path, ruleId);
      const securitySeverity = securityLevel(securitySeverityScore);
      const sarifLevel = r.level || meta.defaultConfiguration?.level || 'warning';
      const levelSeverity = SEVERITY[sarifLevel] || 'warning';
      // A raw SARIF error is already a deterministic block and may never be downgraded
      // by a rule-level security score. A valid positive score raises warning/note results.
      const sev = levelSeverity === 'error' ? 'error' : securitySeverity || levelSeverity;
      out.push({
        tool,
        ruleId,
        file: file.replace(/^file:\/\//, ''),
        line,
        severity: sev,
        sarifLevel,
        securitySeverity,
        securitySeverityScore,
        securitySeveritySource: securitySeverityScore !== null
          ? 'rule.properties.security-severity' : null,
        message: (r.message?.text || r.message?.markdown || r.message?.id || '')
          .trim().replace(/\s+/g, ' '),
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
let scanners;
try {
  scanners = readScannerMetadata(statusPath, sarifDir);
} catch (err) {
  console.error(err.message);
  process.exit(1);
}

const all = [];
for (const f of readdirSync(sarifDir).filter((f) => f.endsWith('.sarif'))) {
  all.push(...fromSarif(join(sarifDir, f), f.replace('.sarif', '')));
}

// Equivalent evidence from the same tool is one problem. Records with conflicting
// authoritative SARIF level/score data remain separate so a later weaker result cannot
// erase a blocking dimension needed by a downstream policy.
const dedupedMap = new Map();
for (const finding of all) {
  const key = JSON.stringify([
    finding.tool,
    finding.file,
    finding.line,
    finding.ruleId,
    finding.sarifLevel,
    finding.securitySeverity,
    finding.securitySeverityScore,
    finding.securitySeveritySource,
  ]);
  if (!dedupedMap.has(key)) dedupedMap.set(key, finding);
}
const deduped = [...dedupedMap.values()];
const scoped = deduped.filter((f) => inScope(f.file, f.line));
const blocking = scoped.filter((f) => blocksByPolicy(f, blockOn));

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
