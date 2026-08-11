#!/usr/bin/env node
/**
 * Red-team harness — diff mode.
 *
 * Reconstruction of the Bitcoin Red Team pipeline, narrowed to what a blocking PR gate can
 * afford: hunt (fan-out over lenses) -> dedup -> adversarial verify (k-of-n) -> report.
 *
 * The repro stage (security/redteam/prompts/04-repro.md) is deliberately NOT executed here.
 * It generates code, and running model-generated code inside CI — which holds a checkout and
 * a token — is a worse problem than the one this gate solves. Repro belongs in the manual
 * audit run, in a sandbox. See security/README.md.
 *
 * Three provider types, mixable per stage (see config.json):
 *   cli        - a subscription coding agent in headless mode (kimi -p, claude -p). No API
 *                key, no per-token billing. This is the cheap path.
 *   anthropic  - /v1/messages, including Moonshot's Anthropic-compatible adapter.
 *   openai     - /chat/completions, including OpenCode Zen.
 *
 * Exit codes: 0 = pass or skipped, 1 = blocking findings, 3 = configuration error.
 *
 * Usage:
 *   node security/redteam/harness.mjs --diff <file> [--out <dir>] [--config <file>]
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { complete as providerComplete, resolveModel, listUnavailable } from './providers.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROMPTS = join(HERE, 'prompts');

// ---------------------------------------------------------------- args & config

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--')) throw new Error(`unexpected argument: ${argv[i]}`);
    args[argv[i].slice(2)] = argv[i + 1];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const outDir = args.out || 'security-report';
const config = JSON.parse(readFileSync(args.config || join(HERE, 'config.json'), 'utf8'));

if (!args.diff) {
  console.error('--diff <file> is required');
  process.exit(3);
}

const diff = readFileSync(args.diff, 'utf8');
if (!diff.trim()) {
  console.log('Empty diff — nothing to review.');
  process.exit(0);
}
const truncated = diff.length > config.gate.maxDiffBytes;
// Default: a truncated review is not a clean pass. Large PRs must be split or reviewed by a human;
// silently scoring only the first chunk would green-light the unreviewed tail.
const blockOnTruncated = config.gate.blockOnTruncatedDiff !== false;
if (truncated) {
  const msg =
    `Diff is ${diff.length} bytes, over the ${config.gate.maxDiffBytes} byte limit. ` +
    (blockOnTruncated
      ? 'Blocking — split the change or raise gate.maxDiffBytes after a manual review.'
      : 'Reviewing the first chunk only; flag this PR for manual review.');
  console.log(msg);
  if (blockOnTruncated) {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'findings.json'), '[]');
    writeFileSync(
      join(outDir, 'report.md'),
      `## AI security review\n\n**Blocked:** diff exceeds \`gate.maxDiffBytes\` ` +
        `(${diff.length} > ${config.gate.maxDiffBytes}). The unreviewed tail must not pass silently.\n`
    );
    process.exit(1);
  }
}
const diffText = diff.slice(0, config.gate.maxDiffBytes);

const systemPrompt = readFileSync(join(PROMPTS, '00-system.md'), 'utf8');
const huntPrompt = readFileSync(join(PROMPTS, '02-hunt.md'), 'utf8');
const verifyPrompt = readFileSync(join(PROMPTS, '03-verify.md'), 'utf8');
const reportPrompt = readFileSync(join(PROMPTS, '05-report.md'), 'utf8');

const UNTRUSTED_BEGIN = '<<<UNTRUSTED_INPUT_BEGIN>>>';
const UNTRUSTED_END = '<<<UNTRUSTED_INPUT_END>>>';

/** Strip sentinel markers from untrusted content so an attacker cannot close the envelope. */
function wrapUntrusted(text) {
  const cleaned = String(text)
    .split(UNTRUSTED_BEGIN).join('')
    .split(UNTRUSTED_END).join('');
  return `${UNTRUSTED_BEGIN}\n${cleaned}\n${UNTRUSTED_END}`;
}

/**
 * Parse a JSON object or array from model output. Optional second argument is the fallback
 * when parsing fails (callers in this file pass an object; triage.mjs has a one-arg form
 * that returns null instead — do not change triage behaviour when sharing).
 */
function parseJson(text, fallback = null) {
  const cleaned = String(text).trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = cleaned.search(/[{[]/);
  if (start === -1) return fallback;
  try {
    return JSON.parse(cleaned.slice(start));
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------- stage 2: hunt

/** Per-lens hunt outcome: either findings or a recorded failure. */
async function hunt(lens) {
  const spec = config.hunt.models[lens];
  const target = spec && resolveModel(config, spec);
  if (!target) return { lens, ok: false, error: 'no reachable model', findings: [] };
  const user = huntPrompt
    .replace(/\{\{LENS\}\}/g, lens)
    .replace('{{TARGET}}', 'The unified diff below. Review the changed lines and what they reach.')
    .replace('{{CONTEXT}}', wrapUntrusted(diffText));

  try {
    const out = await providerComplete(config, target, systemPrompt, user);
    const parsed = parseJson(out, { findings: [] });
    const findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
    return {
      lens,
      ok: true,
      findings: findings.map((f) => ({ ...f, lens, huntModel: target.spec })),
    };
  } catch (err) {
    console.error(`hunt[${lens}] failed: ${err.message}`);
    return { lens, ok: false, error: err.message, findings: [] };
  }
}

/** Same root cause reported by two lenses is one finding, not two. */
function dedupe(findings) {
  const byKey = new Map();
  for (const f of findings) {
    if (!f || !f.file || !f.title) continue;
    const key = `${f.file}:${Math.floor((Number(f.line) || 0) / 5)}:${(f.root_cause || f.title)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ' ')
      .split(' ')
      .filter((w) => w.length > 4)
      .slice(0, 6)
      .join('-')}`;
    const existing = byKey.get(key);
    if (existing) existing.lenses.push(f.lens);
    else byKey.set(key, { ...f, lenses: [f.lens] });
  }
  return [...byKey.values()];
}

// ---------------------------------------------------------------- stage 3: verify

async function verify(finding) {
  const user = verifyPrompt
    .replace('{{FINDING}}', wrapUntrusted(JSON.stringify(finding, null, 2)))
    .replace('{{CODE}}', wrapUntrusted(diffText));

  // Never let the model that found it be its only judge — a model refuting its own finding
  // confirms itself. Fall back to the full panel only if that would leave no verifier.
  const usable = config.verify.models.map((m) => resolveModel(config, m)).filter(Boolean);
  const others = usable.filter((t) => t.spec !== finding.huntModel);
  const panel = others.length ? others : usable;

  // Empty panel: do not silently drop candidates. Pass through as unverified so blocking
  // still follows gate.blockOn (same idea as triage passthrough without a model).
  if (panel.length === 0) {
    return {
      ...finding,
      verdicts: [],
      refutations: 0,
      survived: true,
      unverified: true,
      severity: finding.severity,
    };
  }

  const verdicts = await Promise.all(
    panel.map(async (target) => {
      try {
        const out = await providerComplete(config, target, systemPrompt, user);
        const parsed = parseJson(out, null);
        // An error or unparseable answer is inconclusive, not a refutation.
        if (!parsed || typeof parsed.refuted !== 'boolean') {
          return {
            model: target.spec,
            inconclusive: true,
            refuted: false,
            reason: 'unparseable verdict',
          };
        }
        return { model: target.spec, ...parsed, inconclusive: false };
      } catch (err) {
        return {
          model: target.spec,
          inconclusive: true,
          refuted: false,
          reason: `verifier error: ${err.message}`,
        };
      }
    })
  );

  const conclusive = verdicts.filter((v) => !v.inconclusive);
  // All inconclusive: treat as unverified (pass through), not as refuted away.
  if (conclusive.length === 0) {
    return {
      ...finding,
      verdicts,
      refutations: 0,
      survived: true,
      unverified: true,
      severity: finding.severity,
    };
  }

  const refutations = conclusive.filter((v) => v.refuted === true).length;
  // Threshold applies to verdicts that actually judged, not to errors/timeouts.
  const threshold = Math.min(config.verify.refuteThreshold, conclusive.length);
  const survived = refutations < threshold;

  // The verify stage owns severity; the hunt stage's label is a proposal.
  const corrected = conclusive.find((v) => !v.refuted && v.severity)?.severity;

  return { ...finding, verdicts, refutations, survived, severity: corrected || finding.severity };
}

// ---------------------------------------------------------------- stage 5: report

async function report(finding) {
  // Findings and verdicts are model- or diff-derived — treat as untrusted input, same as hunt/verify.
  const user = reportPrompt
    .replace('{{FINDING}}', wrapUntrusted(JSON.stringify(finding, null, 2)))
    .replace('{{VERDICT}}', wrapUntrusted(JSON.stringify(finding.verdicts, null, 2)))
    .replace('{{REPRO}}', wrapUntrusted(JSON.stringify({ reproducible: false, blocker: 'repro stage not run in CI' })))
    .replace('{{REPRO_OUTPUT}}', wrapUntrusted('(none)'));
  const target = resolveModel(config, config.report.model);
  if (!target) {
    return `## ${finding.title}\n\n_No report model available. Raw finding:_\n\n\`\`\`json\n${JSON.stringify(finding, null, 2)}\n\`\`\``;
  }
  try {
    return await providerComplete(config, target, systemPrompt, user);
  } catch (err) {
    return `## ${finding.title}\n\n_Report generation failed (${err.message}). Raw finding:_\n\n\`\`\`json\n${JSON.stringify(finding, null, 2)}\n\`\`\``;
  }
}

// ---------------------------------------------------------------- main

const rank = { critical: 3, high: 2, medium: 1, low: 0 };

async function main() {
  // Report what is and is not reachable before spending anything.
  const referenced = [...new Set([
    ...Object.values(config.hunt.models),
    ...config.verify.models,
    config.report.model,
  ])];
  const usable = referenced.filter((s) => resolveModel(config, s));
  for (const line of listUnavailable(config, referenced)) console.log(`  ${line}`);
  if (!usable.length) {
    console.log('\nNo model provider is reachable — skipping the AI review stage.');
    console.log('Configure a subscription CLI or an API key; see security/README.md.');
    console.log('The deterministic gate (security/gate/static-checks.sh) still applies.');
    return 0;
  }
  const activeLenses = config.hunt.lenses.filter((l) => {
    const s = config.hunt.models[l];
    return Boolean(s) && Boolean(resolveModel(config, s));
  });
  const hasVerifier = config.verify.models.some((s) => resolveModel(config, s));
  if (!hasVerifier) {
    console.warn(
      'WARNING: no verifier reachable — findings will pass through UNVERIFIED; ' +
        'blocking still follows gate.blockOn.'
    );
  }

  console.log(`Hunting with ${activeLenses.length}/${config.hunt.lenses.length} lenses...`);
  const huntResults = await Promise.all(activeLenses.map(hunt));
  const huntFailures = huntResults.filter((r) => !r.ok);
  const raw = huntResults.flatMap((r) => r.findings);
  const candidates = dedupe(raw);

  if (huntFailures.length) {
    console.error(
      `hunt: ${huntFailures.length}/${activeLenses.length} lens(es) failed: ` +
        huntFailures.map((f) => `${f.lens} (${f.error})`).join('; ')
    );
  }
  console.log(`${raw.length} raw findings -> ${candidates.length} after dedupe`);

  // Every active lens failed: configuration/runtime error, not a green gate.
  if (activeLenses.length > 0 && huntFailures.length === activeLenses.length) {
    mkdirSync(outDir, { recursive: true });
    const detail = huntFailures.map((f) => `- ${f.lens}: ${f.error}`).join('\n');
    writeFileSync(join(outDir, 'findings.json'), '[]');
    writeFileSync(
      join(outDir, 'report.md'),
      `## AI security review\n\n**Hunt stage failed:** all ${activeLenses.length} active ` +
        `lens(es) errored. This is a configuration/runtime error, not a clean pass.\n\n${detail}\n`
    );
    console.error(
      `All ${activeLenses.length} active lens(es) failed — gate cannot run. Exit 3.`
    );
    return 3;
  }

  if (!candidates.length) {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'findings.json'), '[]');
    const failNote = huntFailures.length
      ? `\n\n_${huntFailures.length} lens(es) failed during hunt; remaining lenses reported nothing._\n`
      : '';
    writeFileSync(
      join(outDir, 'report.md'),
      `## AI security review\n\nNo findings.${failNote}`
    );
    console.log('No findings. Gate passes.');
    return 0;
  }

  console.log('Verifying (adversarial, k-of-n)...');
  const verified = await Promise.all(candidates.map(verify));
  const survivors = verified
    .filter((f) => f.survived)
    .sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));
  const unverifiedCount = survivors.filter((f) => f.unverified).length;

  console.log(
    `${verified.length} candidates -> ${survivors.length} survived` +
      (unverifiedCount ? ` (${unverifiedCount} unverified)` : ' verification')
  );

  const blocking = survivors.filter((f) => config.gate.blockOn.includes(f.severity));

  const reports = await Promise.all(survivors.map(report));

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'findings.json'), JSON.stringify(verified, null, 2));

  const verificationNote = unverifiedCount
    ? `**${survivors.length} carried forward (${unverifiedCount} NOT verified — no usable verifier verdict)**`
    : `**${survivors.length} survived adversarial verification**`;

  const huntFailNote = huntFailures.length
    ? ` · ${huntFailures.length} lens(es) failed`
    : '';

  const md = [
    '## AI security review',
    '',
    `${raw.length} raw findings across ${activeLenses.length} lenses · ` +
      `${candidates.length} after dedupe · ${verificationNote} · ` +
      `${blocking.length} blocking.${huntFailNote}`,
    '',
    huntFailures.length
      ? `> **Hunt failures:** ${huntFailures.map((f) => `${f.lens} (${f.error})`).join('; ')}.`
      : null,
    huntFailures.length ? '' : null,
    unverifiedCount
      ? '> **Unverified findings:** no usable verifier was available (or every verifier ' +
        'returned an error/unparseable answer). These findings were **not** adversarially ' +
        'verified; they pass through so a missing verifier cannot silence the hunt stage. ' +
        'Blocking still follows configured severities.'
      : null,
    unverifiedCount ? '' : null,
    blocking.length
      ? `> This check is red. Blocking severities: ${config.gate.blockOn.join(', ')}.`
      : '> This check is green. Anything below is informational.',
    '',
    survivors.length ? reports.join('\n\n---\n\n') : '_Nothing survived verification._',
    '',
    '---',
    '',
    unverifiedCount
      ? '_Some findings above were **not verified**. CI does not execute model-generated ' +
        'proof-of-concept code. Treat a blocking finding as "worth a human look", not as a ' +
        'confirmed exploit. See `docs/security/bitcoin-red-team-reconstruction.md` §5._'
      : '_Findings are verified but **not reproduced** — CI does not execute model-generated ' +
        'proof-of-concept code. Treat a blocking finding as "worth a human look", not as a ' +
        'confirmed exploit. See `docs/security/bitcoin-red-team-reconstruction.md` §5._',
  ]
    .filter((line) => line !== null)
    .join('\n');
  writeFileSync(join(outDir, 'report.md'), md);

  if (blocking.length) {
    const label = unverifiedCount ? 'finding(s)' : 'verified finding(s)';
    console.error(`\nBLOCKING: ${blocking.length} ${label} at ${config.gate.blockOn.join('/')}:`);
    for (const f of blocking) {
      const tag = f.unverified ? 'unverified' : 'verified';
      console.error(`  [${f.severity}] (${tag}) ${f.file}:${f.line} — ${f.title}`);
    }
    return 1;
  }
  console.log('Gate passes.');
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`harness failed: ${err.stack || err.message}`);
    process.exit(3);
  }
);
