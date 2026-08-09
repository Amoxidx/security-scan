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
if (diff.length > config.gate.maxDiffBytes) {
  console.log(
    `Diff is ${diff.length} bytes, over the ${config.gate.maxDiffBytes} byte limit. ` +
      'Reviewing the first chunk only; flag this PR for manual review.'
  );
}
const diffText = diff.slice(0, config.gate.maxDiffBytes);

const systemPrompt = readFileSync(join(PROMPTS, '00-system.md'), 'utf8');
const huntPrompt = readFileSync(join(PROMPTS, '02-hunt.md'), 'utf8');
const verifyPrompt = readFileSync(join(PROMPTS, '03-verify.md'), 'utf8');
const reportPrompt = readFileSync(join(PROMPTS, '05-report.md'), 'utf8');

// ---------------------------------------------------------------- stage 2: hunt

async function hunt(lens) {
  const spec = config.hunt.models[lens];
  const target = spec && resolveModel(config, spec);
  if (!target) return [];
  const user = huntPrompt
    .replace(/\{\{LENS\}\}/g, lens)
    .replace('{{TARGET}}', 'The unified diff below. Review the changed lines and what they reach.')
    .replace('{{CONTEXT}}', `\n\`\`\`diff\n${diffText}\n\`\`\`\n`);

  try {
    const out = await providerComplete(config, target, systemPrompt, user);
    const parsed = parseJson(out, { findings: [] });
    const findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
    return findings.map((f) => ({ ...f, lens, huntModel: target.spec }));
  } catch (err) {
    console.error(`hunt[${lens}] failed: ${err.message}`);
    return [];
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
    .replace('{{FINDING}}', JSON.stringify(finding, null, 2))
    .replace('{{CODE}}', `\n\`\`\`diff\n${diffText}\n\`\`\`\n`);

  // Never let the model that found it be its only judge — a model refuting its own finding
  // confirms itself. Fall back to the full panel only if that would leave no verifier.
  const usable = config.verify.models.map((m) => resolveModel(config, m)).filter(Boolean);
  const others = usable.filter((t) => t.spec !== finding.huntModel);
  const panel = others.length ? others : usable;

  const verdicts = await Promise.all(
    panel.map(async (target) => {
      try {
        const out = await providerComplete(config, target, systemPrompt, user);
        // Unparseable verdict counts as a refutation: the default is "refuted".
        return { model: target.spec, ...parseJson(out, { refuted: true, reason: 'unparseable verdict' }) };
      } catch (err) {
        return { model: target.spec, refuted: true, reason: `verifier error: ${err.message}` };
      }
    })
  );

  const refutations = verdicts.filter((v) => v.refuted).length;
  // With a thin panel the threshold cannot exceed the number of judges, or nothing survives.
  const threshold = Math.min(config.verify.refuteThreshold, panel.length);
  const survived = panel.length > 0 && refutations < threshold;

  // The verify stage owns severity; the hunt stage's label is a proposal.
  const corrected = verdicts.find((v) => !v.refuted && v.severity)?.severity;

  return { ...finding, verdicts, refutations, survived, severity: corrected || finding.severity };
}

// ---------------------------------------------------------------- stage 5: report

async function report(finding) {
  const user = reportPrompt
    .replace('{{FINDING}}', JSON.stringify(finding, null, 2))
    .replace('{{VERDICT}}', JSON.stringify(finding.verdicts, null, 2))
    .replace('{{REPRO}}', JSON.stringify({ reproducible: false, blocker: 'repro stage not run in CI' }))
    .replace('{{REPRO_OUTPUT}}', '(none)');
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
  if (!config.verify.models.some((s) => resolveModel(config, s))) {
    console.warn('WARNING: no verifier reachable — findings cannot survive verification.');
  }

  console.log(`Hunting with ${activeLenses.length}/${config.hunt.lenses.length} lenses...`);
  const raw = (await Promise.all(activeLenses.map(hunt))).flat();
  const candidates = dedupe(raw);
  console.log(`${raw.length} raw findings -> ${candidates.length} after dedupe`);

  if (!candidates.length) {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'findings.json'), '[]');
    writeFileSync(join(outDir, 'report.md'), '## AI security review\n\nNo findings.\n');
    console.log('No findings. Gate passes.');
    return 0;
  }

  console.log('Verifying (adversarial, k-of-n)...');
  const verified = await Promise.all(candidates.map(verify));
  const survivors = verified
    .filter((f) => f.survived)
    .sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));

  console.log(`${verified.length} candidates -> ${survivors.length} survived verification`);

  const blocking = survivors.filter((f) => config.gate.blockOn.includes(f.severity));

  const reports = await Promise.all(survivors.map(report));

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'findings.json'), JSON.stringify(verified, null, 2));

  const md = [
    '## AI security review',
    '',
    `${raw.length} raw findings across ${activeLenses.length} lenses · ` +
      `${candidates.length} after dedupe · **${survivors.length} survived adversarial verification** · ` +
      `${blocking.length} blocking.`,
    '',
    blocking.length
      ? `> This check is red. Blocking severities: ${config.gate.blockOn.join(', ')}.`
      : '> This check is green. Anything below is informational.',
    '',
    survivors.length ? reports.join('\n\n---\n\n') : '_Nothing survived verification._',
    '',
    '---',
    '',
    '_Findings are verified but **not reproduced** — CI does not execute model-generated ' +
      'proof-of-concept code. Treat a blocking finding as "worth a human look", not as a ' +
      'confirmed exploit. See `docs/security/bitcoin-red-team-reconstruction.md` §5._',
  ].join('\n');
  writeFileSync(join(outDir, 'report.md'), md);

  if (blocking.length) {
    console.error(`\nBLOCKING: ${blocking.length} verified finding(s) at ${config.gate.blockOn.join('/')}:`);
    for (const f of blocking) console.error(`  [${f.severity}] ${f.file}:${f.line} — ${f.title}`);
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
