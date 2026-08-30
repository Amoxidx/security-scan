#!/usr/bin/env node
/**
 * Local repro / fuzz / trace lab — manual only, never CI.
 *
 * Takes one finding (+ staged code), drives a local model (default: jk-coder (local
 * Qwen3.8-Flash-Next, MoE, 4-bit) via mlx-serve's OpenAI-compatible endpoint, no longer
 * Ollama) through a hard-capped execute/conclude loop, runs every proposed script inside
 * an ephemeral docker/colima sandbox, and writes a report
 * with verdict reproduced | not-reproduced | inconclusive.
 *
 * Fail closed: hitting the turn cap or wall-clock timeout yields inconclusive, never
 * "not-reproduced" / "safe".
 *
 * Usage:
 *   node security/lab/run.mjs \
 *     --finding <file.json> \
 *     --code-dir <dir> \
 *     [--diff <file>] \
 *     [--out <dir>] \
 *     [--model ollama:jk-coder] \
 *     [--max-turns 6] \
 *     [--timeout-s 600] \
 *     [--sandbox-timeout-s 60] \
 *     [--memory 512m] \
 *     [--cpus 1]
 *
 * Exit: 0 conclusive (reproduced|not-reproduced), 2 inconclusive, 3 setup error.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  cpSync,
  rmSync,
  existsSync,
  readdirSync,
  statSync,
  mkdtempSync,
} from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  complete as providerComplete,
  resolveModel,
  unavailableReason,
} from '../redteam/providers.mjs';
import { ensureImage, runInSandbox, DEFAULT_IMAGE } from './sandbox.mjs';
import { DEFAULT_LAB_MODEL } from '../studio/lab-model.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../..');
const DEFAULT_CONFIG = join(REPO, 'security/redteam/config.json');
const PROMPT_PATH = join(HERE, 'prompt.md');

const VALID_VERDICTS = new Set(['reproduced', 'not-reproduced', 'inconclusive']);

// ---------------------------------------------------------------- args

function parseArgs(argv) {
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
  console.error(`Usage: node security/lab/run.mjs --finding <file> --code-dir <dir> [options]
  --finding <file>           Finding JSON (harness/triage shape)
  --code-dir <dir>           Directory staged into the sandbox as the subject tree
  --diff <file>              Optional unified diff for context
  --out <dir>                Report directory (default: security-lab-report)
  --config <file>            Provider config (default: security/redteam/config.json)
  --model <spec>             provider:model (default: ollama:jk-coder)
  --max-turns <n>            Hard iteration cap (default: 6)
  --timeout-s <n>            Wall-clock timeout for the whole run (default: 600)
  --sandbox-timeout-s <n>    Per-script timeout inside the container (default: 60)
  --memory <docker-mem>      Container memory cap (default: 512m)
  --cpus <n>                 Container CPU cap (default: 1)
  --image <name>             Sandbox image (default: ${DEFAULT_IMAGE})
  --keep-workdir             Keep the staged sandbox workdir for inspection`);
  process.exit(3);
}

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (err) {
  usage(err.message);
}

if (!args.finding || !args['code-dir']) usage('--finding and --code-dir are required');

const findingPath = resolve(args.finding);
const codeDir = resolve(args['code-dir']);
const outDir = resolve(args.out || 'security-lab-report');
const configPath = resolve(args.config || DEFAULT_CONFIG);
const keepWorkdir = Boolean(args['keep-workdir']);
const diffPath = args.diff ? resolve(args.diff) : null;

if (!existsSync(findingPath)) usage(`finding not found: ${findingPath}`);
if (!existsSync(codeDir) || !statSync(codeDir).isDirectory()) usage(`code-dir not a directory: ${codeDir}`);
if (!existsSync(configPath)) usage(`config not found: ${configPath}`);

// ---------------------------------------------------------------- load inputs

const config = JSON.parse(readFileSync(configPath, 'utf8'));
const labCfg = config.lab || {};
const modelSpec = args.model || labCfg.model || DEFAULT_LAB_MODEL;
const maxTurns = Math.max(0, Number(args['max-turns'] ?? labCfg.maxTurns ?? 6));
const timeoutS = Math.max(1, Number(args['timeout-s'] ?? labCfg.timeoutS ?? 600));
const sandboxTimeoutS = Math.max(1, Number(args['sandbox-timeout-s'] ?? 60));
const memory = String(args.memory || '512m');
const cpus = String(args.cpus || '1');
const image = String(args.image || DEFAULT_IMAGE);
// Missing lab.temperature falls through as undefined; providers.mjs then keeps its 0.2 default.
// A present value must be a finite number in [0, 2]: Number("warm") or Number({}) is NaN,
// which would not trigger the providers.mjs default but would serialize as JSON null, so the
// server would sample with its own default while the report still claimed a set temperature.
const temperature = labCfg.temperature === undefined || labCfg.temperature === null
  ? undefined
  : Number(labCfg.temperature);
if (temperature !== undefined && (!Number.isFinite(temperature) || temperature < 0 || temperature > 2)) {
  console.error(
    `invalid lab.temperature: ${JSON.stringify(labCfg.temperature)} — ` +
      'needs a finite number between 0 and 2, or null/absent to use the provider default',
  );
  process.exit(3);
}
const finding = JSON.parse(readFileSync(findingPath, 'utf8'));
const systemPrompt = readFileSync(PROMPT_PATH, 'utf8');
const diffText = diffPath && existsSync(diffPath) ? readFileSync(diffPath, 'utf8') : '';

// Ollama ignores the Authorization header; providers.mjs still requires apiKeyEnv to be set.
if (config.providers?.ollama?.apiKeyEnv) {
  const k = config.providers.ollama.apiKeyEnv;
  if (!process.env[k]) process.env[k] = 'ollama';
}

const target = resolveModel(config, modelSpec);
if (!target) {
  const name = modelSpec.includes(':') ? modelSpec.slice(0, modelSpec.indexOf(':')) : config.defaultProvider;
  console.error(`model unavailable: ${modelSpec} (${unavailableReason(config, name) || 'unresolved'})`);
  process.exit(3);
}

// ---------------------------------------------------------------- helpers

const UNTRUSTED_BEGIN = '<<<UNTRUSTED_INPUT_BEGIN>>>';
const UNTRUSTED_END = '<<<UNTRUSTED_INPUT_END>>>';

function wrapUntrusted(text) {
  const cleaned = String(text)
    .split(UNTRUSTED_BEGIN).join('')
    .split(UNTRUSTED_END).join('');
  return `${UNTRUSTED_BEGIN}\n${cleaned}\n${UNTRUSTED_END}`;
}

export function parseJson(text, fallback = null) {
  let cleaned = String(text).trim();
  // Strip a leading ```json ... ``` fence even when prose follows or precedes it.
  const fence = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) cleaned = fence[1].trim();
  else cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');

  const start = cleaned.search(/[{[]/);
  if (start === -1) return fallback;
  const slice = cleaned.slice(start);
  try {
    return JSON.parse(slice);
  } catch {
    // Balanced-brace scan: models often emit one object then trail off mid-token.
    let depth = 0;
    let inStr = false;
    let esc = false;
    for (let i = 0; i < slice.length; i += 1) {
      const c = slice[i];
      if (inStr) {
        if (esc) esc = false;
        else if (c === '\\') esc = true;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') inStr = true;
      else if (c === '{' || c === '[') depth += 1;
      else if (c === '}' || c === ']') {
        depth -= 1;
        if (depth === 0) {
          try {
            return JSON.parse(slice.slice(0, i + 1));
          } catch {
            return fallback;
          }
        }
      }
    }
    return fallback;
  }
}

function collectCodeSnapshot(dir, { maxFiles = 40, maxBytes = 120_000 } = {}) {
  const files = [];
  const skip = new Set(['node_modules', '.git', 'dist', 'coverage', '.next']);
  function walk(rel) {
    if (files.length >= maxFiles) return;
    const abs = join(dir, rel);
    let entries;
    try {
      entries = readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (files.length >= maxFiles) return;
      if (skip.has(ent.name) || ent.name.startsWith('.git')) continue;
      const child = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) walk(child);
      else if (ent.isFile()) {
        const full = join(dir, child);
        let st;
        try {
          st = statSync(full);
        } catch {
          continue;
        }
        if (st.size > 200_000) continue;
        let body;
        try {
          body = readFileSync(full, 'utf8');
        } catch {
          continue;
        }
        files.push({ path: child, content: body });
      }
    }
  }
  walk('');
  let used = 0;
  const out = [];
  for (const f of files) {
    if (used >= maxBytes) break;
    const room = maxBytes - used;
    const content = f.content.length > room ? f.content.slice(0, room) + '\n/* truncated */\n' : f.content;
    used += content.length;
    out.push({ path: f.path, content });
  }
  return out;
}

function stageWorkdir(srcDir) {
  // Colima/Lima only mounts the user home by default — paths under /tmp, /var/folders,
  // or /private/tmp are invisible inside the VM even when docker -v accepts them.
  // Always stage under $HOME so the bind mount actually contains the files.
  const home = process.env.HOME;
  if (!home) throw new Error('HOME is not set; cannot stage sandbox workdir under a colima-visible path');
  const cacheRoot = join(home, '.cache', 'security-lab');
  mkdirSync(cacheRoot, { recursive: true });
  const work = mkdtempSync(join(cacheRoot, 'run-'));
  // Copy only the subject tree — never the host repo root (would include .git, secrets, etc.).
  cpSync(srcDir, work, {
    recursive: true,
    filter: (src) => {
      const base = basename(src);
      if (base === '.git' || base === 'node_modules') return false;
      return true;
    },
  });
  return work;
}

function remainingMs(deadline) {
  return Math.max(0, deadline - Date.now());
}

function buildInitialUserMessage() {
  const snapshot = collectCodeSnapshot(codeDir);
  const codeBlock = snapshot
    .map((f) => `--- ${f.path}\n${f.content}`)
    .join('\n\n');
  return [
    'FINDING (JSON):',
    wrapUntrusted(JSON.stringify(finding, null, 2)),
    '',
    'CODE (staged workspace files):',
    wrapUntrusted(codeBlock || '(empty workspace)'),
    '',
    diffText
      ? `DIFF (optional context):\n${wrapUntrusted(diffText.slice(0, 80_000))}\n`
      : '',
    'Respond with the next JSON action (`execute` or `conclude`).',
  ].join('\n');
}

async function callModel(system, user, budgetMs, temperature) {
  if (budgetMs <= 0) throw new Error('wall-clock budget exhausted before model call');
  const call = providerComplete(config, target, system, user, { retries: 1, temperature });
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`model call exceeded remaining wall-clock (${budgetMs}ms)`)), budgetMs);
  });
  try {
    return await Promise.race([call, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- report

function writeReport(report) {
  mkdirSync(outDir, { recursive: true });
  const jsonPath = join(outDir, 'report.json');
  const mdPath = join(outDir, 'report.md');
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  const lines = [
    `# Repro lab report`,
    ``,
    `**Verdict:** \`${report.verdict}\``,
    `**Model:** \`${report.model}\``,
    `**Finding:** ${report.finding?.title || report.finding?.summary || report.finding?.id || '(untitled)'}`,
    `**Turns used:** ${report.turnsUsed} / ${report.limits.maxTurns}`,
    `**Elapsed:** ${report.elapsedMs}ms (limit ${report.limits.timeoutS}s)`,
    ``,
    `## Reasoning`,
    ``,
    report.reasoning || '_(none)_',
    ``,
  ];
  if (report.blocker) {
    lines.push(`## Blocker`, ``, report.blocker, ``);
  }
  if (report.limits.hitTurnCap || report.limits.hitWallClock) {
    lines.push(
      `## Fail-closed`,
      ``,
      report.limits.hitWallClock
        ? `inconclusive — did not converge within ${report.limits.timeoutS}s wall-clock`
        : `inconclusive — did not converge within ${report.limits.maxTurns} turns`,
      ``,
    );
  }
  lines.push(`## Turns`, ``);
  for (const t of report.turns) {
    lines.push(`### Turn ${t.turn} — \`${t.action || 'unknown'}\``);
    if (t.sandbox) {
      lines.push(
        ``,
        `- exit: \`${t.sandbox.exitCode}\`${t.sandbox.timedOut ? ' (timed out)' : ''}`,
        `- command: \`${(t.sandbox.runCommand || []).join(' ')}\``,
        ``,
        '```',
        (t.sandbox.stdout || '').slice(0, 4000),
        (t.sandbox.stderr || '').slice(0, 2000),
        '```',
        ``,
      );
    } else if (t.raw) {
      lines.push(``, '```', String(t.raw).slice(0, 3000), '```', ``);
    }
    if (t.error) lines.push(``, `Error: ${t.error}`, ``);
  }
  writeFileSync(mdPath, lines.join('\n'));
  return { jsonPath, mdPath };
}

let workdirForCleanup = null;

function cleanupWorkdir() {
  if (workdirForCleanup && !keepWorkdir) {
    try {
      rmSync(workdirForCleanup, { recursive: true, force: true });
    } catch {
      // best-effort
    }
    workdirForCleanup = null;
  }
}

function finalize(partial) {
  clearTimeout(hardKill);
  cleanupWorkdir();
  const report = {
    verdict: partial.verdict,
    reasoning: partial.reasoning || '',
    blocker: partial.blocker || null,
    finding,
    model: modelSpec,
    provider: target.providerName,
    resolvedModel: target.model,
    temperature: temperature ?? null,
    turnsUsed: partial.turns.length,
    elapsedMs: Date.now() - startedAt,
    limits: {
      maxTurns,
      timeoutS,
      hitTurnCap: Boolean(partial.hitTurnCap),
      hitWallClock: Boolean(partial.hitWallClock),
    },
    sandbox: {
      image,
      memory,
      cpus,
      network: 'none',
      perScriptTimeoutS: sandboxTimeoutS,
    },
    turns: partial.turns,
    startedAt: new Date(startedAt).toISOString(),
    finishedAt: new Date().toISOString(),
  };
  const paths = writeReport(report);
  console.log(`verdict: ${report.verdict}`);
  console.log(`report: ${paths.jsonPath}`);
  console.log(`report-md: ${paths.mdPath}`);
  if (report.verdict === 'inconclusive') process.exit(2);
  process.exit(0);
}

// ---------------------------------------------------------------- main loop

const startedAt = Date.now();
const deadline = startedAt + timeoutS * 1000;
const turns = [];

// Hard process-level kill: if anything hangs past the wall clock + grace, still fail closed.
const hardKill = setTimeout(() => {
  try {
    writeReport({
      verdict: 'inconclusive',
      reasoning: `inconclusive — did not converge within ${timeoutS}s`,
      blocker: `wall-clock hard kill after ${timeoutS}s`,
      finding,
      model: modelSpec,
      provider: target.providerName,
      resolvedModel: target.model,
      temperature: temperature ?? null,
      turnsUsed: turns.length,
      elapsedMs: Date.now() - startedAt,
      limits: { maxTurns, timeoutS, hitTurnCap: false, hitWallClock: true },
      sandbox: { image, memory, cpus, network: 'none', perScriptTimeoutS: sandboxTimeoutS },
      turns,
      startedAt: new Date(startedAt).toISOString(),
      finishedAt: new Date().toISOString(),
    });
    console.error(`inconclusive — did not converge within ${timeoutS}s`);
  } catch (err) {
    console.error(`hard kill; failed to write report: ${err.message}`);
  }
  process.exit(2);
}, timeoutS * 1000 + 5_000);
hardKill.unref?.();

console.log(`lab: model=${modelSpec} maxTurns=${maxTurns} timeoutS=${timeoutS}`);
console.log(`lab: code-dir=${codeDir}`);
console.log(`lab: sandbox image=${image} memory=${memory} cpus=${cpus} network=none`);

// Turn cap 0 → immediate inconclusive (limit must be real, not decorative).
if (maxTurns === 0) {
  finalize({
    verdict: 'inconclusive',
    reasoning: `inconclusive — did not converge within 0 turns`,
    blocker: 'max-turns is 0',
    turns,
    hitTurnCap: true,
    hitWallClock: false,
  });
}

const img = await ensureImage(image, { timeoutMs: Math.min(remainingMs(deadline), 600_000) });
if (!img.ok) {
  console.error(img.error);
  finalize({
    verdict: 'inconclusive',
    reasoning: 'sandbox image unavailable',
    blocker: img.error,
    turns,
    hitTurnCap: false,
    hitWallClock: remainingMs(deadline) <= 0,
  });
}

workdirForCleanup = stageWorkdir(codeDir);
console.log(`lab: staged workdir=${workdirForCleanup}`);

let userMessage = buildInitialUserMessage();

for (let turn = 1; turn <= maxTurns; turn += 1) {
  if (remainingMs(deadline) <= 0) {
    finalize({
      verdict: 'inconclusive',
      reasoning: `inconclusive — did not converge within ${timeoutS}s`,
      blocker: 'wall-clock timeout before next model turn',
      turns,
      hitTurnCap: false,
      hitWallClock: true,
    });
  }

  console.log(`lab: turn ${turn}/${maxTurns} (${Math.ceil(remainingMs(deadline) / 1000)}s left)`);

  let raw;
  try {
    // Leave a few seconds of budget for report writing after the last call.
    const budget = Math.max(1_000, remainingMs(deadline) - 3_000);
    raw = await callModel(systemPrompt, userMessage, budget, temperature);
  } catch (err) {
    turns.push({ turn, action: 'error', error: err.message });
    const hitWall = /wall-clock|budget exhausted/i.test(err.message) || remainingMs(deadline) <= 0;
    finalize({
      verdict: 'inconclusive',
      reasoning: hitWall
        ? `inconclusive — did not converge within ${timeoutS}s`
        : `model error: ${err.message}`,
      blocker: err.message,
      turns,
      hitTurnCap: false,
      hitWallClock: hitWall,
    });
  }

  const parsed = parseJson(raw, null);
  if (!parsed || typeof parsed !== 'object') {
    turns.push({ turn, action: 'unparseable', raw: String(raw).slice(0, 4000) });
    userMessage = [
      'Your previous reply was not valid JSON matching the protocol.',
      'Reply again with exactly one JSON object: action execute or conclude.',
      `Raw reply was:\n${wrapUntrusted(String(raw).slice(0, 2000))}`,
    ].join('\n');
    continue;
  }

  if (parsed.action === 'conclude') {
    const verdict = VALID_VERDICTS.has(parsed.verdict) ? parsed.verdict : 'inconclusive';
    turns.push({
      turn,
      action: 'conclude',
      verdict,
      reasoning: parsed.reasoning || '',
      blocker: parsed.blocker || null,
      raw: parsed,
    });
    finalize({
      verdict,
      reasoning: parsed.reasoning || '',
      blocker: parsed.blocker || null,
      turns,
      hitTurnCap: false,
      hitWallClock: false,
    });
  }

  if (parsed.action !== 'execute') {
    turns.push({ turn, action: parsed.action || 'unknown', raw: parsed });
    userMessage = [
      `Unsupported action ${JSON.stringify(parsed.action)}. Use "execute" or "conclude".`,
    ].join('\n');
    continue;
  }

  const filename = String(parsed.filename || 'repro.mjs').replace(/^\/+/, '');
  const script = String(parsed.script ?? '');
  let runCommand = parsed.run_command;
  if (typeof runCommand === 'string') {
    // Tolerate a single string; split naively on spaces (model should send argv array).
    runCommand = runCommand.trim().split(/\s+/);
  }
  if (!Array.isArray(runCommand)) runCommand = ['node', filename];

  if (!script.trim()) {
    turns.push({ turn, action: 'execute', error: 'empty script' });
    userMessage = 'execute was returned with an empty script. Provide a full script or conclude.';
    continue;
  }

  if (remainingMs(deadline) <= 0) {
    turns.push({ turn, action: 'execute', error: 'wall-clock timeout before sandbox' });
    finalize({
      verdict: 'inconclusive',
      reasoning: `inconclusive — did not converge within ${timeoutS}s`,
      blocker: 'wall-clock timeout before sandbox run',
      turns,
      hitTurnCap: false,
      hitWallClock: true,
    });
  }

  const sandboxBudget = Math.min(sandboxTimeoutS * 1000, remainingMs(deadline));
  const sandboxResult = await runInSandbox({
    workdir: workdirForCleanup,
    filename,
    script,
    runCommand,
    image,
    memory,
    cpus,
    timeoutMs: sandboxBudget,
  });

  turns.push({
    turn,
    action: 'execute',
    filename,
    runCommand,
    expect: parsed.expect || null,
    script: script.slice(0, 20_000),
    sandbox: sandboxResult,
  });

  // Count consecutive non-zero exits with essentially the same script — Qwen often
  // re-emits the same repro instead of concluding. After two identical fails, force conclude.
  const sameFailStreak = (() => {
    if (sandboxResult.exitCode === 0) return 0;
    let streak = 1;
    for (let i = turns.length - 2; i >= 0; i -= 1) {
      const prev = turns[i];
      if (prev.action !== 'execute' || !prev.sandbox || prev.sandbox.exitCode === 0) break;
      const prevScript = String(prev.script || '').trim();
      if (prevScript && prevScript === script.trim()) streak += 1;
      else break;
    }
    return streak;
  })();

  const decisiveHint = sandboxResult.exitCode === 0
    ? [
        'exitCode is 0. Under the contract that is a necessary condition for the bug being present, not a proof of it.',
        'Before you conclude, work through the self-check from your instructions, one point at a time.',
        'The most common false positive is exit 0 because the script ended before the assertion ran —',
        'for example an imported file that calls process.exit(0) while loading.',
        'If any check answers "no", do not conclude: fix the script and run it again.',
        'If you conclude, your reasoning must state which assertion you evaluated and what it showed.',
        'Example shape: {"action":"conclude","verdict":"<verdict you derived>","reasoning":"<your own finding from this run>","blocker":null}',
      ].join(' ')
    : sameFailStreak >= 2
      ? [
          `exitCode is non-zero for the ${sameFailStreak}rd consecutive time with the same script.`,
          'The fair test failed: the defect is ABSENT given this code, or the claim is wrong.',
          'Your next reply MUST be action conclude with verdict not-reproduced (or inconclusive if the environment blocked a fair test).',
          'Do NOT re-emit the same script. Example:',
          '{"action":"conclude","verdict":"not-reproduced","reasoning":"fair assertion did not hold after N runs","blocker":null}',
        ].join(' ')
      : [
          'exitCode is non-zero. Either the defect is absent or the script is wrong.',
          'Fix the script with another execute once, or conclude not-reproduced if the test was already fair.',
        ].join(' ');

  userMessage = [
    'Sandbox result for your last execute action:',
    wrapUntrusted(JSON.stringify({
      filename,
      runCommand,
      exitCode: sandboxResult.exitCode,
      timedOut: sandboxResult.timedOut,
      stdout: (sandboxResult.stdout || '').slice(0, 8000),
      stderr: (sandboxResult.stderr || '').slice(0, 4000),
      error: sandboxResult.error || null,
      network: 'none',
      sameFailStreak,
    }, null, 2)),
    '',
    'Your script that just ran was:',
    wrapUntrusted(script.slice(0, 8000)),
    '',
    decisiveHint,
    'Empty stdout is fine for assertion-only scripts.',
    'Reply with exactly one JSON object, no markdown fences.',
    `Turns remaining after this one: ${maxTurns - turn}.`,
  ].join('\n');
}

// Turn cap exhausted without conclude.
finalize({
  verdict: 'inconclusive',
  reasoning: `inconclusive — did not converge within ${maxTurns} turns`,
  blocker: `turn cap (${maxTurns}) reached without a conclude action`,
  turns,
  hitTurnCap: true,
  hitWallClock: false,
});
