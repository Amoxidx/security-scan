/**
 * Model providers, shared by the lens harness and the triage stage.
 *
 * Three types, mixable per stage (see config.json):
 *   cli        a subscription coding agent in headless mode (kimi -p, claude -p). No API
 *              key, no per-token billing.
 *   anthropic  /v1/messages, including Moonshot's Anthropic-compatible adapter.
 *   openai     /chat/completions, including OpenCode Zen.
 *
 * A provider that cannot be reached is reported and skipped, never fatal — the caller
 * decides whether losing that stage is acceptable.
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, appendFileSync } from 'node:fs';

/** Env vars named by any provider's apiKeyEnv, cleared so child processes cannot inherit them. */
export function scrubbedEnv(config, base = process.env, extra = {}) {
  const env = { ...base, ...extra };
  for (const p of Object.values(config.providers || {})) {
    if (p.apiKeyEnv) env[p.apiKeyEnv] = '';
  }
  return env;
}

// ---------------------------------------------------------------- resolution

/** 'provider:model' -> {providerName, model}; a bare id uses defaultProvider. */
export function splitSpec(config, spec) {
  const i = spec.indexOf(':');
  if (i === -1) return { providerName: config.defaultProvider, model: spec };
  return { providerName: spec.slice(0, i), model: spec.slice(i + 1) };
}

/**
 * Resolve the argv for a CLI provider.
 * On Studio, claude-cli often needs security/studio/claude-via-gui.sh so SSH can
 * reach the GUI-login keychain — set SECURITY_CLAUDE_WRAPPER to that absolute path.
 */
export function resolveCliCommand(provider, providerName) {
  const cmd = Array.isArray(provider?.command) ? [...provider.command] : [];
  if (providerName === 'claude-cli') {
    const wrap = process.env.SECURITY_CLAUDE_WRAPPER;
    if (wrap && existsSync(wrap)) {
      // Keep flags after the binary (usually '-p'); replace only argv[0].
      if (cmd.length === 0) return [wrap, '-p'];
      return [wrap, ...cmd.slice(1)];
    }
  }
  return cmd;
}

function cliBinaryExists(bin) {
  if (!bin) return false;
  if (bin.includes('/') || bin.startsWith('.')) return existsSync(bin);
  // Pass bin as $1 so a name with shell metacharacters cannot inject into -c.
  return spawnSync('sh', ['-c', 'command -v "$1"', 'sh', bin], { encoding: 'utf8' }).status === 0;
}

const availability = new Map();

// ---------------------------------------------------------------- usage log (observation only; never changes the complete() string contract)

const usageLog = [];

function isBilled(target) {
  return target.provider?.billed === true;
}

function recordUsage(entry) {
  usageLog.push(entry);
  const path = process.env.SECURITY_USAGE_LOG_FILE;
  if (!path) return;
  try {
    appendFileSync(path, `${JSON.stringify(entry)}\n`);
  } catch {
    // Observation only — a missing/unwritable file must not fail the scan.
  }
}

/** Copy of recorded model-call usage. Callers must not mutate the internal log. */
export function getUsageLog() {
  return usageLog.map((e) => ({ ...e }));
}

/** Clear recorded usage. Tests and each check-pr.mjs process start empty. */
export function resetUsageLog() {
  usageLog.length = 0;
}

function cliUsageFromParsed(target, parsed) {
  return {
    ts: new Date().toISOString(),
    providerName: target.providerName,
    model: target.model,
    kind: 'cli',
    inputTokens: parsed.usage?.input_tokens ?? null,
    outputTokens: parsed.usage?.output_tokens ?? null,
    cacheReadTokens: parsed.usage?.cache_read_input_tokens ?? null,
    cacheCreationTokens: parsed.usage?.cache_creation_input_tokens ?? null,
    costUsd: parsed.total_cost_usd ?? null,
    billed: isBilled(target),
  };
}

/** Token usage from an HTTP response. Field names follow the schema selected by isAnthropic. */
function httpUsageFromJson(target, json, isAnthropic) {
  const usage = json?.usage || {};
  return {
    ts: new Date().toISOString(),
    providerName: target.providerName,
    model: target.model,
    kind: 'http',
    inputTokens: isAnthropic ? (usage.input_tokens ?? null) : (usage.prompt_tokens ?? null),
    outputTokens: isAnthropic ? (usage.output_tokens ?? null) : (usage.completion_tokens ?? null),
    cacheReadTokens: usage.cache_read_input_tokens ?? null,
    cacheCreationTokens: usage.cache_creation_input_tokens ?? null,
    costUsd: null,
    billed: isBilled(target),
  };
}

function cliParseErrorEntry(target) {
  return {
    ts: new Date().toISOString(),
    providerName: target.providerName,
    model: target.model,
    kind: 'cli',
    parseError: true,
  };
}

/** Parse CLI JSON stdout. On parse failure or missing `result`, log parseError. Always return a string. */
function takeCliResult(target, out) {
  let parsed;
  try {
    parsed = JSON.parse(out);
  } catch {
    recordUsage(cliParseErrorEntry(target));
    return out;
  }
  if (parsed.result === undefined) {
    recordUsage(cliParseErrorEntry(target));
  } else {
    recordUsage(cliUsageFromParsed(target, parsed));
  }
  return parsed.result ?? '';
}

/** Why a provider cannot be used, or null when it can. */
export function unavailableReason(config, name) {
  if (availability.has(name)) return availability.get(name);
  const p = config.providers[name];
  let reason = null;
  if (!p) {
    reason = `no provider named '${name}' in config`;
  } else if (p.type === 'cli') {
    const cmd = resolveCliCommand(p, name);
    const bin = cmd[0];
    if (!cliBinaryExists(bin)) {
      reason = `'${bin}' not on PATH`;
    }
  } else if (!process.env[p.apiKeyEnv]) {
    reason = `${p.apiKeyEnv} not set`;
  }
  availability.set(name, reason);
  return reason;
}

/** A usable target, or null. Callers drop null targets rather than failing the run. */
export function resolveModel(config, spec) {
  if (!spec) return null;
  const { providerName, model } = splitSpec(config, spec);
  if (unavailableReason(config, providerName)) return null;
  return { providerName, model, provider: config.providers[providerName], spec };
}

/** Human-readable lines for every spec that cannot be used. */
export function listUnavailable(config, specs) {
  return [...new Set(specs)]
    .filter((s) => s && !resolveModel(config, s))
    .map((s) => `unavailable: ${s} (${unavailableReason(config, splitSpec(config, s).providerName)})`);
}

// ---------------------------------------------------------------- concurrency

// Subscription tiers cap in-flight requests (Kimi Code allows ~30), and CLI providers spawn
// a process per call. Fan-out without a limiter trades findings for rate-limit errors.
let inFlight = 0;
const waiting = [];

async function withSlot(limit, fn) {
  if (inFlight >= limit) await new Promise((r) => waiting.push(r));
  inFlight += 1;
  try {
    return await fn();
  } finally {
    inFlight -= 1;
    waiting.shift()?.();
  }
}

// ---------------------------------------------------------------- transports

/** ARG_MAX from the OS; argv+env together cannot exceed this. Cached. */
let cachedArgMax = null;
function osArgMax() {
  if (cachedArgMax != null) return cachedArgMax;
  const r = spawnSync('getconf', ['ARG_MAX'], { encoding: 'utf8' });
  const n = Number((r.stdout || '').trim());
  cachedArgMax = Number.isFinite(n) && n > 0 ? n : 262144;
  return cachedArgMax;
}

/**
 * Put `prompt` immediately after the prompt flag (`-p` / `--prompt`).
 * Kimi 0.36.0 requires `-p <prompt>` as a value; a bare `-p` swallows `--model`.
 */
function insertPromptArg(argv, prompt, promptFlag = '-p') {
  const idx = argv.findIndex((a) => a === promptFlag || a === '--prompt' || a === '-p');
  if (idx >= 0) argv.splice(idx + 1, 0, prompt);
  else argv.push(promptFlag, prompt);
}

function assertPromptFitsArgv(bin, argv, prompt) {
  const argMax = osArgMax();
  const envBytes = Object.entries(process.env).reduce(
    (n, [k, v]) => n + Buffer.byteLength(k) + Buffer.byteLength(String(v ?? '')) + 2,
    0,
  );
  const argvBytes = [bin, ...argv, prompt].reduce(
    (n, a) => n + Buffer.byteLength(String(a)) + 8,
    0,
  );
  const used = envBytes + argvBytes;
  if (used > argMax) {
    throw new Error(
      `${bin} promptArg: prompt is ${Buffer.byteLength(prompt)} bytes; ` +
        `argv+env ${used} exceeds ARG_MAX ${argMax}. ` +
        'Refusing to truncate a security prompt.',
    );
  }
}

/** A subscription coding agent in headless mode. */
function callCli(config, target, system, user, temperature) {
  const { provider, model, providerName } = target;
  const full = resolveCliCommand(provider, providerName);
  const bin = full[0];
  const argv = full.slice(1);
  const prompt = `${system}\n\n---\n\n${user}`;
  const promptArg = provider.promptArg === true;

  // A headless agent CLI has no sampling flag we may set, so a caller-requested
  // temperature is dropped here. Saying so keeps a run from looking deterministic when it is not.
  if (temperature !== undefined && temperature !== 0.2) {
    console.error(
      `[providers] ${providerName}: temperature ${temperature} is ignored for CLI targets — ` +
        `${bin} has no sampling flag, output is not deterministic`,
    );
  }

  if (promptArg) {
    assertPromptFitsArgv(bin, argv, prompt);
    insertPromptArg(argv, prompt, provider.promptFlag || '-p');
  }
  if (provider.jsonOutput === true) argv.push('--output-format', 'json');
  if (provider.modelFlag) argv.push(provider.modelFlag, model);

  return new Promise((resolve_, reject) => {
    const child = spawn(bin, argv, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // The agent must not inherit the gate's own model credentials.
      env: scrubbedEnv(config),
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`${bin} timed out`));
    }, provider.timeoutMs || 300000);

    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${bin} exited ${code}: ${err.slice(0, 300)}`));
      else if (provider.jsonOutput === true) resolve_(takeCliResult(target, out));
      else resolve_(out);
    });

    // promptArg: Kimi takes the prompt as -p's value. Leave stdin empty.
    // Everyone else (claude -p, codex exec) still reads stdin.
    if (promptArg) child.stdin.end();
    else child.stdin.end(prompt);
  });
}

async function callHttp(target, system, user, temperature = 0.2) {
  const { provider, model } = target;
  const key = process.env[provider.apiKeyEnv];
  const anthropic = provider.type === 'anthropic';

  const url = anthropic ? `${provider.baseUrl}/v1/messages` : `${provider.baseUrl}/chat/completions`;
  const headers = anthropic
    ? { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }
    : { 'content-type': 'application/json', authorization: `Bearer ${key}` };
  const body = anthropic
    ? { model, max_tokens: 8000, temperature, system, messages: [{ role: 'user', content: user }] }
    : {
        model,
        max_tokens: 8000,
        temperature,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      };

  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  if (res.status === 429 || res.status >= 500) throw new Error(`http ${res.status}`);
  if (!res.ok) throw new Error(`http ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const json = await res.json();
  recordUsage(httpUsageFromJson(target, json, anthropic));
  return anthropic
    ? (json.content ?? []).map((b) => b.text || '').join('')
    : json.choices?.[0]?.message?.content ?? '';
}

// ---------------------------------------------------------------- entry point

export async function complete(config, target, system, user, { retries = 3, temperature } = {}) {
  const limit = config.maxConcurrency || 6;
  return withSlot(limit, async () => {
    for (let attempt = 0; attempt < retries; attempt += 1) {
      try {
        return target.provider.type === 'cli'
          ? await callCli(config, target, system, user, temperature)
          : await callHttp(target, system, user, temperature);
      } catch (err) {
        if (attempt === retries - 1) throw err;
        await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
      }
    }
    return '';
  });
}
