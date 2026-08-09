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

const availability = new Map();

/** Why a provider cannot be used, or null when it can. */
export function unavailableReason(config, name) {
  if (availability.has(name)) return availability.get(name);
  const p = config.providers[name];
  let reason = null;
  if (!p) {
    reason = `no provider named '${name}' in config`;
  } else if (p.type === 'cli') {
    const bin = p.command[0];
    // Pass bin as $1 so a name with shell metacharacters cannot inject into -c.
    if (spawnSync('sh', ['-c', 'command -v "$1"', 'sh', bin], { encoding: 'utf8' }).status !== 0) {
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

/** A subscription coding agent in headless mode. Prompt on stdin, answer on stdout. */
function callCli(config, target, system, user) {
  const { provider, model } = target;
  const argv = [...provider.command.slice(1)];
  if (provider.modelFlag) argv.push(provider.modelFlag, model);

  return new Promise((resolve_, reject) => {
    const child = spawn(provider.command[0], argv, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // The agent must not inherit the gate's own model credentials.
      env: scrubbedEnv(config),
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`${provider.command[0]} timed out`));
    }, provider.timeoutMs || 300000);

    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${provider.command[0]} exited ${code}: ${err.slice(0, 300)}`));
      else resolve_(out);
    });

    child.stdin.end(`${system}\n\n---\n\n${user}`);
  });
}

async function callHttp(target, system, user) {
  const { provider, model } = target;
  const key = process.env[provider.apiKeyEnv];
  const anthropic = provider.type === 'anthropic';

  const url = anthropic ? `${provider.baseUrl}/v1/messages` : `${provider.baseUrl}/chat/completions`;
  const headers = anthropic
    ? { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }
    : { 'content-type': 'application/json', authorization: `Bearer ${key}` };
  const body = anthropic
    ? { model, max_tokens: 8000, temperature: 0.2, system, messages: [{ role: 'user', content: user }] }
    : {
        model,
        max_tokens: 8000,
        temperature: 0.2,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      };

  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  if (res.status === 429 || res.status >= 500) throw new Error(`http ${res.status}`);
  if (!res.ok) throw new Error(`http ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const json = await res.json();
  return anthropic
    ? (json.content ?? []).map((b) => b.text || '').join('')
    : json.choices?.[0]?.message?.content ?? '';
}

// ---------------------------------------------------------------- entry point

export async function complete(config, target, system, user, { retries = 3 } = {}) {
  const limit = config.maxConcurrency || 6;
  return withSlot(limit, async () => {
    for (let attempt = 0; attempt < retries; attempt += 1) {
      try {
        return target.provider.type === 'cli'
          ? await callCli(config, target, system, user)
          : await callHttp(target, system, user);
      } catch (err) {
        if (attempt === retries - 1) throw err;
        await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
      }
    }
    return '';
  });
}
