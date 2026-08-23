/**
 * Lab model selection for Studio (Ollama / Qwen).
 * Shared by check-pr.mjs and unit tests — never starts a pipeline.
 */

import { spawnSync } from 'node:child_process';

export const DEFAULT_LAB_MODEL = 'ollama:jk-coder';
export const OLLAMA_TAGS_URL = 'http://127.0.0.1:11434/api/tags';

/** List local Ollama model names via the tags API (sync, best-effort). */
export function listOllamaModels({ url = OLLAMA_TAGS_URL } = {}) {
  const r = spawnSync(
    'curl',
    ['-sf', '--max-time', '3', url],
    { encoding: 'utf8' },
  );
  if (r.status !== 0 || !r.stdout) return [];
  try {
    const json = JSON.parse(r.stdout);
    return (json.models || []).map((m) => m.name).filter(Boolean);
  } catch {
    return [];
  }
}

function modelPart(spec) {
  const s = String(spec);
  if (s.startsWith('ollama:')) return s.slice('ollama:'.length);
  const i = s.indexOf(':');
  if (i === -1) return s;
  // provider:model — keep everything after first colon (model tags contain colons)
  return s.slice(i + 1);
}

function toOllamaSpec(nameOrSpec) {
  const s = String(nameOrSpec);
  if (s.startsWith('ollama:')) return s;
  return `ollama:${s}`;
}

/**
 * Pick the lab model spec (provider:model).
 * Explicit --lab-model wins. Otherwise config.lab.model if present on Ollama,
 * else first preferredModels hit, else any qwen3-coder-next, else the config default.
 *
 * @param {object} config redteam config (uses config.lab)
 * @param {string|null} explicitSpec CLI override
 * @param {{ available?: string[] }} [opts] inject available models for tests
 */
export function resolveLabModelSpec(config, explicitSpec = null, opts = {}) {
  if (explicitSpec) return explicitSpec;
  const lab = config?.lab || {};
  const configured = lab.model || DEFAULT_LAB_MODEL;
  const preferred = Array.isArray(lab.preferredModels) && lab.preferredModels.length
    ? lab.preferredModels
    : [
      'qwen3-coder-next:q4_K_M',
      'frob/qwen3-coder-next:80b-a3b-q5_K_M',
      'qwen3-coder-next',
    ];

  const available = Array.isArray(opts.available)
    ? opts.available
    : listOllamaModels();

  if (!available.length) return configured;

  const has = (name) => available.some(
    (n) => n === name || n.startsWith(`${name}:`) || name.startsWith(`${n}:`),
  );

  const configuredName = modelPart(configured);
  if (available.includes(configuredName) || has(configuredName)) {
    return toOllamaSpec(configuredName);
  }

  for (const p of preferred) {
    const hit = available.find((n) => n === p || n.startsWith(`${p}:`));
    if (hit) return toOllamaSpec(hit);
  }
  const any = available.find((n) => n.includes('qwen3-coder-next'));
  if (any) return toOllamaSpec(any);
  return configured;
}
