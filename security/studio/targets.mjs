/**
 * Target profiles for Studio checks.
 *
 * A target is a named codebase (repo + local paths + host allow extras).
 * Modes (pr / local / tree) are orthogonal: same target, different scope.
 */

import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PATH = join(HERE, 'targets.json');

/** Expand ~ and $HOME in a path string. */
export function expandPath(p) {
  if (!p) return p;
  let s = String(p);
  if (s.startsWith('~/') || s === '~') {
    s = join(homedir(), s.slice(1).replace(/^\//, '') || '');
  }
  s = s.replace(/\$HOME\b/g, homedir());
  s = s.replace(/\$\{HOME\}/g, homedir());
  return resolve(s);
}

export function loadTargetsRegistry(path = DEFAULT_PATH) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (!raw.targets || typeof raw.targets !== 'object') {
    throw new Error(`targets file missing .targets map: ${path}`);
  }
  return raw;
}

/** Return target object with id filled in, or null. */
export function getTarget(registry, id) {
  if (!id) return null;
  const t = registry.targets[id];
  if (!t) return null;
  return { id, ...t };
}

/** List {id, label, repo} for CLI --list-targets. */
export function listTargets(registry) {
  return Object.entries(registry.targets).map(([id, t]) => ({
    id,
    label: t.label || id,
    repo: t.repo || null,
    primary: Boolean(t.primary),
    defaultBase: t.defaultBase || 'master',
  }));
}

/**
 * First existing local git checkout for this target, or null.
 * Explicit --repo-dir / --dir always wins (caller passes it as override).
 */
export function resolveLocalPath(target, overrideDir) {
  if (overrideDir) {
    const p = expandPath(overrideDir);
    if (!existsSync(p)) throw new Error(`path does not exist: ${p}`);
    return p;
  }
  if (!target) return null;
  for (const cand of target.localPaths || []) {
    const p = expandPath(cand);
    if (existsSync(join(p, '.git')) || existsSync(p)) {
      if (existsSync(join(p, '.git')) || existsSync(join(p, 'package.json'))) {
        return p;
      }
    }
  }
  return null;
}

/**
 * Infer target id from a github owner/name or a local path remote.
 * Falls back to defaultTarget, then "generic".
 */
export function inferTargetId(registry, { repo = null, dir = null } = {}) {
  if (repo) {
    const want = String(repo).toLowerCase();
    for (const [id, t] of Object.entries(registry.targets)) {
      if (t.repo && String(t.repo).toLowerCase() === want) return id;
    }
  }
  if (dir) {
    const abs = expandPath(dir);
    for (const [id, t] of Object.entries(registry.targets)) {
      for (const cand of t.localPaths || []) {
        if (expandPath(cand) === abs) return id;
      }
    }
  }
  return registry.defaultTarget || 'generic';
}

/**
 * Build SECURITY_HOST_ALLOW_EXTRA value (pipe-separated regex fragments).
 * Merges target.hostAllowExtra with any CLI extras.
 */
export function hostAllowExtraEnv(target, cliExtra = []) {
  const parts = [];
  for (const h of target?.hostAllowExtra || []) {
    if (h && String(h).trim()) parts.push(String(h).trim());
  }
  for (const h of cliExtra) {
    if (h && String(h).trim()) parts.push(String(h).trim());
  }
  // De-dupe, preserve order
  return [...new Set(parts)].join('|');
}

/**
 * Resolve default base ref for a target, with CLI override.
 * Accepts bare branch names ("develop") or full refs ("origin/develop").
 */
export function resolveBase(target, cliBase, { mode } = {}) {
  if (cliBase) return normalizeBase(cliBase);
  if (mode === 'tree') return null; // tree uses empty-tree..HEAD
  const b = target?.defaultBase || 'master';
  return normalizeBase(b);
}

function normalizeBase(b) {
  const s = String(b);
  if (s.startsWith('origin/') || s.startsWith('refs/')) return s;
  // Bare branch → origin/<branch> for three-dot diffs against remote tracking.
  if (!s.includes('/')) return `origin/${s}`;
  return s;
}

/** Empty git tree SHA — diff empty..HEAD = full tree as "added". */
export const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
