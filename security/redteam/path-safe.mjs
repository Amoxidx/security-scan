/**
 * Resolve a scanner/SARIF path strictly inside a repository root.
 *
 * Rejects absolute paths, URI schemes, null bytes, lexical escapes via '..',
 * and symlink targets that leave the repository (realpath re-check).
 * Callers must treat null as "do not read".
 */

import { resolve, isAbsolute, sep } from 'node:path';
import { existsSync, lstatSync, realpathSync } from 'node:fs';

function contained(root, path) {
  const prefix = root.endsWith(sep) ? root : root + sep;
  return path === root || path.startsWith(prefix);
}

/**
 * True when every existing ancestor of `path` (inclusive), after realpath, stays under realRoot.
 * Catches `src -> /etc` even when the final leaf does not exist yet.
 */
function ancestorsStayInside(realRoot, path) {
  let cur = path;
  for (;;) {
    try {
      if (existsSync(cur)) {
        // lstat first so we can detect a symlink even when its target is missing.
        const st = lstatSync(cur);
        if (st.isSymbolicLink() || st.isFile() || st.isDirectory()) {
          const real = realpathSync(cur);
          if (!contained(realRoot, real)) return false;
        }
      }
    } catch {
      return false;
    }
    if (cur === realRoot) break;
    const parent = resolve(cur, '..');
    if (parent === cur) break;
    // Stop once we leave the real root walk (should not happen if path started under root).
    if (!contained(realRoot, parent) && parent !== realRoot) break;
    cur = parent;
  }
  return true;
}

export function resolveRepoFile(repoRoot, file) {
  if (!file || typeof file !== 'string' || file.includes('\0')) return null;
  const trimmed = file.replace(/^file:\/\//, '').trim();
  if (!trimmed) return null;
  // Windows drive / UNC / POSIX absolute — never join an absolute second segment.
  if (isAbsolute(trimmed) || /^[A-Za-z]:[\\/]/.test(trimmed) || trimmed.startsWith('\\\\')) {
    return null;
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) return null; // scheme: …

  const root = resolve(repoRoot);
  let realRoot;
  try {
    realRoot = existsSync(root) ? realpathSync(root) : root;
  } catch {
    return null;
  }

  const candidate = resolve(root, trimmed);
  // Lexical containment against both the logical and real root.
  if (!contained(root, candidate) && !contained(realRoot, candidate)) return null;
  if (!contained(root, candidate)) return null;

  if (existsSync(candidate)) {
    try {
      const realFile = realpathSync(candidate);
      if (!contained(realRoot, realFile)) return null;
      // Return the real path so callers never open through a symlink that could race.
      return realFile;
    } catch {
      return null;
    }
  }

  // Leaf missing: still reject if a parent symlink points outside the repo.
  if (!ancestorsStayInside(realRoot, candidate)) return null;
  return candidate;
}
