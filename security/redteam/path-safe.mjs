/**
 * Resolve a scanner/SARIF path strictly inside a repository root.
 *
 * Rejects absolute paths, URI schemes, null bytes, and any escape via '..'.
 * Callers must treat null as "do not read".
 */

import { resolve, isAbsolute, sep } from 'node:path';

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
  const candidate = resolve(root, trimmed);
  const prefix = root.endsWith(sep) ? root : root + sep;
  if (candidate !== root && !candidate.startsWith(prefix)) return null;
  return candidate;
}
