#!/usr/bin/env node
/**
 * Runs one probe in its own process and prints the verdict as JSON on stdout.
 *
 * A separate process is not a nicety here: probes deliberately push code into failure states
 * — stack exhaustion, unhandled rejections — that would take the runner down with them.
 *
 * Called by run-probes.mjs; not meant to be invoked directly.
 */

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [probePath, caseDir] = process.argv.slice(2);

function emit(obj) {
  process.stdout.write(`\n__PROBE__${JSON.stringify(obj)}\n`);
  process.exit(0);
}

try {
  const probe = await import(pathToFileURL(resolve(probePath)).href);
  const fn = probe.default;
  if (typeof fn !== 'function') emit({ error: 'probe has no default export' });

  const importFrom = (rel) => import(pathToFileURL(resolve(caseDir, rel)).href);
  const result = await fn({ dir: resolve(caseDir), importFrom });

  emit({
    describes: probe.describes || '',
    present: Boolean(result?.present),
    evidence: String(result?.evidence ?? '').slice(0, 500),
  });
} catch (err) {
  emit({ error: `${err?.name || 'Error'}: ${String(err?.message).slice(0, 300)}` });
}
