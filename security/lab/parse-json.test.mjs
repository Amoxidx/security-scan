#!/usr/bin/env node
/**
 * Unit checks for parseJson() from run.mjs.
 *
 * run.mjs is a CLI: importing it executes argv parsing and exits. These tests load
 * the exported parseJson source from run.mjs into a temporary module so the real
 * function body is exercised without Docker/Ollama or the CLI side effects.
 *
 * Exit: 0 all passed, 1 one or more failed.
 */

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUN_SRC = join(HERE, 'run.mjs');

function extractParseJsonSource(src) {
  const re = /export\s+function\s+parseJson\s*\(/;
  const m = re.exec(src);
  if (!m) {
    throw new Error('export function parseJson(...) not found in run.mjs');
  }
  const start = m.index;
  // Slice until the next top-level function in run.mjs. Brace-counting alone is
  // wrong here: parseJson contains the regex /[{[]/ whose `{` is not a block.
  const rest = src.slice(start);
  const nextFn = rest.search(/\nfunction\s+[A-Za-z_$]/);
  if (nextFn === -1) {
    throw new Error('could not locate end of parseJson (next function missing)');
  }
  return rest.slice(0, nextFn).trimEnd() + '\n';
}

const src = readFileSync(RUN_SRC, 'utf8');
const fnSrc = extractParseJsonSource(src);

const work = mkdtempSync(join(tmpdir(), 'lab-parse-json.'));
const modPath = join(work, 'parseJson.mjs');
writeFileSync(modPath, `${fnSrc}\n`);

const { parseJson } = await import(pathToFileURL(modPath).href);

let pass = 0;
let fail = 0;

function check(name, ok, detail = '') {
  if (ok) {
    pass += 1;
    console.log(`  PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// 1. clean JSON object
{
  const got = parseJson('{"action":"conclude","verdict":"reproduced"}');
  check(
    'parseJson: clean object',
    got && got.action === 'conclude' && got.verdict === 'reproduced',
    `got=${JSON.stringify(got)}`,
  );
}

// 2. fenced ```json block with prose before/after
{
  const text = [
    'Here is my decision:',
    '```json',
    '{',
    '  "action": "execute",',
    '  "filename": "probe.mjs",',
    '  "run_command": ["node", "probe.mjs"]',
    '}',
    '```',
    'That should work.',
  ].join('\n');
  const got = parseJson(text);
  check(
    'parseJson: fenced json with prose',
    got && got.action === 'execute' && got.filename === 'probe.mjs',
    `got=${JSON.stringify(got)}`,
  );
}

// 3. truncated trailing garbage after a complete object (balanced-brace scan)
{
  const text = '{"verdict":"inconclusive","reason":"cap"}{"partial":';
  const got = parseJson(text);
  check(
    'parseJson: first complete object from truncated stream',
    got && got.verdict === 'inconclusive' && got.reason === 'cap',
    `got=${JSON.stringify(got)}`,
  );
}

// 4. no JSON → fallback null
{
  const got = parseJson('sorry, I cannot produce JSON this turn', null);
  check('parseJson: no json returns fallback null', got === null, `got=${JSON.stringify(got)}`);
}

rmSync(work, { recursive: true, force: true });

console.log(`${pass}/${pass + fail} parseJson cases`);
process.exit(fail === 0 ? 0 : 1);
