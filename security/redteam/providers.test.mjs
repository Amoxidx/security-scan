#!/usr/bin/env node
/**
 * Unit checks for complete() usage logging in providers.mjs.
 * Fake CLI binaries + mocked fetch; no live models or network.
 *
 * Exit: 0 all passed, 1 one or more failed.
 */
import { writeFileSync, chmodSync, readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROVIDERS = join(HERE, 'providers.mjs');
const CONFIG = join(HERE, 'config.json');

const CLAUDE_JSON = {
  is_error: false,
  total_cost_usd: 0.0764,
  usage: {
    input_tokens: 9,
    cache_creation_input_tokens: 36638,
    cache_read_input_tokens: 18100,
    output_tokens: 140,
  },
  modelUsage: {
    'claude-haiku-4-5-20251001': {
      inputTokens: 532,
      outputTokens: 153,
      cacheReadInputTokens: 18100,
      cacheCreationInputTokens: 36638,
      costUSD: 0.0764,
    },
  },
  result: 'Hey Joshua, hi!',
  type: 'result',
};

const work = mkdtempSync(join(tmpdir(), 'providers-usage.'));
const m = await import(pathToFileURL(PROVIDERS).href);

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

{
  const cfg = JSON.parse(readFileSync(CONFIG, 'utf8'));
  const leaked = Object.entries(cfg.providers)
    .filter(([name, p]) => name !== 'claude-cli' && p.jsonOutput);
  check(
    'config jsonOutput only on claude-cli',
    cfg.providers['claude-cli']?.jsonOutput === true && leaked.length === 0,
    leaked.length ? `leaked=${leaked.map(([n]) => n).join(',')}` : '',
  );
  const billed = Object.entries(cfg.providers)
    .filter(([, p]) => p.billed === true)
    .map(([name]) => name)
    .sort();
  check(
    'config billed only on moonshot/anthropic/zen',
    billed.join(',') === 'anthropic,moonshot,zen' && cfg.providers.ollama?.billed !== true,
    billed.join(','),
  );
  check(
    'config ollama baseUrl is canonical IPv4 loopback',
    cfg.providers.ollama?.baseUrl === 'http://127.0.0.1:11434/v1'
      && cfg.providers.ollama?.baseUrl !== 'http://localhost:11434/v1',
    cfg.providers.ollama?.baseUrl,
  );
  const promptArgNames = Object.entries(cfg.providers)
    .filter(([, p]) => p.promptArg === true)
    .map(([name]) => name);
  check(
    'config promptArg only on kimi-cli',
    promptArgNames.length === 1 && promptArgNames[0] === 'kimi-cli'
      && cfg.providers['claude-cli']?.promptArg !== true
      && cfg.providers['codex-cli']?.promptArg !== true,
    promptArgNames.join(','),
  );
  const huntModels = Object.values(cfg.hunt?.models || {});
  const verifyModels = Array.isArray(cfg.verify?.models) ? cfg.verify.models : [];
  const kimiStage = [...huntModels, ...verifyModels]
    .filter((s) => String(s).startsWith('kimi-cli:'));
  check(
    'hunt/verify kimi alias is kimi-cli:kimi-code/k3',
    kimiStage.length > 0
      && kimiStage.every((s) => s === 'kimi-cli:kimi-code/k3')
      && !JSON.stringify({ hunt: cfg.hunt, verify: cfg.verify }).includes('kimi-cli:kimi-k3'),
    JSON.stringify({ hunt: huntModels, verify: verifyModels, kimiStage }),
  );
}

const jsonBin = join(work, 'fake-claude-json.sh');
const argsJson = join(work, 'fake-claude-json.args');
writeFileSync(
  jsonBin,
  `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsJson}"\ncat <<'JSON'\n${JSON.stringify(CLAUDE_JSON)}\nJSON\n`,
);
chmodSync(jsonBin, 0o755);

const badBin = join(work, 'fake-claude-bad.sh');
writeFileSync(badBin, '#!/bin/sh\nprintf \'not-json{{{\'\n');
chmodSync(badBin, 0o755);

const CLAUDE_JSON_NO_RESULT = { ...CLAUDE_JSON };
delete CLAUDE_JSON_NO_RESULT.result;
const noResultBin = join(work, 'fake-claude-no-result.sh');
writeFileSync(
  noResultBin,
  `#!/bin/sh\ncat <<'JSON'\n${JSON.stringify(CLAUDE_JSON_NO_RESULT)}\nJSON\n`,
);
chmodSync(noResultBin, 0o755);

const emptyResultBin = join(work, 'fake-claude-empty-result.sh');
writeFileSync(
  emptyResultBin,
  `#!/bin/sh\ncat <<'JSON'\n${JSON.stringify({ ...CLAUDE_JSON, result: '' })}\nJSON\n`,
);
chmodSync(emptyResultBin, 0o755);

const plainBin = join(work, 'fake-kimi-plain.sh');
const argsPlain = join(work, 'fake-kimi-plain.args');
writeFileSync(
  plainBin,
  `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsPlain}"\nprintf 'plain-kimi-out\\n'\n`,
);
chmodSync(plainBin, 0o755);

{
  m.resetUsageLog();
  const got = await m.complete(
    { maxConcurrency: 1, providers: {} },
    {
      providerName: 'claude-cli',
      model: 'claude-opus-5',
      provider: {
        type: 'cli',
        command: [jsonBin, '-p'],
        modelFlag: '--model',
        jsonOutput: true,
        timeoutMs: 8000,
      },
      spec: 'claude-cli:claude-opus-5',
    },
    'sys',
    'user',
  );
  const log1 = m.getUsageLog();
  const e = log1[0] || {};
  const argvJson = readFileSync(argsJson, 'utf8').trim().split('\n');
  check(
    'jsonOutput returns only result string',
    got === 'Hey Joshua, hi!',
    `got=${JSON.stringify(got)}`,
  );
  check(
    'jsonOutput logs one usage entry with token fields',
    log1.length === 1
      && e.providerName === 'claude-cli'
      && e.model === 'claude-opus-5'
      && e.kind === 'cli'
      && e.inputTokens === 9
      && e.outputTokens === 140
      && e.cacheReadTokens === 18100
      && e.cacheCreationTokens === 36638
      && e.costUsd === 0.0764
      && e.billed === false
      && !e.parseError,
    JSON.stringify(e),
  );
  check(
    'jsonOutput passes --output-format json',
    argvJson.includes('--output-format') && argvJson.includes('json'),
    argvJson.join(' '),
  );
  log1.push({ injected: true });
  check(
    'getUsageLog returns a copy',
    !m.getUsageLog().some((x) => x.injected),
  );
}

{
  m.resetUsageLog();
  let threw = false;
  let raw;
  try {
    raw = await m.complete(
      { maxConcurrency: 1, providers: {} },
      {
        providerName: 'claude-cli',
        model: 'claude-opus-5',
        provider: { type: 'cli', command: [badBin, '-p'], jsonOutput: true, timeoutMs: 8000 },
        spec: 'claude-cli:claude-opus-5',
      },
      'sys',
      'user',
    );
  } catch (err) {
    threw = true;
    raw = err.message;
  }
  const log2 = m.getUsageLog();
  check(
    'bad json does not throw and returns raw stdout',
    !threw && raw === 'not-json{{{',
    `threw=${threw} raw=${JSON.stringify(raw)}`,
  );
  check(
    'bad json logs parseError without usage fields',
    log2.length === 1
      && log2[0].parseError === true
      && !('inputTokens' in log2[0])
      && !('outputTokens' in log2[0])
      && !('costUsd' in log2[0]),
    JSON.stringify(log2[0]),
  );
}

{
  m.resetUsageLog();
  let threw = false;
  let raw;
  try {
    raw = await m.complete(
      { maxConcurrency: 1, providers: {} },
      {
        providerName: 'claude-cli',
        model: 'claude-opus-5',
        provider: { type: 'cli', command: [noResultBin, '-p'], jsonOutput: true, timeoutMs: 8000 },
        spec: 'claude-cli:claude-opus-5',
      },
      'sys',
      'user',
    );
  } catch (err) {
    threw = true;
    raw = err.message;
  }
  const logMissing = m.getUsageLog();
  check(
    'json without result returns empty string without throwing',
    !threw && raw === '',
    `threw=${threw} raw=${JSON.stringify(raw)}`,
  );
  check(
    'json without result logs parseError without usage fields',
    logMissing.length === 1
      && logMissing[0].parseError === true
      && !('inputTokens' in logMissing[0])
      && !('outputTokens' in logMissing[0])
      && !('costUsd' in logMissing[0]),
    JSON.stringify(logMissing[0]),
  );
}

{
  m.resetUsageLog();
  const empty = await m.complete(
    { maxConcurrency: 1, providers: {} },
    {
      providerName: 'claude-cli',
      model: 'claude-opus-5',
      provider: { type: 'cli', command: [emptyResultBin, '-p'], jsonOutput: true, timeoutMs: 8000 },
      spec: 'claude-cli:claude-opus-5',
    },
    'sys',
    'user',
  );
  const logEmpty = m.getUsageLog();
  const ee = logEmpty[0] || {};
  check(
    'json with empty result string is a legitimate answer',
    empty === ''
      && logEmpty.length === 1
      && !ee.parseError
      && ee.inputTokens === 9
      && ee.outputTokens === 140
      && ee.costUsd === 0.0764,
    JSON.stringify({ empty, ee }),
  );
}

{
  m.resetUsageLog();
  const plain = await m.complete(
    { maxConcurrency: 1, providers: {} },
    {
      providerName: 'kimi-cli',
      model: 'kimi-code/k3',
      provider: {
        type: 'cli',
        command: [plainBin, '-p'],
        modelFlag: '--model',
        timeoutMs: 8000,
      },
      spec: 'kimi-cli:kimi-code/k3',
    },
    'sys',
    'user',
  );
  const argvPlain = readFileSync(argsPlain, 'utf8');
  check(
    'without jsonOutput returns raw stdout and logs nothing',
    plain === 'plain-kimi-out\n'
      && m.getUsageLog().length === 0
      && !argvPlain.includes('--output-format'),
    `out=${JSON.stringify(plain)} log=${m.getUsageLog().length} argv=${argvPlain.trim()}`,
  );
}

{
  async function httpComplete(providerExtra) {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      status: 200,
      ok: true,
      json: async () => ({
        content: [{ text: 'http-result' }],
        usage: { input_tokens: 11, output_tokens: 22, cache_read_input_tokens: 3 },
      }),
    });
    process.env.USAGE_HTTP_KEY = 'x';
    try {
      return await m.complete(
        { maxConcurrency: 1, providers: {} },
        {
          providerName: 'moonshot',
          model: 'kimi-k2',
          provider: {
            type: 'anthropic',
            baseUrl: 'http://127.0.0.1:9',
            apiKeyEnv: 'USAGE_HTTP_KEY',
            ...providerExtra,
          },
          spec: 'moonshot:kimi-k2',
        },
        'sys',
        'user',
      );
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  m.resetUsageLog();
  const httpBilled = await httpComplete({ billed: true });
  const hb = m.getUsageLog()[0] || {};
  check(
    'http with billed:true logs billed tokens without costUsd',
    httpBilled === 'http-result'
      && m.getUsageLog().length === 1
      && hb.kind === 'http'
      && hb.billed === true
      && hb.inputTokens === 11
      && hb.outputTokens === 22
      && hb.cacheReadTokens === 3
      && hb.costUsd === null,
    JSON.stringify({ httpBilled, hb }),
  );

  m.resetUsageLog();
  const httpFree = await httpComplete({});
  const hf = m.getUsageLog()[0] || {};
  check(
    'http without billed flag logs billed:false',
    httpFree === 'http-result' && hf.billed === false,
    JSON.stringify(hf),
  );
}

{
  async function httpCompleteOpenAi(json) {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      status: 200,
      ok: true,
      json: async () => json,
    });
    process.env.USAGE_HTTP_KEY = 'x';
    try {
      return await m.complete(
        { maxConcurrency: 1, providers: {} },
        {
          providerName: 'zen',
          model: 'gpt-x',
          provider: {
            type: 'openai',
            baseUrl: 'http://127.0.0.1:9',
            apiKeyEnv: 'USAGE_HTTP_KEY',
            billed: true,
          },
          spec: 'zen:gpt-x',
        },
        'sys',
        'user',
      );
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  m.resetUsageLog();
  const openaiGot = await httpCompleteOpenAi({
    choices: [{ message: { content: 'openai-result' } }],
    usage: {
      input_tokens: 99,
      output_tokens: 88,
      prompt_tokens: 5,
      completion_tokens: 7,
    },
  });
  const oa = m.getUsageLog()[0] || {};
  check(
    'openai http reads prompt_tokens not a decoy input_tokens',
    openaiGot === 'openai-result'
      && m.getUsageLog().length === 1
      && oa.kind === 'http'
      && oa.inputTokens === 5
      && oa.outputTokens === 7
      && oa.inputTokens !== 99
      && oa.outputTokens !== 88,
    JSON.stringify({ openaiGot, oa }),
  );

  m.resetUsageLog();
  const decoyOnly = await httpCompleteOpenAi({
    choices: [{ message: { content: 'openai-decoy' } }],
    usage: { input_tokens: 99 },
  });
  const od = m.getUsageLog()[0] || {};
  check(
    'openai http ignores a lone anthropic input_tokens field',
    decoyOnly === 'openai-decoy'
      && m.getUsageLog().length === 1
      && od.inputTokens === null
      && od.outputTokens === null,
    JSON.stringify({ decoyOnly, od }),
  );
}

{
  m.resetUsageLog();
  const logFile = join(work, 'usage.jsonl');
  process.env.SECURITY_USAGE_LOG_FILE = logFile;
  try {
    await m.complete(
      { maxConcurrency: 1, providers: {} },
      {
        providerName: 'claude-cli',
        model: 'claude-opus-5',
        provider: {
          type: 'cli',
          command: [jsonBin, '-p'],
          modelFlag: '--model',
          jsonOutput: true,
          timeoutMs: 8000,
        },
        spec: 'claude-cli:claude-opus-5',
      },
      'sys',
      'user',
    );
    const raw = existsSync(logFile) ? readFileSync(logFile, 'utf8') : '';
    const lines = raw.split('\n').filter((l) => l.trim());
    let parsed = null;
    try { parsed = JSON.parse(lines[0] || ''); } catch { parsed = null; }
    check(
      'SECURITY_USAGE_LOG_FILE gets one jsonl line matching memory',
      lines.length === 1
        && parsed
        && parsed.inputTokens === 9
        && parsed.costUsd === 0.0764
        && parsed.billed === false
        && m.getUsageLog().length === 1,
      `lines=${lines.length} parsed=${JSON.stringify(parsed)}`,
    );
  } finally {
    delete process.env.SECURITY_USAGE_LOG_FILE;
  }
}

{
  m.resetUsageLog();
  process.env.SECURITY_USAGE_LOG_FILE = join(work, 'no-such-dir', 'usage.jsonl');
  let threw = false;
  try {
    await m.complete(
      { maxConcurrency: 1, providers: {} },
      {
        providerName: 'claude-cli',
        model: 'claude-opus-5',
        provider: {
          type: 'cli',
          command: [jsonBin, '-p'],
          jsonOutput: true,
          timeoutMs: 8000,
        },
        spec: 'claude-cli:claude-opus-5',
      },
      'sys',
      'user',
    );
  } catch {
    threw = true;
  } finally {
    delete process.env.SECURITY_USAGE_LOG_FILE;
  }
  check(
    'unwritable SECURITY_USAGE_LOG_FILE does not throw',
    !threw && m.getUsageLog().length === 1,
    `threw=${threw} log=${m.getUsageLog().length}`,
  );
}

{
  const childLog = join(work, 'child-usage.jsonl');
  const childScript = join(work, 'child-complete.mjs');
  writeFileSync(
    childScript,
    `import { complete } from ${JSON.stringify(pathToFileURL(PROVIDERS).href)};
const got = await complete(
  { maxConcurrency: 1, providers: {} },
  {
    providerName: 'claude-cli',
    model: 'claude-opus-5',
    provider: {
      type: 'cli',
      command: [${JSON.stringify(jsonBin)}, '-p'],
      jsonOutput: true,
      timeoutMs: 8000,
    },
    spec: 'claude-cli:claude-opus-5',
  },
  'sys',
  'user',
);
if (got !== 'Hey Joshua, hi!') {
  console.error('child result', JSON.stringify(got));
  process.exit(2);
}
`,
  );
  m.resetUsageLog();
  const child = spawnSync(process.execPath, [childScript], {
    encoding: 'utf8',
    env: { ...process.env, SECURITY_USAGE_LOG_FILE: childLog },
  });
  const parentLog = m.getUsageLog();
  const raw = existsSync(childLog) ? readFileSync(childLog, 'utf8') : '';
  const lines = raw.split('\n').filter((l) => l.trim());
  let parsed = null;
  try { parsed = JSON.parse(lines[0] || ''); } catch { parsed = null; }
  check(
    'child process fills jsonl while parent memory stays empty',
    child.status === 0
      && parentLog.length === 0
      && lines.length === 1
      && parsed
      && parsed.inputTokens === 9
      && parsed.outputTokens === 140,
    `status=${child.status} stderr=${(child.stderr || '').slice(0, 200)} parent=${parentLog.length} lines=${lines.length}`,
  );
}

{
  const recBin = join(work, 'record-argv-stdin.mjs');
  const recArgs = join(work, 'record.args');
  const recStdin = join(work, 'record.stdin');
  writeFileSync(
    recBin,
    `#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(recArgs)}, JSON.stringify(process.argv.slice(2)));
const chunks = [];
for await (const c of process.stdin) chunks.push(c);
writeFileSync(${JSON.stringify(recStdin)}, Buffer.concat(chunks));
process.stdout.write('recorded\\n');
`,
  );
  chmodSync(recBin, 0o755);

  m.resetUsageLog();
  const promptArgOut = await m.complete(
    { maxConcurrency: 1, providers: {} },
    {
      providerName: 'kimi-cli',
      model: 'kimi-code/k3',
      provider: {
        type: 'cli',
        command: [recBin, '-p'],
        modelFlag: '--model',
        promptArg: true,
        timeoutMs: 8000,
      },
      spec: 'kimi-cli:kimi-code/k3',
    },
    'SYS-PROMPT',
    'USER-PROMPT',
  );
  const paArgv = JSON.parse(readFileSync(recArgs, 'utf8'));
  const paStdin = readFileSync(recStdin, 'utf8');
  const expectedPrompt = 'SYS-PROMPT\n\n---\n\nUSER-PROMPT';
  const pIdx = paArgv.indexOf('-p');
  const mIdx = paArgv.indexOf('--model');
  check(
    'promptArg puts prompt on argv after -p, before --model; stdin empty',
    promptArgOut === 'recorded\n'
      && pIdx >= 0
      && paArgv[pIdx + 1] === expectedPrompt
      && mIdx === pIdx + 2
      && paArgv[mIdx + 1] === 'kimi-code/k3'
      && paStdin === '',
    `argv=${JSON.stringify(paArgv)} stdin=${JSON.stringify(paStdin)} out=${JSON.stringify(promptArgOut)}`,
  );

  writeFileSync(recArgs, '');
  writeFileSync(recStdin, '');
  m.resetUsageLog();
  const stdinOut = await m.complete(
    { maxConcurrency: 1, providers: {} },
    {
      providerName: 'claude-cli',
      model: 'claude-opus-5',
      provider: {
        type: 'cli',
        command: [recBin, '-p'],
        modelFlag: '--model',
        timeoutMs: 8000,
      },
      spec: 'claude-cli:claude-opus-5',
    },
    'SYS-PROMPT',
    'USER-PROMPT',
  );
  const clArgv = JSON.parse(readFileSync(recArgs, 'utf8'));
  const clStdin = readFileSync(recStdin, 'utf8');
  check(
    'default CLI still sends prompt on stdin, not as -p value',
    stdinOut === 'recorded\n'
      && clArgv[0] === '-p'
      && clArgv[1] === '--model'
      && clArgv[2] === 'claude-opus-5'
      && !clArgv.includes(expectedPrompt)
      && clStdin === expectedPrompt,
    `argv=${JSON.stringify(clArgv)} stdin=${JSON.stringify(clStdin)}`,
  );

  let argMaxErr = '';
  try {
    const argMax = Number(spawnSync('getconf', ['ARG_MAX'], { encoding: 'utf8' }).stdout.trim());
    const huge = 'H'.repeat((Number.isFinite(argMax) ? argMax : 262144) + 4096);
    await m.complete(
      { maxConcurrency: 1, providers: {} },
      {
        providerName: 'kimi-cli',
        model: 'kimi-code/k3',
        provider: {
          type: 'cli',
          command: [recBin, '-p'],
          modelFlag: '--model',
          promptArg: true,
          timeoutMs: 8000,
        },
        spec: 'kimi-cli:kimi-code/k3',
      },
      'sys',
      huge,
      { retries: 1 },
    );
  } catch (err) {
    argMaxErr = err.message || String(err);
  }
  check(
    'promptArg over ARG_MAX fails loud without truncating',
    /ARG_MAX/.test(argMaxErr) && /Refusing to truncate/.test(argMaxErr),
    argMaxErr.slice(0, 240),
  );
}

{
  async function httpCaptureTemperature(temperature) {
    const origFetch = globalThis.fetch;
    let sentBody = null;
    globalThis.fetch = async (url, init) => {
      sentBody = JSON.parse(init.body);
      return {
        status: 200,
        ok: true,
        json: async () => ({
          content: [{ text: 'temp-result' }],
          usage: { input_tokens: 1, output_tokens: 2 },
        }),
      };
    };
    process.env.USAGE_HTTP_KEY = 'x';
    try {
      const opts = { retries: 1 };
      if (temperature !== undefined) opts.temperature = temperature;
      const out = await m.complete(
        { maxConcurrency: 1, providers: { moonshot: { type: 'anthropic' } } },
        {
          providerName: 'moonshot',
          model: 'kimi-k2',
          provider: {
            type: 'anthropic',
            baseUrl: 'http://127.0.0.1:9',
            apiKeyEnv: 'USAGE_HTTP_KEY',
          },
          spec: 'moonshot:kimi-k2',
        },
        'sys',
        'user',
        opts,
      );
      return { out, sentBody };
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  async function openAiCaptureTemperature(temperature) {
    const origFetch = globalThis.fetch;
    let sentBody = null;
    globalThis.fetch = async (url, init) => {
      sentBody = JSON.parse(init.body);
      return {
        status: 200,
        ok: true,
        json: async () => ({ choices: [{ message: { content: 'temp-result' } }] }),
      };
    };
    process.env.USAGE_HTTP_KEY = 'x';
    try {
      const opts = { retries: 1 };
      if (temperature !== undefined) opts.temperature = temperature;
      const out = await m.complete(
        { maxConcurrency: 1, providers: { zen: { type: 'openai' } } },
        {
          providerName: 'zen',
          model: 'gpt-x',
          provider: {
            type: 'openai',
            baseUrl: 'http://127.0.0.1:9',
            apiKeyEnv: 'USAGE_HTTP_KEY',
          },
          spec: 'zen:gpt-x',
        },
        'sys',
        'user',
        opts,
      );
      return { out, sentBody };
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  m.resetUsageLog();
  const tempDefault = await httpCaptureTemperature();
  check(
    'anthropic http body keeps temperature 0.2 without the option',
    tempDefault.out === 'temp-result' && tempDefault.sentBody?.temperature === 0.2,
    JSON.stringify(tempDefault.sentBody),
  );

  m.resetUsageLog();
  const tempZero = await httpCaptureTemperature(0);
  check(
    'anthropic http body carries temperature 0 from options',
    tempZero.out === 'temp-result' && tempZero.sentBody?.temperature === 0,
    JSON.stringify(tempZero.sentBody),
  );

  m.resetUsageLog();
  const tempCustom = await httpCaptureTemperature(0.7);
  check(
    'anthropic http body carries a custom temperature from options',
    tempCustom.sentBody?.temperature === 0.7,
    JSON.stringify(tempCustom.sentBody),
  );

  m.resetUsageLog();
  const oaTempDefault = await openAiCaptureTemperature();
  check(
    'chat_completions body keeps temperature 0.2 without the option',
    oaTempDefault.out === 'temp-result' && oaTempDefault.sentBody?.temperature === 0.2,
    JSON.stringify(oaTempDefault.sentBody),
  );

  m.resetUsageLog();
  const oaTempZero = await openAiCaptureTemperature(0);
  check(
    'chat_completions body carries temperature 0 from options',
    oaTempZero.out === 'temp-result' && oaTempZero.sentBody?.temperature === 0,
    JSON.stringify(oaTempZero.sentBody),
  );
}

{
  m.resetUsageLog();
  check('resetUsageLog clears the array', m.getUsageLog().length === 0);
}

rmSync(work, { recursive: true, force: true });

console.log(`${pass}/${pass + fail} providers usage cases`);
process.exit(fail === 0 ? 0 : 1);
