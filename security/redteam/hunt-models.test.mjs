import assert from 'node:assert/strict';
import test from 'node:test';

import { completeHunt } from './hunt-models.mjs';

const primary = 'primary:model';
const fallback = 'fallback:model';
const config = {
  hunt: {
    models: { entropy: primary },
    fallbackModels: [primary, fallback],
  },
};
const parseJson = (text) => JSON.parse(text);
const resolveModel = (_config, spec) => ({ spec });
const finding = { file: 'src/app.mjs', line: 7, title: 'Example' };

async function run(outcomes) {
  const calls = [];
  const logs = [];
  const result = await completeHunt({
    config,
    lens: 'entropy',
    user: 'user',
    systemPrompt: 'system',
    resolveModel,
    parseJson,
    logError: (message) => logs.push(message),
    complete: async (_config, target) => {
      calls.push(target.spec);
      const outcome = outcomes[target.spec];
      if (outcome instanceof Error) throw outcome;
      return JSON.stringify({ findings: outcome });
    },
  });
  return { result, calls, logs };
}

test('hunt model fallback is visible, tagged, ordered, and fail-closed', async (t) => {
  await t.test('primary failure falls back and tags findings', async () => {
    const { result, calls, logs } = await run({
      [primary]: new Error('quota exhausted'),
      [fallback]: [finding],
    });
    assert.deepEqual(calls, [primary, fallback]);
    assert.deepEqual(result.findings, [{
      ...finding,
      lens: 'entropy',
      huntModel: fallback,
      usedFallback: true,
    }]);
    assert.equal(result.ok, true);
    assert.match(logs[0], /primary primary:model unavailable\/failed -> fell back to fallback:model/);
  });

  await t.test('primary success does not use fallback', async () => {
    const { result, calls, logs } = await run({ [primary]: [finding] });
    assert.deepEqual(calls, [primary]);
    assert.equal(result.findings[0].huntModel, primary);
    assert.equal(result.findings[0].usedFallback, false);
    assert.deepEqual(logs, []);
  });

  await t.test('all failures produce no findings', async () => {
    const { result, calls } = await run({
      [primary]: new Error('primary down'),
      [fallback]: new Error('fallback down'),
    });
    assert.deepEqual(calls, [primary, fallback]);
    assert.equal(result.ok, false);
    assert.deepEqual(result.findings, []);
    assert.match(result.error, /primary down/);
    assert.match(result.error, /fallback down/);
  });
});
