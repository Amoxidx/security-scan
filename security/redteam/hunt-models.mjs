/** Try a hunt lens's primary model, then its configured fallbacks, in order. */
export async function completeHunt({
  config,
  lens,
  user,
  systemPrompt,
  resolveModel,
  complete,
  parseJson,
  logError = console.error,
}) {
  const primarySpec = config.hunt.models[lens];
  const specs = [primarySpec, ...(config.hunt.fallbackModels || [])]
    .filter((spec, index, all) => spec && all.indexOf(spec) === index);
  const errors = [];

  for (const spec of specs) {
    const target = resolveModel(config, spec);
    if (!target) {
      errors.push(`${spec}: unavailable`);
      continue;
    }
    try {
      const out = await complete(config, target, systemPrompt, user);
      const parsed = parseJson(out, { findings: [] });
      const findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
      const usedFallback = spec !== primarySpec;
      if (usedFallback) {
        logError(
          `hunt[${lens}] primary ${primarySpec} unavailable/failed -> fell back to ${spec}`
        );
      }
      return {
        lens,
        ok: true,
        findings: findings.map((finding) => ({
          ...finding,
          lens,
          huntModel: target.spec,
          usedFallback,
        })),
      };
    } catch (err) {
      errors.push(`${spec}: ${err.message}`);
    }
  }

  return {
    lens,
    ok: false,
    error: errors.join('; ') || 'no reachable model',
    findings: [],
  };
}
