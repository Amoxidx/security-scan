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
      const parsed = parseJson(out, null);
      // Empty results are valid only in the documented array/object shapes.
      // An unparseable or structurally invalid response is a failed lens so
      // it cannot be mistaken for a clean hunt.
      const findings = Array.isArray(parsed) ? parsed : parsed?.findings;
      if (!Array.isArray(findings) || findings.some((finding) => !validFinding(finding))) {
        throw new Error('unparseable or malformed hunt response');
      }
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

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const CONFIDENCES = new Set(['high', 'medium', 'low']);
const REQUIRED_TEXT = [
  'title',
  'file',
  'root_cause',
  'attacker_model',
  'impact',
  'guarantee_broken',
  'how_to_disprove',
];

function validFinding(finding) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) return false;
  if (REQUIRED_TEXT.some((key) => typeof finding[key] !== 'string' || !finding[key].trim())) return false;
  if (!Number.isInteger(finding.line) || finding.line < 1) return false;
  if (!SEVERITIES.has(finding.severity) || !CONFIDENCES.has(finding.confidence)) return false;
  return Array.isArray(finding.attack_path) &&
    finding.attack_path.length > 0 &&
    finding.attack_path.every((step) => typeof step === 'string' && step.trim());
}
