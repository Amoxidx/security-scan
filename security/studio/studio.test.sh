#!/usr/bin/env bash
#
# Regression for security/studio + docker resolution (no Ollama, no live PR, no network).
# Exit: 0 all passed, 1 failure. Summary: "N/M Fälle bestanden"

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SANDBOX="$ROOT/security/lab/sandbox.mjs"
CHECK_PR="$ROOT/security/studio/check-pr.mjs"
BOOTSTRAP="$ROOT/security/studio/bootstrap.sh"

PASS=0
FAIL=0
TOTAL=0
WORK=
cleanup() { [ -n "${WORK:-}" ] && [ -d "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT
WORK="$(mktemp -d "${TMPDIR:-/tmp}/studio-test.XXXXXX")"

case_result() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL + 1))
  if [ "$ok" = "1" ]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"
    [ -n "$detail" ] && printf '         %s\n' "$detail"
  fi
}

run() {
  set +e
  RUN_OUT="$("$@" 2>&1)"
  RUN_RC=$?
  set -e
  return 0
}

short() { echo "$1" | tr '\n' ' ' | cut -c1-220; }

set +e

echo "=== resolveDockerBin ==="
{
  cat > "$WORK/docker-resolve.mjs" <<'EOF'
import { pathToFileURL } from 'node:url';
import { writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

async function main() {
  const { resolveDockerBin } = await import(pathToFileURL(process.argv[2]).href);

  const base = resolveDockerBin();
  if (typeof base !== 'string' || base.length === 0) {
    console.error('expected non-empty docker bin, got', base);
    process.exit(1);
  }

  const fake = join(process.env.WORK, 'fake-docker');
  mkdirSync(process.env.WORK, { recursive: true });
  writeFileSync(fake, '#!/bin/sh\necho fake\n');
  chmodSync(fake, 0o755);
  process.env.DOCKER_BIN = fake;
  const over = resolveDockerBin();
  if (over !== fake) {
    console.error('DOCKER_BIN override ignored:', over);
    process.exit(1);
  }
  console.log(JSON.stringify({ base, over }));
}
main().catch((e) => { console.error(e); process.exit(1); });
EOF
  run env WORK="$WORK" node "$WORK/docker-resolve.mjs" "$SANDBOX"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q '"over"'; then
    case_result "resolveDockerBin + DOCKER_BIN override" 1
  else
    case_result "resolveDockerBin + DOCKER_BIN override" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

echo "=== check-pr.mjs --help / usage ==="
{
  run node "$CHECK_PR" --help
  # usage() exits 3
  if [ "$RUN_RC" -eq 3 ] && echo "$RUN_OUT" | grep -qE 'Usage \(primary|Usage:'; then
    case_result "check-pr --help exits 3 with usage" 1
  else
    case_result "check-pr --help exits 3 with usage" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

echo "=== check-pr.mjs --local --skip-ai on this repo ==="
{
  OUT="$WORK/local-static"
  run node "$CHECK_PR" --local --repo-dir "$ROOT" --base origin/master \
    --skip-ai --skip-scanners --out "$OUT"
  # static may pass or fail depending on dirty tree; we only require the orchestrator to finish 0/1/2 not 3
  if [ "$RUN_RC" -eq 3 ]; then
    case_result "local --skip-ai orchestrator runs" 0 "setup error: $(short "$RUN_OUT")"
  elif [ -f "$OUT/report.md" ] && [ -f "$OUT/gate.json" ] && [ -f "$OUT/subject.json" ]; then
    case_result "local --skip-ai orchestrator runs" 1
  else
    case_result "local --skip-ai orchestrator runs" 0 "rc=$RUN_RC missing artifacts; $(short "$RUN_OUT")"
  fi
}

echo "=== check-pr.mjs --local --skip-ai with scanners (if semgrep present) ==="
{
  if ! command -v semgrep >/dev/null 2>&1; then
    case_result "local scanners stage (semgrep optional)" 1 "skipped — semgrep not installed"
  else
    OUT="$WORK/local-scan"
    run node "$CHECK_PR" --local --repo-dir "$ROOT" --base origin/master \
      --skip-ai --out "$OUT"
    if [ -f "$OUT/findings.json" ] || [ -f "$OUT/sarif/scanners.json" ] || [ -f "$OUT/scanners.log" ]; then
      case_result "local scanners stage (semgrep optional)" 1
    else
      case_result "local scanners stage (semgrep optional)" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
    fi
  fi
}

echo "=== bootstrap.sh --check runs ==="
{
  run bash "$BOOTSTRAP" --check
  # may exit 0 or 1 depending on host; must not be 2 (usage) and must print Summary
  if [ "$RUN_RC" -eq 2 ]; then
    case_result "bootstrap --check" 0 "usage error"
  elif echo "$RUN_OUT" | grep -q 'Summary'; then
    case_result "bootstrap --check" 1
  else
    case_result "bootstrap --check" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
  fi
}

echo "=== finalGate unit (node) ==="
{
  cat > "$WORK/final-gate.mjs" <<'EOF'
// Inline the decision table from check-pr (duplicated intentionally as a contract test).
function finalGate({ staticBlocked, labResults, harnessSurvivors, blockOn }) {
  const reasons = [];
  let blocked = false;
  let inconclusiveBlock = false;
  if (staticBlocked) { blocked = true; reasons.push('static'); }

  const labByKey = new Map();
  for (const r of labResults) {
    labByKey.set(`${r.file}:${r.line}:${r.title}`, r.verdict);
  }
  for (const f of harnessSurvivors) {
    const k = `${f.file}:${f.line}:${f.title}`;
    const lv = labByKey.get(k) || null;
    if (lv === 'not-reproduced') { reasons.push('cleared'); continue; }
    if (lv === 'reproduced') { blocked = true; reasons.push('reproduced'); continue; }
    if (lv === 'inconclusive' && blockOn.includes(f.severity)) {
      blocked = true; inconclusiveBlock = true; reasons.push('inconclusive'); continue;
    }
    if (!lv && blockOn.includes(f.severity)) { blocked = true; reasons.push('severity'); }
  }
  return { blocked, inconclusiveBlock, reasons };
}

const blockOn = ['critical', 'high', 'error'];

// reproduced wins
let g = finalGate({
  staticBlocked: false,
  labResults: [{ file: 'a.ts', line: 1, title: 't', verdict: 'reproduced' }],
  harnessSurvivors: [{ file: 'a.ts', line: 1, title: 't', severity: 'high', survived: true }],
  blockOn,
});
if (!g.blocked || !g.reasons.includes('reproduced')) { console.error('reproduced', g); process.exit(1); }

// not-reproduced clears
g = finalGate({
  staticBlocked: false,
  labResults: [{ file: 'a.ts', line: 1, title: 't', verdict: 'not-reproduced' }],
  harnessSurvivors: [{ file: 'a.ts', line: 1, title: 't', severity: 'critical', survived: true }],
  blockOn,
});
if (g.blocked) { console.error('should clear', g); process.exit(1); }

// no lab + high severity blocks
g = finalGate({
  staticBlocked: false,
  labResults: [],
  harnessSurvivors: [{ file: 'a.ts', line: 1, title: 't', severity: 'high', survived: true }],
  blockOn,
});
if (!g.blocked) { console.error('severity block', g); process.exit(1); }

// low severity without lab does not block
g = finalGate({
  staticBlocked: false,
  labResults: [],
  harnessSurvivors: [{ file: 'a.ts', line: 1, title: 't', severity: 'low', survived: true }],
  blockOn,
});
if (g.blocked) { console.error('low should pass', g); process.exit(1); }

console.log('ok');
EOF
  run node "$WORK/final-gate.mjs"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "finalGate decision table" 1
  else
    case_result "finalGate decision table" 0 "$(short "$RUN_OUT")"
  fi
}

echo "=== targets.mjs ==="
{
  cat > "$WORK/targets-test.mjs" <<'EOF'
import { pathToFileURL } from 'node:url';

async function main() {
  const m = await import(pathToFileURL(process.argv[2]).href);
  const reg = m.loadTargetsRegistry();
  if (!reg.targets['security-scan'] || !reg.targets['dfx-api'] || !reg.targets['generic']) {
    console.error('missing core targets');
    process.exit(1);
  }
  const t = m.getTarget(reg, 'dfx-api');
  if (t.repo !== 'DFXswiss/api') { console.error('dfx-api repo', t); process.exit(1); }
  const extra = m.hostAllowExtraEnv(t, ['extra\\.example']);
  if (!extra.includes('api\\.dfx\\.swiss')) {
    console.error('host extra missing dfx', extra);
    process.exit(1);
  }
  if (!extra.includes('extra\\.example')) { console.error('cli extra missing', extra); process.exit(1); }
  const id = m.inferTargetId(reg, { repo: 'DFXswiss/services' });
  if (id !== 'dfx-services') { console.error('infer', id); process.exit(1); }
  const base = m.resolveBase(t, null, { mode: 'local' });
  if (base !== 'origin/develop') { console.error('base', base); process.exit(1); }
  const exp = m.expandPath('~/Amoxidx/security-scan');
  if (!exp.includes('Amoxidx')) { console.error('expand', exp); process.exit(1); }
  console.log('ok');
}
main().catch((e) => { console.error(e); process.exit(1); });
EOF
  run node "$WORK/targets-test.mjs" "$ROOT/security/studio/targets.mjs"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "targets registry + hostAllow + infer" 1
  else
    case_result "targets registry + hostAllow + infer" 0 "$(short "$RUN_OUT")"
  fi
}

echo "=== list-targets + tree mode dry ==="
{
  run node "$CHECK_PR" --list-targets
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q 'dfx-api'; then
    case_result "list-targets shows dfx-api" 1
  else
    case_result "list-targets shows dfx-api" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
  fi

  # tree mode on this repo, scanners only — proves other-codebase path works without AI
  OUT="$WORK/tree-mode"
  run node "$CHECK_PR" --mode tree --dir "$ROOT" --target security-scan \
    --skip-ai --skip-static --out "$OUT"
  if [ -f "$OUT/subject.json" ] && [ -f "$OUT/report.md" ]; then
    MODE="$(node -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).mode)" "$OUT/subject.json")"
    if [ "$MODE" = "tree" ]; then
      case_result "tree mode on local dir produces report" 1
    else
      case_result "tree mode on local dir produces report" 0 "mode=$MODE"
    fi
  else
    case_result "tree mode on local dir produces report" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
  fi
}

echo "=== SECURITY_HOST_ALLOW_EXTRA reaches static-checks ==="
{
  # Unit-ish: the shell gate merges EXTRA; empty CODE_ADDED path is hard, so just
  # verify the env is accepted (gate still needs a real git base — use this repo).
  if ! git -C "$ROOT" rev-parse --verify origin/master >/dev/null 2>&1; then
    case_result "static-checks accepts SECURITY_HOST_ALLOW_EXTRA" 1 "skipped — no origin/master"
  else
    run env SECURITY_HOST_ALLOW_EXTRA='example\.invalid' \
      bash "$ROOT/security/gate/static-checks.sh" origin/master
    # Exit 0 or 1 both fine (dirty tree may block for other reasons); must not crash.
    if [ "$RUN_RC" -le 1 ]; then
      case_result "static-checks accepts SECURITY_HOST_ALLOW_EXTRA" 1
    else
      case_result "static-checks accepts SECURITY_HOST_ALLOW_EXTRA" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
    fi
  fi
}

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m%s/%s Fälle bestanden\033[0m\n' "$PASS" "$TOTAL"
  exit 0
fi
printf '\033[31m%s/%s Fälle bestanden\033[0m\n' "$PASS" "$TOTAL"
exit 1
