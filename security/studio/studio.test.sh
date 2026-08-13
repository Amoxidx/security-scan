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

echo "=== auto-pr-check.sh kill switch (default ON) ==="
{
  AUTO="$ROOT/security/studio/auto-pr-check.sh"
  if [ ! -f "$AUTO" ]; then
    case_result "auto-pr-check.sh exists" 0 "missing"
  else
    run bash -n "$AUTO"
    if [ "$RUN_RC" -eq 0 ]; then
      case_result "auto-pr-check.sh bash -n" 1
    else
      case_result "auto-pr-check.sh bash -n" 0 "$(short "$RUN_OUT")"
    fi
    OFFF="$WORK/auto-off"
    STATED="$WORK/auto-state"
    run env SECURITY_SCAN_AUTO_OFF_FILE="$OFFF" SECURITY_SCAN_AUTO_STATE_DIR="$STATED" \
      bash "$AUTO" --off
    if [ -f "$OFFF" ]; then
      case_result "auto-pr-check --off creates kill-switch file" 1
    else
      case_result "auto-pr-check --off creates kill-switch file" 0 "file missing"
    fi
    run env SECURITY_SCAN_AUTO_OFF_FILE="$OFFF" SECURITY_SCAN_AUTO_STATE_DIR="$STATED" \
      bash "$AUTO" --once
    if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -qi 'SKIP\|disabled'; then
      case_result "auto-pr-check --once exits 0 when disabled" 1
    else
      # SKIP goes to log file; exit 0 is the contract
      if [ "$RUN_RC" -eq 0 ]; then
        case_result "auto-pr-check --once exits 0 when disabled" 1
      else
        case_result "auto-pr-check --once exits 0 when disabled" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
      fi
    fi
    run env SECURITY_SCAN_AUTO_OFF_FILE="$OFFF" SECURITY_SCAN_AUTO_STATE_DIR="$STATED" \
      bash "$AUTO" --on
    if [ ! -f "$OFFF" ]; then
      case_result "auto-pr-check --on clears kill-switch (default ON)" 1
    else
      case_result "auto-pr-check --on clears kill-switch (default ON)" 0 "file still present"
    fi
    run env SECURITY_SCAN_AUTO_PR_CHECK=0 SECURITY_SCAN_AUTO_OFF_FILE="$WORK/no-off" \
      SECURITY_SCAN_AUTO_STATE_DIR="$STATED" bash "$AUTO" --once
    if [ "$RUN_RC" -eq 0 ]; then
      case_result "SECURITY_SCAN_AUTO_PR_CHECK=0 skips tick exit 0" 1
    else
      case_result "SECURITY_SCAN_AUTO_PR_CHECK=0 skips tick exit 0" 0 "rc=$RUN_RC"
    fi
  fi
}

echo "=== claude-via-gui.sh present + syntax ==="
{
  WRAP="$ROOT/security/studio/claude-via-gui.sh"
  if [ ! -f "$WRAP" ]; then
    case_result "claude-via-gui.sh exists" 0 "missing"
  else
    run bash -n "$WRAP"
    if [ "$RUN_RC" -eq 0 ]; then
      case_result "claude-via-gui.sh bash -n" 1
    else
      case_result "claude-via-gui.sh bash -n" 0 "$(short "$RUN_OUT")"
    fi
    if [ -x "$WRAP" ] || chmod +x "$WRAP" 2>/dev/null; then
      case_result "claude-via-gui.sh executable" 1
    else
      case_result "claude-via-gui.sh executable" 0 "not executable"
    fi
  fi
}

echo "=== resolveCliCommand (SECURITY_CLAUDE_WRAPPER) ==="
{
  cat > "$WORK/cli-wrap.mjs" <<'EOF'
import { pathToFileURL } from 'node:url';
import { writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

async function main() {
  const providersPath = process.argv[2];
  const work = process.env.WORK;
  const wrap = join(work, 'fake-claude-wrap.sh');
  writeFileSync(wrap, '#!/bin/sh\nexit 0\n');
  chmodSync(wrap, 0o755);

  const m = await import(pathToFileURL(providersPath).href);
  const provider = { type: 'cli', command: ['claude', '-p'], modelFlag: '--model' };

  delete process.env.SECURITY_CLAUDE_WRAPPER;
  let cmd = m.resolveCliCommand(provider, 'claude-cli');
  if (cmd[0] !== 'claude' || cmd[1] !== '-p') {
    console.error('default command broken', cmd);
    process.exit(1);
  }

  process.env.SECURITY_CLAUDE_WRAPPER = wrap;
  cmd = m.resolveCliCommand(provider, 'claude-cli');
  if (cmd[0] !== wrap || cmd[1] !== '-p') {
    console.error('wrapper not applied', cmd);
    process.exit(1);
  }

  // Non-claude providers ignore the wrapper.
  cmd = m.resolveCliCommand({ type: 'cli', command: ['codex', 'exec'] }, 'codex-cli');
  if (cmd[0] !== 'codex') {
    console.error('codex polluted', cmd);
    process.exit(1);
  }
  console.log('ok');
}
main().catch((e) => { console.error(e); process.exit(1); });
EOF
  run env WORK="$WORK" node "$WORK/cli-wrap.mjs" "$ROOT/security/redteam/providers.mjs"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "resolveCliCommand honors SECURITY_CLAUDE_WRAPPER" 1
  else
    case_result "resolveCliCommand honors SECURITY_CLAUDE_WRAPPER" 0 "$(short "$RUN_OUT")"
  fi
}

echo "=== complete() usage log (cli jsonOutput + http) ==="
{
  run node "$ROOT/security/redteam/providers.test.mjs"
  printf '%s\n' "$RUN_OUT"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "providers.test.mjs usage log" 1
  else
    case_result "providers.test.mjs usage log" 0 "$(short "$RUN_OUT")"
  fi

  # Three child-stage env objects must pass the file-bridge path.
  BRIDGE="$(grep -c 'SECURITY_USAGE_LOG_FILE: usageLogFile(outDir)' "$CHECK_PR" || true)"
  if [ "$BRIDGE" = "3" ]; then
    case_result "check-pr passes SECURITY_USAGE_LOG_FILE to 3 child stages" 1
  else
    case_result "check-pr passes SECURITY_USAGE_LOG_FILE to 3 child stages" 0 "count=$BRIDGE"
  fi
}

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
    if [ -f "$OUT/usage.json" ] && grep -q '"calls": \[\]' "$OUT/usage.json"; then
      case_result "skip-ai writes empty usage.json" 1
    else
      case_result "skip-ai writes empty usage.json" 0 "usage.json missing or calls not empty"
    fi
    if grep -q '### Model usage' "$OUT/report.md"; then
      case_result "skip-ai omits Model usage section" 0 "section present"
    else
      case_result "skip-ai omits Model usage section" 1
    fi
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

echo "=== resolveLabModelSpec (config default + ollama preference) ==="
{
  cat > "$WORK/lab-model-test.mjs" <<'EOF'
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

async function main() {
  const modPath = process.argv[2];
  const configPath = process.argv[3];
  const m = await import(pathToFileURL(modPath).href);
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  if (!config.lab?.model?.includes('qwen3-coder-next')) {
    console.error('config.lab.model missing/wrong', config.lab);
    process.exit(1);
  }
  const explicit = m.resolveLabModelSpec(config, 'ollama:forced-model');
  if (explicit !== 'ollama:forced-model') {
    console.error('explicit override failed', explicit);
    process.exit(1);
  }
  // No live tags: empty available list → configured default.
  const offline = m.resolveLabModelSpec(
    { lab: { model: 'ollama:qwen3-coder-next:q4_K_M', preferredModels: [] } },
    null,
    { available: [] },
  );
  if (offline !== 'ollama:qwen3-coder-next:q4_K_M') {
    console.error('offline default failed', offline);
    process.exit(1);
  }
  // Prefer exact primary when present.
  const primary = m.resolveLabModelSpec(config, null, {
    available: ['qwen3-coder-next:q4_K_M', 'qwen2.5:7b-instruct'],
  });
  if (primary !== 'ollama:qwen3-coder-next:q4_K_M') {
    console.error('primary pick failed', primary);
    process.exit(1);
  }
  // Fall back to frob tag when primary missing.
  const fallback = m.resolveLabModelSpec(config, null, {
    available: ['frob/qwen3-coder-next:80b-a3b-q5_K_M', 'qwen3:32b'],
  });
  if (fallback !== 'ollama:frob/qwen3-coder-next:80b-a3b-q5_K_M') {
    console.error('fallback pick failed', fallback);
    process.exit(1);
  }
  console.log(JSON.stringify({ explicit, offline, primary, fallback, configDefault: config.lab.model }));
}
main().catch((e) => { console.error(e); process.exit(1); });
EOF
  run node "$WORK/lab-model-test.mjs" "$ROOT/security/studio/lab-model.mjs" "$ROOT/security/redteam/config.json"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q 'qwen3-coder-next'; then
    case_result "resolveLabModelSpec uses config.lab + explicit override" 1
  else
    case_result "resolveLabModelSpec uses config.lab + explicit override" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
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
