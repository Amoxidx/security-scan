#!/usr/bin/env bash
#
# Self-contained regression tests for security/lab (run.mjs + sandbox.mjs).
# Uses only bash and node. No Ollama, no Docker/Colima, no model download.
#
# Exit: 0 all passed, 1 one or more failed.
# Summary line: "N/M Fälle bestanden"

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/security/lab"
RUN_MJS="$LAB/run.mjs"
SANDBOX_MJS="$LAB/sandbox.mjs"
PARSE_JSON_TEST="$LAB/parse-json.test.mjs"
FINDING="$LAB/fixtures/finding-proto-pollution.json"
CODE_DIR="$ROOT/security/eval/corpus/vuln/006-proto-pollution/after"

PASS=0
FAIL=0
TOTAL=0

WORK=
cleanup() {
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lab-test.XXXXXX")"

case_result() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL + 1))
  if [ "$ok" = "1" ]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"
    if [ -n "$detail" ]; then
      printf '         %s\n' "$detail"
    fi
  fi
}

# Run command; set RUN_RC and RUN_OUT (stdout+stderr). Never aborts the suite.
run() {
  set +e
  RUN_OUT="$("$@" 2>&1)"
  RUN_RC=$?
  set -e
  return 0
}

short() {
  echo "$1" | tr '\n' ' ' | cut -c1-220
}

read_report_field() {
  # usage: read_report_field <report.json> <field-path like verdict|blocker|turnsUsed|limits.hitTurnCap>
  node -e "
const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const path = process.argv[2].split('.');
let v = r;
for (const p of path) v = v == null ? undefined : v[p];
process.stdout.write(v === undefined || v === null ? '' : String(v));
" "$1" "$2"
}

# Disable errexit for the suite body; each case captures its own status.
set +e

# ---------------------------------------------------------------- max-turns 0 → immediate inconclusive (no model / no sandbox)

echo "=== run.mjs max-turns 0 (fail-closed, no Ollama/Docker) ==="

{
  OUT="$WORK/max-turns-0"
  mkdir -p "$OUT"
  # OLLAMA_API_KEY only satisfies providers.mjs resolution; no server is contacted
  # because maxTurns === 0 finalizes before ensureImage() / the model loop.
  run env OLLAMA_API_KEY=ollama node "$RUN_MJS" \
    --finding "$FINDING" \
    --code-dir "$CODE_DIR" \
    --max-turns 0 \
    --out "$OUT"

  REPORT="$OUT/report.json"
  DETAIL="rc=$RUN_RC out=$(short "$RUN_OUT")"

  if [ "$RUN_RC" -ne 2 ]; then
    case_result "max-turns 0 → inconclusive exit 2 without model/sandbox" 0 "$DETAIL"
  elif [ ! -f "$REPORT" ]; then
    case_result "max-turns 0 → inconclusive exit 2 without model/sandbox" 0 "report.json missing; $DETAIL"
  else
    # Assert the early fail-closed path, not a later docker/model failure.
    VERDICT="$(read_report_field "$REPORT" "verdict")"
    BLOCKER="$(read_report_field "$REPORT" "blocker")"
    TURNS="$(read_report_field "$REPORT" "turnsUsed")"
    HIT="$(read_report_field "$REPORT" "limits.hitTurnCap")"

    if [ "$VERDICT" = "inconclusive" ] \
      && [ "$BLOCKER" = "max-turns is 0" ] \
      && [ "$TURNS" = "0" ] \
      && [ "$HIT" = "true" ]; then
      case_result "max-turns 0 → inconclusive exit 2 without model/sandbox" 1
    else
      case_result "max-turns 0 → inconclusive exit 2 without model/sandbox" 0 \
        "verdict=$VERDICT blocker=$BLOCKER turnsUsed=$TURNS hitTurnCap=$HIT; $DETAIL"
    fi
  fi
}

# ---------------------------------------------------------------- sandbox.mjs validation (no docker spawn)

echo "=== sandbox.mjs runInSandbox validation (pre-docker) ==="

{
  cat > "$WORK/sandbox-validation.mjs" <<'EOF'
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const { runInSandbox } = await import(pathToFileURL(process.env.LAB_SANDBOX_MJS).href);

const wd = mkdtempSync(join(tmpdir(), 'lab-sbx-'));
const results = {};
try {
  results.dotdot = await runInSandbox({
    workdir: wd, filename: '../x.js', script: '1', runCommand: ['node', 'x.js'],
  });
  results.abspath = await runInSandbox({
    workdir: wd, filename: '/etc/passwd', script: '1', runCommand: ['node', 'x.js'],
  });
  results.nullbyte = await runInSandbox({
    workdir: wd, filename: 'x\0.js', script: '1', runCommand: ['node', 'x.js'],
  });
  results.missingCmd = await runInSandbox({
    workdir: wd, filename: 'ok.js', script: '1',
  });
  results.notArray = await runInSandbox({
    workdir: wd, filename: 'ok.js', script: '1', runCommand: 'node ok.js',
  });
  results.emptyCmd = await runInSandbox({
    workdir: wd, filename: 'ok.js', script: '1', runCommand: [],
  });
  results.banned = await runInSandbox({
    workdir: wd, filename: 'ok.js', script: '1', runCommand: ['curl', 'https://example.com'],
  });
  results.bannedNpm = await runInSandbox({
    workdir: wd, filename: 'ok.js', script: '1', runCommand: ['npm', 'install'],
  });
  results.missingWd = await runInSandbox({
    workdir: join(wd, 'does-not-exist'), filename: 'ok.js', script: '1', runCommand: ['node', 'ok.js'],
  });
  console.log(JSON.stringify(results));
} finally {
  rmSync(wd, { recursive: true, force: true });
}
EOF
  run env LAB_SANDBOX_MJS="$SANDBOX_MJS" node "$WORK/sandbox-validation.mjs"
  if [ "$RUN_RC" -ne 0 ]; then
    case_result "sandbox validation harness runs" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  else
    JSON_LINE="$(printf '%s\n' "$RUN_OUT" | grep '^{' | tail -1)"

    check_field() {
      local name="$1" key="$2" pattern="$3"
      local err
      err="$(node -e "
const j = JSON.parse(process.argv[1]);
const r = j[process.argv[2]];
if (!r || r.ok !== false) { console.log('ok_not_false'); process.exit(0); }
const e = String(r.error || '');
if (!new RegExp(process.argv[3], 'i').test(e)) { console.log(e); process.exit(0); }
console.log('OK');
" "$JSON_LINE" "$key" "$pattern")"
      if [ "$err" = "OK" ]; then
        case_result "$name" 1
      else
        case_result "$name" 0 "got=$err json_key=$key"
      fi
    }

    check_field "filename with .. → unsafe filename" "dotdot" "unsafe filename"
    check_field "filename with leading / → unsafe filename" "abspath" "unsafe filename"
    check_field "filename with null byte → unsafe filename" "nullbyte" "unsafe filename"
    check_field "runCommand missing → run_command error" "missingCmd" "run_command"
    check_field "runCommand not array → run_command error" "notArray" "run_command"
    check_field "runCommand empty array → run_command error" "emptyCmd" "run_command"
    check_field "runCommand[0]=curl banned → not allowed" "banned" "not allowed"
    check_field "runCommand[0]=npm banned → not allowed" "bannedNpm" "not allowed"
    check_field "workdir missing → workdir missing" "missingWd" "workdir missing"
  fi
}

# ---------------------------------------------------------------- parseJson robustness

echo "=== run.mjs parseJson (export + robust parse) ==="

{
  run node "$PARSE_JSON_TEST"
  PARSED_ANY=0
  while IFS= read -r line; do
    case "$line" in
      *"PASS  "*)
        PARSED_ANY=1
        name="${line#*PASS  }"
        # strip trailing detail after em dash if present on FAIL only
        case_result "$name" 1
        ;;
      *"FAIL  "*)
        PARSED_ANY=1
        name="${line#*FAIL  }"
        case_result "$name" 0 "$(short "$RUN_OUT")"
        ;;
    esac
  done <<< "$RUN_OUT"

  if [ "$RUN_RC" -ne 0 ] && [ "$PARSED_ANY" -eq 0 ]; then
    case_result "parseJson helper executed" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# ---------------------------------------------------------------- summary

echo
printf '%s/%s Fälle bestanden\n' "$PASS" "$TOTAL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
