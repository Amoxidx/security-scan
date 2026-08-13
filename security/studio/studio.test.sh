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
cleanup() {
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf "$WORK"
  fi
}
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

echo "=== claude-via-gui.sh diagnostics / retry / last-failure ==="
{
  WRAP="$ROOT/security/studio/claude-via-gui.sh"
  GDIR="$WORK/gui"
  mkdir -p "$GDIR"
  CACHE="$GDIR/cache"
  FAKE="$GDIR/fake-claude"
  COUNT="$GDIR/count"

  invoke_wrap() {
    env CLAUDE_BIN="$FAKE" \
      SECURITY_CLAUDE_GUI_CACHE="$CACHE" \
      SECURITY_CLAUDE_GUI_FORCE="${WRAP_FORCE:-0}" \
      SECURITY_CLAUDE_GUI_RETRIES="${WRAP_RETRIES:-0}" \
      SECURITY_CLAUDE_GUI_TIMEOUT_S="${WRAP_TIMEOUT:-20}" \
      SECURITY_CLAUDE_GUI_FAILURE_MAX_AGE_S="${WRAP_MAX_AGE:-3600}" \
      bash "$WRAP" "$@"
  }

  # Empty-stderr exit 1 must no longer produce the "exited 1:" void.
  cat > "$FAKE" <<'EOF'
#!/bin/sh
exit 1
EOF
  chmod +x "$FAKE"
  mkdir -p "$CACHE"
  run invoke_wrap -p --model sonnet <<'EOF'
prompt
EOF
  if [ "$RUN_RC" -ne 0 ] && [ -n "$RUN_OUT" ] \
      && echo "$RUN_OUT" | grep -q 'empty stderr' \
      && echo "$RUN_OUT" | grep -qE 'run_via_gui|run_direct|direct_auth_ok|gui_auth_ok'; then
    case_result "empty-stderr failure emits stage + hint" 1
  else
    case_result "empty-stderr failure emits stage + hint" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi

  MARK="$CACHE/last-failure.json"
  if [ -f "$MARK" ] \
      && grep -q '"ts"' "$MARK" \
      && grep -q '"stage"' "$MARK" \
      && grep -q '"message"' "$MARK" \
      && grep -q 'empty stderr' "$MARK"; then
    case_result "failure writes last-failure.json" 1
  else
    case_result "failure writes last-failure.json" 0 \
      "mark=$(short "$(cat "$MARK" 2>/dev/null || echo missing)")"
  fi

  run invoke_wrap --studio-auth-check
  if [ "$RUN_RC" -ne 0 ] \
      && echo "$RUN_OUT" | grep -q 'direct_auth_ok' \
      && echo "$RUN_OUT" | grep -q 'gui_auth_ok'; then
    case_result "auth-check failure names both stages" 1
  else
    case_result "auth-check failure names both stages" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi

  # Recent marker is mentioned even when the current probe succeeds.
  cat > "$FAKE" <<'EOF'
#!/bin/sh
if [ "$1" = "auth" ]; then
  printf '%s\n' '{"loggedIn":true}'
  exit 0
fi
printf '%s\n' 'ok-answer'
exit 0
EOF
  chmod +x "$FAKE"
  mkdir -p "$CACHE"
  printf '{"ts":"%s","stage":"run_via_gui","message":"run_via_gui failed: exit 1: simulated"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$MARK"
  run invoke_wrap --studio-auth-check
  if [ "$RUN_RC" -eq 0 ] \
      && echo "$RUN_OUT" | grep -q 'auth ok (direct)' \
      && echo "$RUN_OUT" | grep -q 'letzter Fehlschlag' \
      && echo "$RUN_OUT" | grep -q 'simulated'; then
    case_result "auth-check mentions recent last-failure.json" 1
  else
    case_result "auth-check mentions recent last-failure.json" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi

  printf '{"ts":"%s","stage":"run_via_gui","message":"auth-check-should-clear"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$MARK"
  run invoke_wrap --studio-auth-check
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q 'auth ok (direct)' && [ ! -f "$MARK" ]; then
    case_result "successful auth-check clears last-failure.json" 1
  else
    case_result "successful auth-check clears last-failure.json" 0 \
      "rc=$RUN_RC mark_exists=$([ -f "$MARK" ] && echo yes || echo no) out=$(short "$RUN_OUT")"
  fi

  # Marker older than the window stays silent.
  printf '{"ts":"%s","stage":"run_via_gui","message":"run_via_gui failed: exit 1: stale-marker"}\n' \
    "$(date -u -v-2H +%Y-%m-%dT%H:%M:%SZ)" > "$MARK"
  run invoke_wrap --studio-auth-check
  if [ "$RUN_RC" -eq 0 ] \
      && echo "$RUN_OUT" | grep -q 'auth ok (direct)' \
      && ! echo "$RUN_OUT" | grep -q 'stale-marker' \
      && ! echo "$RUN_OUT" | grep -q 'letzter Fehlschlag'; then
    case_result "auth-check ignores last-failure older than 1h" 1
  else
    case_result "auth-check ignores last-failure older than 1h" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi

  # Successful run deletes the marker.
  printf '{"ts":"%s","stage":"run_via_gui","message":"should-be-cleared"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$MARK"
  run invoke_wrap -p --model sonnet <<'EOF'
prompt
EOF
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q 'ok-answer' && [ ! -f "$MARK" ]; then
    case_result "successful run clears last-failure.json" 1
  else
    case_result "successful run clears last-failure.json" 0 \
      "rc=$RUN_RC mark_exists=$([ -f "$MARK" ] && echo yes || echo no) out=$(short "$RUN_OUT")"
  fi

  # Empty stdout+stderr + exit!=0 is retried; a real stderr body is not.
  cat > "$FAKE" <<EOF
#!/bin/sh
if [ "\$1" = "auth" ]; then
  printf '%s\\n' '{"loggedIn":false}'
  exit 1
fi
n=0
[ -f "$COUNT" ] && n=\$(cat "$COUNT")
n=\$((n + 1))
echo "\$n" > "$COUNT"
exit 1
EOF
  chmod +x "$FAKE"
  rm -f "$COUNT"
  mkdir -p "$CACHE"
  WRAP_RETRIES=2
  run invoke_wrap -p --model sonnet <<'EOF'
prompt
EOF
  WRAP_RETRIES=0
  ncount="$(cat "$COUNT" 2>/dev/null || echo 0)"
  if [ "$RUN_RC" -ne 0 ] && [ "$ncount" = "3" ]; then
    case_result "empty-stderr run_via_gui retries default-2 extra times" 1
  else
    case_result "empty-stderr run_via_gui retries default-2 extra times" 0 \
      "rc=$RUN_RC count=$ncount out=$(short "$RUN_OUT")"
  fi

  cat > "$FAKE" <<EOF
#!/bin/sh
if [ "\$1" = "auth" ]; then
  printf '%s\\n' '{"loggedIn":false}'
  exit 1
fi
n=0
[ -f "$COUNT" ] && n=\$(cat "$COUNT")
n=\$((n + 1))
echo "\$n" > "$COUNT"
echo "model exploded" >&2
exit 1
EOF
  chmod +x "$FAKE"
  rm -f "$COUNT"
  mkdir -p "$CACHE"
  WRAP_RETRIES=2
  run invoke_wrap -p --model sonnet <<'EOF'
prompt
EOF
  WRAP_RETRIES=0
  ncount="$(cat "$COUNT" 2>/dev/null || echo 0)"
  if [ "$RUN_RC" -ne 0 ] && [ "$ncount" = "1" ] && echo "$RUN_OUT" | grep -q 'model exploded'; then
    case_result "non-empty stderr is not retried" 1
  else
    case_result "non-empty stderr is not retried" 0 \
      "rc=$RUN_RC count=$ncount out=$(short "$RUN_OUT")"
  fi

  # --- sanitize_text + unwritable cache (review blockers) ---

  file_mode() {
    stat -f '%OLp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null || echo missing
  }

  # Persist a failing run_direct whose stderr is $1; then inspect last-failure.json.
  fail_with_stderr() {
    printf '%s\n' "$1" > "$GDIR/secret-payload"
    cat > "$FAKE" <<EOF
#!/bin/sh
if [ "\$1" = "auth" ]; then
  printf '%s\\n' '{"loggedIn":true}'
  exit 0
fi
cat "$GDIR/secret-payload" >&2
exit 1
EOF
    chmod +x "$FAKE"
    rm -f "$MARK"
    mkdir -p "$CACHE"
    run invoke_wrap -p --model sonnet <<'PROMPT'
prompt
PROMPT
  }

  fail_with_stderr '{"access_token": "eyJabc123notajwt"}'
  if [ "$RUN_RC" -ne 0 ] && [ -f "$MARK" ] \
      && grep -q '\[redacted\]' "$MARK" \
      && ! grep -q 'eyJabc123notajwt' "$MARK" \
      && ! grep -q 'access_token' "$MARK"; then
    case_result "sanitize redacts JSON-quoted access_token" 1
  else
    case_result "sanitize redacts JSON-quoted access_token" 0 \
      "rc=$RUN_RC mark=$(short "$(cat "$MARK" 2>/dev/null || echo missing)")"
  fi

  # Prefix/body stay on separate source lines so no ADDED line matches the gate
  # patterns (sk-ant-[A-Za-z0-9_-]{32,} / AKIA[0-9A-Z]{16}). Runtime expansion
  # rebuilds the exact strings sanitize_text must redact.
  SK_OAT_PFX='sk-ant-oat01-'
  SK_OAT_BODY='abcdefghijklmnopqrstuvwxyz012345'
  SK_ORT_PFX='sk-ant-ort01-'
  SK_ORT_BODY='abcdefghijklmnopqrstuvwxyz012345'
  fail_with_stderr "{\"claudeAiOauth\":{\"accessToken\":\"${SK_OAT_PFX}${SK_OAT_BODY}\",\"refreshToken\":\"${SK_ORT_PFX}${SK_ORT_BODY}\"}}"
  if [ "$RUN_RC" -ne 0 ] && [ -f "$MARK" ] \
      && grep -q '\[redacted\]' "$MARK" \
      && ! grep -q 'sk-ant-oat01' "$MARK" \
      && ! grep -q 'sk-ant-ort01' "$MARK" \
      && ! grep -q 'accessToken' "$MARK"; then
    case_result "sanitize redacts Claude camelCase OAuth tokens" 1
  else
    case_result "sanitize redacts Claude camelCase OAuth tokens" 0 \
      "rc=$RUN_RC mark=$(short "$(cat "$MARK" 2>/dev/null || echo missing)")"
  fi

  AKIA_PART1='AKIA'
  AKIA_PART2='IOSFODNN7EXAMPLE'
  fail_with_stderr "{\"api_key\": \"${AKIA_PART1}${AKIA_PART2}\"}"
  if [ "$RUN_RC" -ne 0 ] && [ -f "$MARK" ] \
      && grep -q '\[redacted\]' "$MARK" \
      && ! grep -q "${AKIA_PART1}${AKIA_PART2}" "$MARK" \
      && ! grep -q 'api_key' "$MARK"; then
    case_result "sanitize redacts JSON-quoted api_key" 1
  else
    case_result "sanitize redacts JSON-quoted api_key" 0 \
      "rc=$RUN_RC mark=$(short "$(cat "$MARK" 2>/dev/null || echo missing)")"
  fi

  fail_with_stderr 'invalid_grant: refresh failed for token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ'
  if [ "$RUN_RC" -ne 0 ] && [ -f "$MARK" ] \
      && grep -q '\[redacted\]' "$MARK" \
      && ! grep -q 'eyJhbGci' "$MARK"; then
    case_result "sanitize redacts raw JWT without keyword" 1
  else
    case_result "sanitize redacts raw JWT without keyword" 0 \
      "rc=$RUN_RC mark=$(short "$(cat "$MARK" 2>/dev/null || echo missing)")"
  fi

  # Persist path that emit_auth_check_success would otherwise re-print on stdout.
  fail_with_stderr '{"access_token": "eyJabc123notajwt"}'
  cat > "$FAKE" <<'EOF'
#!/bin/sh
if [ "$1" = "auth" ]; then
  printf '%s\n' '{"loggedIn":true}'
  exit 0
fi
printf '%s\n' 'ok-answer'
exit 0
EOF
  chmod +x "$FAKE"
  run invoke_wrap --studio-auth-check
  if [ "$RUN_RC" -eq 0 ] \
      && echo "$RUN_OUT" | grep -q 'auth ok (direct)' \
      && echo "$RUN_OUT" | grep -q 'letzter Fehlschlag' \
      && ! echo "$RUN_OUT" | grep -q 'eyJabc123notajwt' \
      && ! echo "$RUN_OUT" | grep -q 'access_token'; then
    case_result "auth-check success does not re-emit persisted secret" 1
  else
    case_result "auth-check success does not re-emit persisted secret" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi

  fail_with_stderr '{"access_token": "eyJabc123notajwt"}'
  dperm="$(file_mode "$CACHE")"
  fperm="$(file_mode "$MARK")"
  if [ "$dperm" = "700" ] && [ "$fperm" = "600" ]; then
    case_result "last-failure.json and cache dir are owner-only" 1
  else
    case_result "last-failure.json and cache dir are owner-only" 0 \
      "dir=$dperm file=$fperm"
  fi

  # Blocker 2: unwritable CACHE_ROOT must fail loud, not abort on bare mkdir/mktemp.
  cat > "$FAKE" <<'EOF'
#!/bin/sh
if [ "$1" = "auth" ]; then
  printf '%s\n' '{"loggedIn":true}'
  exit 0
fi
printf '%s\n' 'should-not-run'
exit 0
EOF
  chmod +x "$FAKE"
  ROPARENT="$GDIR/ro-parent"
  rm -rf "$ROPARENT"
  mkdir -p "$ROPARENT"
  chmod 555 "$ROPARENT"
  CACHE="$ROPARENT/cache"
  MARK="$CACHE/last-failure.json"
  run invoke_wrap -p --model sonnet <<'PROMPT'
prompt
PROMPT
  chmod 755 "$ROPARENT" 2>/dev/null || true
  if [ "$RUN_RC" -eq 3 ] \
      && echo "$RUN_OUT" | grep -q 'claude-via-gui:' \
      && echo "$RUN_OUT" | grep -qE 'not writable|mktemp failed' \
      && ! echo "$RUN_OUT" | grep -q 'should-not-run'; then
    case_result "unwritable cache still emits diagnostic" 1
  else
    case_result "unwritable cache still emits diagnostic" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
  CACHE="$GDIR/cache"
  MARK="$CACHE/last-failure.json"
  mkdir -p "$CACHE"

  # Same defect on the GUI fallback: parent of CACHE_ROOT is 555, FORCE=1
  # so the call site takes run_via_gui (plain statement, not an if-condition).
  cat > "$FAKE" <<'EOF'
#!/bin/sh
if [ "$1" = "auth" ]; then
  printf '%s\n' '{"loggedIn":true}'
  exit 0
fi
printf '%s\n' 'should-not-run'
exit 0
EOF
  chmod +x "$FAKE"
  ROPARENT="$GDIR/ro-parent-gui"
  rm -rf "$ROPARENT"
  mkdir -p "$ROPARENT"
  chmod 555 "$ROPARENT"
  CACHE="$ROPARENT/cache"
  MARK="$CACHE/last-failure.json"
  WRAP_FORCE=1
  run invoke_wrap -p --model sonnet <<'PROMPT'
prompt
PROMPT
  WRAP_FORCE=0
  chmod 755 "$ROPARENT" 2>/dev/null || true
  if [ "$RUN_RC" -eq 3 ] \
      && echo "$RUN_OUT" | grep -q 'claude-via-gui:' \
      && echo "$RUN_OUT" | grep -qE 'not writable|mktemp failed' \
      && ! echo "$RUN_OUT" | grep -q 'should-not-run'; then
    case_result "unwritable cache still emits diagnostic via run_via_gui" 1
  else
    case_result "unwritable cache still emits diagnostic via run_via_gui" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
  CACHE="$GDIR/cache"
  MARK="$CACHE/last-failure.json"
  mkdir -p "$CACHE"
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
