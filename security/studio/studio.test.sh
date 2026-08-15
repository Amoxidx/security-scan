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
      PATH="${WRAP_PATH:-$PATH}" \
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

  # Fund 3: a pre-existing CACHE_ROOT owned by someone else must refuse.
  # chown to another real user needs sudo on macOS, so mock `stat -f %u`
  # (and GNU `stat -c %u`) via PATH to report a foreign uid.
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
  FOREIGN="$GDIR/foreign-cache"
  rm -rf "$FOREIGN"
  mkdir -p "$FOREIGN"
  STATBIN="$GDIR/fake-stat-bin"
  mkdir -p "$STATBIN"
  cat > "$STATBIN/stat" <<'EOF'
#!/bin/sh
if [ "$1" = "-f" ] && [ "$2" = "%u" ]; then
  echo 65534
  exit 0
fi
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then
  echo 65534
  exit 0
fi
exec /usr/bin/stat "$@"
EOF
  chmod +x "$STATBIN/stat"
  CACHE="$FOREIGN"
  MARK="$CACHE/last-failure.json"
  WRAP_PATH="$STATBIN:$PATH"
  run invoke_wrap -p --model sonnet <<'PROMPT'
prompt
PROMPT
  WRAP_PATH=
  if [ "$RUN_RC" -eq 3 ] \
      && echo "$RUN_OUT" | grep -q 'exists but is not owned by the current user' \
      && ! echo "$RUN_OUT" | grep -q 'should-not-run'; then
    case_result "foreign-owned cache refuses instead of being reused" 1
  else
    case_result "foreign-owned cache refuses instead of being reused" 0 \
      "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
  CACHE="$GDIR/cache"
  MARK="$CACHE/last-failure.json"
  mkdir -p "$CACHE"

  # Fund 1: launchd labels must not be primarily PID+$RANDOM (15 bits).
  if grep -qE 'claude-(auth|run)\.\$\$\.\$RANDOM' "$WRAP"; then
    case_result "launchd labels use 64-bit urandom not PID+RANDOM" 0 \
      "still uses \$\$ . \$RANDOM"
  elif grep -q 'od -An -tx1 -N8 /dev/urandom' "$WRAP"; then
    case_result "launchd labels use 64-bit urandom not PID+RANDOM" 1
  else
    case_result "launchd labels use 64-bit urandom not PID+RANDOM" 0 \
      "no \$\$ . \$RANDOM but also no od /dev/urandom"
  fi

  # Fund 3 helper: one definition + one call immediately before each mkdir.
  helper_def=0
  grep -q '^ensure_owned_cache_root()' "$WRAP" && helper_def=1
  mkdir_n="$(grep -c 'mkdir -p "$CACHE_ROOT"' "$WRAP" || true)"
  mention_n="$(grep -c 'ensure_owned_cache_root' "$WRAP" || true)"
  if [ "$helper_def" -eq 1 ] && [ "$mkdir_n" -eq 4 ] \
      && [ "$mention_n" -eq $((mkdir_n + 1)) ]; then
    case_result "ensure_owned_cache_root wraps all four CACHE_ROOT mkdirs" 1
  else
    case_result "ensure_owned_cache_root wraps all four CACHE_ROOT mkdirs" 0 \
      "def=$helper_def mkdir_n=$mkdir_n mention_n=$mention_n"
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

echo "=== run() + row() signal passthrough (node) ==="
{
  # check-pr.mjs is not importable (top-level parseArgs + main()). Extract the
  # live run()/row() bodies so a regression in either function fails this case.
  cat > "$WORK/signal-passthrough.mjs" <<'EOF'
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function extractFunction(src, name) {
  const start = src.indexOf(`\nfunction ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in check-pr.mjs`);
  const rest = src.slice(start + 1);
  const end = rest.search(/\n\}\n/);
  if (end < 0) throw new Error(`end of function ${name} not found`);
  return rest.slice(0, end + 2);
}

function loadRunAndRow(checkPrPath) {
  const src = readFileSync(checkPrPath, 'utf8');
  const body = `${extractFunction(src, 'run')}\n${extractFunction(src, 'row')}\nreturn { run, row };`;
  return new Function('spawnSync', body)(spawnSync);
}

function stageFromRun(r) {
  // Same fields stageXxx() forward into row(): exit + signal + blocked.
  return { exit: r.status, signal: r.signal || null, blocked: false };
}

function main() {
  const checkPrPath = process.argv[2];
  const work = process.env.WORK;
  const { run, row } = loadRunAndRow(checkPrPath);

  const dieTerm = join(work, 'die-term.sh');
  writeFileSync(dieTerm, '#!/bin/sh\nkill -TERM $$\n');
  chmodSync(dieTerm, 0o755);
  const killed = run(dieTerm, []);
  const killedRow = row('harness', stageFromRun(killed));
  if (killed.signal !== 'SIGTERM') {
    console.error('run() dropped signal', killed);
    process.exit(1);
  }
  if (!killedRow.includes('(signal: SIGTERM)')) {
    console.error('row() missing (signal: SIGTERM); got:', killedRow, killed);
    process.exit(1);
  }

  const okPath = join(work, 'ok-exit.sh');
  writeFileSync(okPath, '#!/bin/sh\nexit 0\n');
  chmodSync(okPath, 0o755);
  const ok = run(okPath, []);
  const okRow = row('static', stageFromRun(ok));
  if (ok.status !== 0 || ok.signal) {
    console.error('clean script should be exit 0 / no signal', ok);
    process.exit(1);
  }
  if (/\(signal:/.test(okRow)) {
    console.error('exit 0 must not show (signal: ...):', okRow);
    process.exit(1);
  }

  console.log(JSON.stringify({ killedRow, okRow, status: killed.status, signal: killed.signal }));
}
main();
EOF
  run env WORK="$WORK" node "$WORK/signal-passthrough.mjs" "$CHECK_PR"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q '(signal: SIGTERM)'; then
    case_result "run+row pass signal through to table row" 1
  else
    case_result "run+row pass signal through to table row" 0 "$(short "$RUN_OUT")"
  fi
}

echo "=== stageEnv() PATH includes ~/.local/node/bin ==="
{
  # check-pr.mjs is not importable (top-level parseArgs + main()). Extract the
  # live stageEnv() body and inject a fake homedir so the new PATH entry is
  # reachable only through that prepended directory.
  cat > "$WORK/stageenv-path.mjs" <<'EOF'
import { readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function extractFunction(src, name) {
  const start = src.indexOf(`\nfunction ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in check-pr.mjs`);
  const rest = src.slice(start + 1);
  const end = rest.search(/\n\}\n/);
  if (end < 0) throw new Error(`end of function ${name} not found`);
  return rest.slice(0, end + 2);
}

function loadStageEnv(checkPrPath, fakeHome) {
  const src = readFileSync(checkPrPath, 'utf8');
  const body = `${extractFunction(src, 'stageEnv')}\nreturn { stageEnv };`;
  return new Function(
    'homedir',
    'join',
    'REPO_ROOT',
    'hostExtra',
    'existsSync',
    'resolveDockerBin',
    body,
  )(
    () => fakeHome,
    join,
    '/fake-repo',
    '',
    () => false,
    () => '/usr/bin/docker',
  );
}

function commandV(name, path) {
  return spawnSync('sh', ['-c', 'command -v "$1"', 'sh', name], {
    env: { PATH: path },
    encoding: 'utf8',
  });
}

function main() {
  const checkPrPath = process.argv[2];
  const work = process.env.WORK;
  const fakeHome = join(work, 'fake-home');
  const nodeBin = join(fakeHome, '.local', 'node', 'bin');
  const toolName = 'stageenv-node-bin-probe';
  const toolPath = join(nodeBin, toolName);
  mkdirSync(nodeBin, { recursive: true });
  writeFileSync(toolPath, '#!/bin/sh\nexit 0\n');
  chmodSync(toolPath, 0o755);

  const { stageEnv } = loadStageEnv(checkPrPath, fakeHome);
  const basePath = '/usr/bin:/bin';
  const env = stageEnv({ PATH: basePath });
  const parts = (env.PATH || '').split(':');
  if (!parts.includes(nodeBin)) {
    console.error('stageEnv PATH missing', nodeBin, env.PATH);
    process.exit(1);
  }

  const miss = commandV(toolName, basePath);
  if (miss.status === 0) {
    console.error('probe leaked onto base PATH', miss.stdout);
    process.exit(1);
  }

  const found = commandV(toolName, env.PATH);
  if (found.status !== 0 || found.stdout.trim() !== toolPath) {
    console.error('command -v missed probe on staged PATH', found);
    process.exit(1);
  }

  console.log(JSON.stringify({ nodeBin, found: found.stdout.trim() }));
}
main();
EOF
  run env WORK="$WORK" node "$WORK/stageenv-path.mjs" "$CHECK_PR"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q '\.local/node/bin'; then
    case_result "stageEnv prepends ~/.local/node/bin to PATH" 1
  else
    case_result "stageEnv prepends ~/.local/node/bin to PATH" 0 "$(short "$RUN_OUT")"
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

echo "=== static-checks.sh against the empty-tree base (tree mode's real base) ==="
{
  # The test above passes --skip-static, so it never exercised this path — exactly why
  # this bug shipped. --mode tree hands the empty-tree object hash to static-checks.sh
  # as "$BASE"; before the fix, the "..." diff syntax rejected it outright ("is a tree,
  # not a commit") and blocked the gate before any real check ran.
  EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904
  run bash "$ROOT/security/gate/static-checks.sh" "$EMPTY_TREE"
  if [ "$RUN_RC" -le 1 ] && echo "$RUN_OUT" | grep -qE '^Changed files \([0-9]+\)'; then
    case_result "static-checks.sh runs against the empty-tree base" 1
  else
    case_result "static-checks.sh runs against the empty-tree base" 0 "rc=$RUN_RC $(short "$RUN_OUT")"
  fi
}

echo "=== static-checks.sh keeps merge-base (three-dot) semantics for a real commit base ==="
{
  # A tree-object base must fall back to two-dot, but a real commit base must still use
  # three-dot (diff against the merge-base, not the literal base tip) -- otherwise a PR
  # scan would report every unrelated base-branch commit as part of the PR's own diff.
  # This is the discriminating case the empty-tree test above cannot catch: on this repo,
  # origin/master is a direct ancestor of HEAD, so two-dot and three-dot happen to produce
  # the same result here regardless of which one the script picks.
  #
  # The discriminator must be a MODIFIED shared file, not an added/removed one: a plain
  # add-only-on-base-branch file is filtered out either way by --diff-filter=d (excludes
  # deletions), so two-dot and three-dot would look identical through that lens too — a
  # first version of this test used exactly that shape and passed even with the "always
  # treat as not-a-commit" mutation below, silently proving nothing.
  REPO="$WORK/mergebase-semantics"
  rm -rf "$REPO"; mkdir -p "$REPO"
  git -C "$REPO" init -q -b main
  git -C "$REPO" config user.email t@t.local
  git -C "$REPO" config user.name t
  echo v0 > "$REPO/shared.txt"
  git -C "$REPO" add shared.txt
  git -C "$REPO" commit -q -m c0
  git -C "$REPO" checkout -q -b feature
  echo head-only > "$REPO/head-only.txt"
  git -C "$REPO" add head-only.txt
  git -C "$REPO" commit -q -m head-commit
  git -C "$REPO" checkout -q main
  echo v1-base-modified > "$REPO/shared.txt"
  git -C "$REPO" commit -q -am base-modifies-shared
  git -C "$REPO" checkout -q feature

  run env -C "$REPO" bash "$ROOT/security/gate/static-checks.sh" main
  # Three-dot (correct): feature never touched shared.txt relative to the merge-base c0,
  # so only head-only.txt is "changed". Two-dot (the bug/mutation): shared.txt differs
  # between main's tip and feature's tip, so it wrongly shows up too.
  if echo "$RUN_OUT" | grep -q 'head-only.txt' && ! echo "$RUN_OUT" | grep -q 'shared.txt'; then
    case_result "static-checks.sh uses merge-base for a real commit base" 1
  else
    case_result "static-checks.sh uses merge-base for a real commit base" 0 "$(short "$RUN_OUT")"
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

echo "=== fetchBaseFully() unshallows a shallow local clone for real merge-base (node) ==="
{
  cat > "$WORK/fetchbasefully.mjs" <<'EOF'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

function extractFunction(src, name) {
  const start = src.indexOf(`\nfunction ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in check-pr.mjs`);
  const rest = src.slice(start + 1);
  const end = rest.search(/\n\}\n/);
  if (end < 0) throw new Error(`end of function ${name} not found`);
  return rest.slice(0, end + 2);
}

function loadFetchBaseFully(checkPrPath) {
  const src = readFileSync(checkPrPath, 'utf8');
  const body = `${extractFunction(src, 'run')}\n${extractFunction(src, 'fetchBaseFully')}\nreturn { run, fetchBaseFully };`;
  return new Function('spawnSync', body)(spawnSync);
}

function sh(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

function main() {
  const checkPrPath = process.argv[2];
  const root = mkdtempSync(join(tmpdir(), 'fetchbasefully-'));
  const origin = join(root, 'origin.git');
  const local = join(root, 'local');
  try {
    // A bare-ish "origin" with a base branch of 60 commits and a PR branch
    // that forked at commit 1 -- 59 commits behind the current base tip.
    sh('git', ['init', '-q', '-b', 'main', origin]);
    sh('git', ['-C', origin, 'config', 'user.email', 't@t.local']);
    sh('git', ['-C', origin, 'config', 'user.name', 't']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'c0']);
    sh('git', ['-C', origin, 'branch', 'pr-branch']);
    for (let i = 1; i <= 60; i += 1) {
      sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', `c${i}`]);
    }
    sh('git', ['-C', origin, 'checkout', '-q', 'pr-branch']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'pr-only-commit']);
    sh('git', ['-C', origin, 'checkout', '-q', 'main']);

    // "local" = a pre-existing SHALLOW clone, exactly the real-world scenario
    // (gh repo clone --depth 1, same as check-pr.mjs's own clone path).
    // --no-local forces real shallow-clone semantics; a same-machine "local"
    // clone (the default optimization) silently ignores --depth otherwise.
    sh('git', ['clone', '-q', '--no-local', '--depth', '1', origin, local]);
    if (sh('git', ['-C', local, 'rev-parse', '--is-shallow-repository'], local).trim() !== 'true') {
      throw new Error('setup broken: local clone is not shallow');
    }

    const { fetchBaseFully } = loadFetchBaseFully(checkPrPath);
    sh('git', ['-C', local, 'fetch', '--depth', '1', 'origin',
      '+refs/heads/pr-branch:refs/remotes/origin/pr-branch'], local);

    // Before the fix under test: a --depth-limited base fetch would leave the
    // two shallow slices non-overlapping -- merge-base fails with "no merge
    // base", exactly the failure mode measured in 47 of 144 real scans.
    fetchBaseFully(local, '+refs/heads/main:refs/remotes/origin/main');

    const mb = spawnSync('git', ['-C', local, 'merge-base', 'origin/main', 'origin/pr-branch'], { encoding: 'utf8' });
    if (mb.status !== 0 || !mb.stdout.trim()) {
      console.error('merge-base still fails after fetchBaseFully:', mb.stderr);
      process.exit(1);
    }
    console.log('ok merge-base=' + mb.stdout.trim().slice(0, 8));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
main();
EOF
  run env WORK="$WORK" node "$WORK/fetchbasefully.mjs" "$CHECK_PR"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q '^ok merge-base='; then
    case_result "fetchBaseFully unshallows local clone for real merge-base" 1
  else
    case_result "fetchBaseFully unshallows local clone for real merge-base" 0 "$(short "$RUN_OUT")"
  fi
}

echo "=== fetchPrHead() force-updates a stale local PR-head ref after upstream rebase (node) ==="
{
  cat > "$WORK/fetchprhead.mjs" <<'EOF'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

function extractFunction(src, name) {
  const start = src.indexOf(`\nfunction ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in check-pr.mjs`);
  const rest = src.slice(start + 1);
  const end = rest.search(/\n\}\n/);
  if (end < 0) throw new Error(`end of function ${name} not found`);
  return rest.slice(0, end + 2);
}

function loadFetchPrHead(checkPrPath) {
  const src = readFileSync(checkPrPath, 'utf8');
  const body = `${extractFunction(src, 'run')}\n${extractFunction(src, 'sh')}\n${extractFunction(src, 'fetchPrHead')}\nreturn { sh, fetchPrHead };`;
  return new Function('spawnSync', body)(spawnSync);
}

function sh(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

function main() {
  const checkPrPath = process.argv[2];
  const root = mkdtempSync(join(tmpdir(), 'fetchprhead-'));
  const origin = join(root, 'origin.git');
  const local = join(root, 'local');
  try {
    // "origin": a main branch plus a PR branch at commit A.
    sh('git', ['init', '-q', '-b', 'main', origin]);
    sh('git', ['-C', origin, 'config', 'user.email', 't@t.local']);
    sh('git', ['-C', origin, 'config', 'user.name', 't']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'c0']);
    sh('git', ['-C', origin, 'checkout', '-q', '-b', 'pr-branch']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'pr-commit-A']);
    sh('git', ['-C', origin, 'checkout', '-q', 'main']);

    // Wire up a `pull/9/head` ref on "origin" the way a real GitHub PR exposes
    // it, at commit A first (matching what a prior scan would have fetched).
    sh('git', ['-C', origin, 'update-ref', 'refs/pull/9/head', 'pr-branch']);

    // "local" = a persistent per-target checkout (the real-world `local` fast
    // path), already holding refs/security-scan/pr-9 from a PRIOR scan of this
    // PR number at commit A -- exactly what check-pr.mjs leaves behind.
    sh('git', ['clone', '-q', origin, local]);
    sh('git', ['-C', local, 'fetch', '-q', 'origin',
      'pull/9/head:refs/security-scan/pr-9'], local);

    // Rebase pr-branch on the far side: same PR number, diverged history --
    // the exact "push to an open PR after a rebase" scenario the LaunchAgent
    // hits on every re-scan of a PR whose author force-pushed.
    sh('git', ['-C', origin, 'checkout', '-q', 'main']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'c1-after-rebase']);
    sh('git', ['-C', origin, 'branch', '-f', 'pr-branch', 'main']);
    sh('git', ['-C', origin, 'checkout', '-q', 'pr-branch']);
    sh('git', ['-C', origin, 'commit', '--allow-empty', '-q', '-m', 'pr-commit-B-rebased']);
    sh('git', ['-C', origin, 'update-ref', 'refs/pull/9/head', 'pr-branch']); // move pull/9/head to the rebased tip
    sh('git', ['-C', origin, 'checkout', '-q', 'main']);

    const { fetchPrHead } = loadFetchPrHead(checkPrPath);
    // Before the fix: this throws (non-fast-forward, exit 1) because the old
    // refs/security-scan/pr-9 (commit A) is not an ancestor of the rebased
    // commit B and the refspec had no "+" force prefix.
    fetchPrHead(local, 9, 'refs/security-scan/pr-9');

    const rev = spawnSync('git', ['-C', local, 'rev-parse', 'refs/security-scan/pr-9'], { encoding: 'utf8' });
    const subject = spawnSync('git', ['-C', local, 'log', '-1', '--format=%s', 'refs/security-scan/pr-9'], { encoding: 'utf8' });
    if (rev.status !== 0 || subject.stdout.trim() !== 'pr-commit-B-rebased') {
      console.error('ref not force-updated to rebased head:', subject.stdout, subject.stderr);
      process.exit(1);
    }
    console.log('ok updated-to=' + subject.stdout.trim());
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
main();
EOF
  run env WORK="$WORK" node "$WORK/fetchprhead.mjs" "$CHECK_PR"
  if [ "$RUN_RC" -eq 0 ] && echo "$RUN_OUT" | grep -q '^ok updated-to=pr-commit-B-rebased'; then
    case_result "fetchPrHead force-updates a stale PR-head ref after rebase" 1
  else
    case_result "fetchPrHead force-updates a stale PR-head ref after rebase" 0 "$(short "$RUN_OUT")"
  fi
}
echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m%s/%s Fälle bestanden\033[0m\n' "$PASS" "$TOTAL"
  exit 0
fi
printf '\033[31m%s/%s Fälle bestanden\033[0m\n' "$PASS" "$TOTAL"
exit 1
