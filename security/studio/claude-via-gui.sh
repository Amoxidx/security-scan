#!/usr/bin/env bash
#
# Run the subscription coding-agent CLI so SSH / agent sessions can use a
# GUI-login keychain session.
#
# On macOS, `claude auth login` stores OAuth in the login keychain. Non-interactive
# SSH often cannot read that item ("User interaction is not allowed"), so
# `claude auth status` reports loggedIn:false even when the user is signed in.
# Jobs started in the Aqua GUI domain (launchctl gui/$UID) can read the keychain.
#
# Usage (same as `claude -p`):
#   claude-via-gui.sh -p --model sonnet   # prompt on stdin, answer on stdout
#   claude-via-gui.sh --studio-auth-check # exit 0 if auth works (direct or GUI)
#
# Env:
#   CLAUDE_BIN                 real claude binary (default: first real binary on PATH)
#   SECURITY_CLAUDE_GUI_FORCE  1 = always use GUI domain (even if direct auth works)
#   SECURITY_CLAUDE_GUI_TIMEOUT_S  wall clock for one GUI job (default: 300)
#   SECURITY_CLAUDE_GUI_RETRIES    extra run_via_gui attempts after an
#                                  empty-stdout AND empty-stderr exit != 0
#                                  (default: 2; set 0 to disable).
#                                  Retry assumes empty stdout+stderr means
#                                  the job had no side effects — true for
#                                  the current use (read-only text review
#                                  prompt, no tool-calls), but wrong if this
#                                  wrapper ever ran a job with real file or
#                                  network writes.
#   SECURITY_CLAUDE_GUI_CACHE      override marker/work cache
#                                  (default: ~/.cache/security-claude-gui)
#   SECURITY_CLAUDE_GUI_FAILURE_MAX_AGE_S
#                                  --studio-auth-check mentions last-failure.json
#                                  younger than this (default: 3600)
#
# last-failure.json reflects the most recent event across ALL concurrent
# invocations of this script, not just this process — a concurrent success
# can clear a failure written moments earlier by another instance.
#
# Exit: passes through claude's exit code; 3 = setup error (no binary / no GUI session).

set -euo pipefail
umask 077

SELF_NAME="$(basename "$0")"
CACHE_ROOT="${SECURITY_CLAUDE_GUI_CACHE:-${HOME:-/tmp}/.cache/security-claude-gui}"
FAILURE_MARKER="${CACHE_ROOT}/last-failure.json"
TIMEOUT_S="${SECURITY_CLAUDE_GUI_TIMEOUT_S:-300}"
FAILURE_MAX_AGE_S="${SECURITY_CLAUDE_GUI_FAILURE_MAX_AGE_S:-3600}"
FAIL_STAGE="setup"

# Populated by the auth probes so --studio-auth-check can name the failing stage.
DIRECT_AUTH_CODE=""
DIRECT_AUTH_ERR=""
GUI_AUTH_CODE=""
GUI_AUTH_ERR=""
GUI_AUTH_REASON=""

die() {
  echo "claude-via-gui: $*" >&2
  # Skip when the cache itself is unusable: writing the marker would recurse
  # (die → marker → owner check → die) and persist into a foreign directory.
  if [ "${SKIP_FAILURE_MARKER:-0}" != "1" ]; then
    write_failure_marker "${FAIL_STAGE}" "$*"
  fi
  exit 3
}

is_darwin() { [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]; }

is_nonneg_int() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

# Refuse a pre-existing CACHE_ROOT that is not owned by this user. mkdir
# stays at each call site so best-effort vs fail-loud is unchanged.
ensure_owned_cache_root() {
  [ -e "$CACHE_ROOT" ] || return 0
  local owner
  owner="$(stat -f %u "$CACHE_ROOT" 2>/dev/null || stat -c %u "$CACHE_ROOT" 2>/dev/null || true)"
  if [ "$owner" != "$(id -u)" ]; then
    SKIP_FAILURE_MARKER=1
    die "cache dir ${CACHE_ROOT} exists but is not owned by the current user — refusing to use it"
  fi
}

# 64 bits from /dev/urandom (16 hex chars). PID is a debug suffix only.
gui_job_label() {
  local kind="$1" hex
  hex="$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
  if [ "${#hex}" -ne 16 ]; then
    die "failed to read 64 bits of entropy for launchd label"
  fi
  printf 'com.amoxidx.claude-%s.%s.%s' "$kind" "$$" "$hex"
}

# One-line, quote-free text for marker JSON (no tokens; truncate).
sanitize_text() {
  local s lowered
  s="$(printf '%s' "${1:-}" | tr '\n\r\t' '   ' | tr -d '\000-\037\177')"
  lowered="$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
  # JWT on the original (eyJ is case-sensitive). Other heuristics after lowercasing
  # so camelCase keys (accessToken, apiKey, sessionToken) match the snake_case forms.
  if printf '%s' "$s" | grep -qE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
      || printf '%s' "$lowered" | grep -qE 'bearer [a-z0-9._~+/=-]+|authorization:[[:space:]]*bearer |sk-[a-z0-9-]{8,}|"?[a-z_]*api[_-]?key"?[[:space:]]*[=:]|"?[a-z_]*(access|refresh)[_-]?token"?[[:space:]]*[=:]|"?[a-z_]*session[_-]?token"?[[:space:]]*[=:]|"?[a-z_]*(token|password|secret)"?[[:space:]]*[=:]'; then
    s='[redacted]'
  fi
  printf '%s' "$s" | tr -d '\\"' | cut -c1-400
}

write_failure_marker() {
  local stage="$1" message="$2" ts tmp
  ensure_owned_cache_root
  mkdir -p "$CACHE_ROOT" 2>/dev/null || return 0
  chmod 700 "$CACHE_ROOT" 2>/dev/null || true
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  stage="$(sanitize_text "$stage")"
  message="$(sanitize_text "$message")"
  tmp="$(mktemp "${CACHE_ROOT}/.last-failure.XXXXXX" 2>/dev/null)" || return 0
  if ! printf '{"ts":"%s","stage":"%s","message":"%s"}\n' "$ts" "$stage" "$message" \
      > "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$FAILURE_MARKER" 2>/dev/null || { rm -f "$tmp"; return 0; }
}

clear_failure_marker() {
  rm -f "$FAILURE_MARKER" 2>/dev/null || true
}

json_get() {
  local file="$1" key="$2"
  [ -f "$file" ] || return 1
  sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -1
}

iso_to_epoch() {
  local ts="$1"
  date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$ts" "+%s" 2>/dev/null && return 0
  date -u -d "$ts" "+%s" 2>/dev/null && return 0
  return 1
}

# Prints "letzter Fehlschlag vor N Minuten: <message>" when the marker is fresh.
recent_failure_note() {
  local ts stage message then now age mins max_age
  [ -f "$FAILURE_MARKER" ] || return 1
  ts="$(json_get "$FAILURE_MARKER" ts)"
  stage="$(json_get "$FAILURE_MARKER" stage)"
  message="$(json_get "$FAILURE_MARKER" message)"
  [ -n "$ts" ] || return 1
  then="$(iso_to_epoch "$ts")" || return 1
  now="$(date -u +%s)"
  age=$((now - then))
  [ "$age" -lt 0 ] && age=0
  max_age="$FAILURE_MAX_AGE_S"
  is_nonneg_int "$max_age" || max_age=3600
  [ "$age" -lt "$max_age" ] || return 1
  mins=$((age / 60))
  if [ -z "$message" ]; then
    message="stage ${stage:-unknown}"
  fi
  if [ "$mins" -lt 1 ]; then
    printf 'letzter Fehlschlag vor weniger als 1 Minute: %s' "$message"
  else
    printf 'letzter Fehlschlag vor %s Minuten: %s' "$mins" "$message"
  fi
}

empty_stderr_hint() {
  local code="$1"
  printf 'claude exited %s with empty stderr — likely keychain access denied or GUI session unavailable, run '\''claude auth login'\'' interactively on the Studio desktop once' "$code"
}

# Always emit a non-empty stderr line: stage, exit code, err body or explicit empty hint.
fail_loud() {
  local stage="$1" code="$2" err="${3:-}" extra="${4:-}"
  local body msg
  FAIL_STAGE="$stage"
  if [ -n "$err" ]; then
    body="$(printf '%s' "$err" | tr '\n' ' ' | cut -c1-400)"
  else
    body="$(empty_stderr_hint "$code")"
  fi
  msg="${stage} failed: exit ${code}: ${body}"
  [ -n "$extra" ] && msg="${msg} (${extra})"
  echo "claude-via-gui: ${msg}" >&2
  write_failure_marker "$stage" "$msg"
}

find_real_claude() {
  if [ -n "${CLAUDE_BIN:-}" ] && [ -x "${CLAUDE_BIN}" ]; then
    echo "${CLAUDE_BIN}"
    return 0
  fi
  local cand base
  # Prefer user install, then brew cask, then PATH — never this wrapper.
  for cand in \
    "${HOME}/.local/bin/claude" \
    /opt/homebrew/bin/claude \
    /usr/local/bin/claude
  do
    [ -x "$cand" ] || continue
    base="$(basename "$cand")"
    [ "$base" = "claude-via-gui" ] && continue
    [ "$base" = "$SELF_NAME" ] && continue
    # Symlink that points at this wrapper → skip.
    if [ -L "$cand" ]; then
      case "$(readlink "$cand" 2>/dev/null || true)" in
        *claude-via-gui*) continue ;;
      esac
    fi
    # Shebang scripts that are our wrapper.
    if head -n 3 "$cand" 2>/dev/null | grep -q 'claude-via-gui'; then
      continue
    fi
    echo "$cand"
    return 0
  done
  if command -v claude >/dev/null 2>&1; then
    cand="$(command -v claude)"
    case "$cand" in
      *claude-via-gui*) ;;
      *) echo "$cand"; return 0 ;;
    esac
  fi
  return 1
}

# Returns 0 when this process can already use the subscription login.
direct_auth_ok() {
  local bin="$1" out errfile rc=0
  FAIL_STAGE="direct_auth_ok"
  errfile="$(mktemp "${TMPDIR:-/tmp}/cvg-auth-err.XXXXXX")"
  out="$("$bin" auth status 2>"$errfile")" || rc=$?
  DIRECT_AUTH_CODE="$rc"
  DIRECT_AUTH_ERR="$(cat "$errfile" 2>/dev/null || true)"
  rm -f "$errfile"
  printf '%s' "$out" | grep -q '"loggedIn"[[:space:]]*:[[:space:]]*true'
}

# Probe auth through a short GUI-domain job (writes status JSON to a file).
gui_auth_ok() {
  local bin="$1" work label uidn plist runner
  FAIL_STAGE="gui_auth_ok"
  GUI_AUTH_CODE=""
  GUI_AUTH_ERR=""
  GUI_AUTH_REASON=""
  if ! is_darwin; then
    GUI_AUTH_REASON="not Darwin"
    return 1
  fi
  uidn="$(id -u)"
  if ! command -v launchctl >/dev/null 2>&1; then
    GUI_AUTH_REASON="launchctl not available"
    return 1
  fi
  # Need an active Aqua session for this UID.
  if ! launchctl print "gui/${uidn}" >/dev/null 2>&1; then
    GUI_AUTH_REASON="no active GUI session for uid ${uidn}"
    return 1
  fi

  ensure_owned_cache_root
  mkdir -p "$CACHE_ROOT"
  chmod 700 "$CACHE_ROOT" 2>/dev/null || true
  work="$(mktemp -d "${CACHE_ROOT}/auth-XXXXXX")"
  label="$(gui_job_label auth)"
  runner="${work}/run.sh"
  plist="${work}/job.plist"

  cat >"$runner" <<EOF
#!/bin/zsh
export HOME="${HOME}"
export USER="${USER:-$(id -un)}"
export PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
"$bin" auth status >"${work}/status.json" 2>"${work}/status.err"
echo \$? >"${work}/code"
EOF
  chmod 700 "$runner"

  # Minimal plist (no external DOCTYPE) — launchctl does not need a DTD reference.
  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>
    <string>${runner}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>WorkingDirectory</key><string>${HOME}</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>${HOME}</string>
    <key>USER</key><string>${USER:-$(id -un)}</string>
    <key>PATH</key><string>${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict></plist>
EOF

  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
  if ! launchctl bootstrap "gui/${uidn}" "$plist" >/dev/null 2>&1; then
    GUI_AUTH_REASON="launchctl bootstrap failed"
    rm -rf "$work"
    return 1
  fi

  local i=0
  while [ "$i" -lt 30 ]; do
    [ -f "${work}/code" ] && break
    sleep 0.2
    i=$((i + 1))
  done
  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true

  if [ -f "${work}/code" ]; then
    GUI_AUTH_CODE="$(tr -d '[:space:]' < "${work}/code" 2>/dev/null || true)"
  fi
  if [ -f "${work}/status.err" ]; then
    GUI_AUTH_ERR="$(cat "${work}/status.err" 2>/dev/null || true)"
  fi

  if [ ! -f "${work}/status.json" ]; then
    GUI_AUTH_REASON="${GUI_AUTH_REASON:-status.json missing}"
    rm -rf "$work"
    return 1
  fi
  if grep -q '"loggedIn"[[:space:]]*:[[:space:]]*true' "${work}/status.json"; then
    rm -rf "$work"
    return 0
  fi
  GUI_AUTH_REASON="loggedIn is not true"
  rm -rf "$work"
  return 1
}

# One launchd job against an already-prepared $work dir. Sets JOB_CODE (empty on timeout).
submit_gui_job() {
  local work="$1" uidn="$2" label plist
  plist="${work}/job.plist"
  label="$(gui_job_label run)"
  JOB_CODE=""

  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>
    <string>${work}/run.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>WorkingDirectory</key><string>${HOME}</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>${HOME}</string>
    <key>USER</key><string>${USER:-$(id -un)}</string>
    <key>PATH</key><string>${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict></plist>
EOF

  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
  if ! launchctl bootstrap "gui/${uidn}" "$plist" >/dev/null 2>&1; then
    launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
    return 1
  fi

  local waited=0
  while [ "$waited" -lt "$TIMEOUT_S" ]; do
    if [ -f "${work}/code" ]; then
      JOB_CODE="$(tr -d '[:space:]' < "${work}/code" 2>/dev/null || echo 1)"
      [ -n "$JOB_CODE" ] || JOB_CODE=1
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
  return 0
}

run_via_gui() {
  local bin="$1"
  shift
  local work uidn runner retries attempt max_attempts
  FAIL_STAGE="run_via_gui"
  is_darwin || die "GUI fallback only available on macOS"
  uidn="$(id -u)"
  command -v launchctl >/dev/null 2>&1 || die "launchctl not available"
  launchctl print "gui/${uidn}" >/dev/null 2>&1 || die "no active GUI session for uid ${uidn} (log into the Mac desktop once)"

  ensure_owned_cache_root
  mkdir -p "$CACHE_ROOT" 2>/dev/null || die "cache dir ${CACHE_ROOT} not writable"
  chmod 700 "$CACHE_ROOT" 2>/dev/null || true
  work="$(mktemp -d "${CACHE_ROOT}/run-XXXXXX" 2>/dev/null)" || die "mktemp -d failed in ${CACHE_ROOT}"
  runner="${work}/run.sh"

  # Persist argv (one line per arg; empty args not used by claude -p).
  : >"${work}/args.txt"
  local a
  for a in "$@"; do
    printf '%s\n' "$a" >>"${work}/args.txt"
  done
  # Prompt from our stdin.
  cat >"${work}/prompt.txt"

  cat >"$runner" <<EOF
#!/bin/zsh
set -uo pipefail
export HOME="${HOME}"
export USER="${USER:-$(id -un)}"
export PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
ARGS=()
while IFS= read -r line || [ -n "\$line" ]; do
  ARGS+=("\$line")
done < "${work}/args.txt"
"$bin" "\${ARGS[@]}" < "${work}/prompt.txt" > "${work}/out.txt" 2> "${work}/err.txt"
echo \$? > "${work}/code"
EOF
  chmod 700 "$runner"

  retries="${SECURITY_CLAUDE_GUI_RETRIES:-2}"
  is_nonneg_int "$retries" || retries=2
  max_attempts=$((retries + 1))
  [ "$max_attempts" -ge 1 ] || max_attempts=1

  attempt=0
  local code="" err_txt="" out_empty err_empty
  while [ "$attempt" -lt "$max_attempts" ]; do
    attempt=$((attempt + 1))
    rm -f "${work}/code" "${work}/out.txt" "${work}/err.txt"
    code=""
    JOB_CODE=""

    if ! submit_gui_job "$work" "$uidn"; then
      rm -rf "$work"
      die "launchctl bootstrap gui/${uidn} failed"
    fi
    code="$JOB_CODE"

    if [ -z "$code" ]; then
      # Timeout is not the empty-stderr race — do not retry.
      if [ -f "${work}/err.txt" ]; then
        echo "claude-via-gui: GUI job timed out after ${TIMEOUT_S}s" >&2
        head -c 500 "${work}/err.txt" >&2 || true
      fi
      err_txt="$(cat "${work}/err.txt" 2>/dev/null || true)"
      rm -rf "$work"
      if [ -n "$err_txt" ]; then
        die "GUI claude job timed out after ${TIMEOUT_S}s"
      fi
      die "GUI claude job timed out after ${TIMEOUT_S}s ($(empty_stderr_hint timeout))"
    fi

    if [ "$code" = "0" ]; then
      if [ -f "${work}/out.txt" ]; then
        cat "${work}/out.txt"
      fi
      clear_failure_marker
      rm -rf "$work"
      return 0
    fi

    out_empty=1
    err_empty=1
    [ -s "${work}/out.txt" ] && out_empty=0
    [ -s "${work}/err.txt" ] && err_empty=0

    # Retry only the empty-stdout+empty-stderr + exit!=0 race, not a real model error.
    if [ "$out_empty" -eq 1 ] && [ "$err_empty" -eq 1 ] && [ "$attempt" -lt "$max_attempts" ]; then
      sleep 2
      continue
    fi
    break
  done

  if [ -f "${work}/out.txt" ]; then
    cat "${work}/out.txt"
  fi
  err_txt=""
  if [ -f "${work}/err.txt" ]; then
    err_txt="$(cat "${work}/err.txt" 2>/dev/null || true)"
  fi
  local extra=""
  [ "$attempt" -gt 1 ] && extra="after ${attempt} attempts"
  fail_loud "run_via_gui" "$code" "$err_txt" "$extra"
  local rc="$code"
  rm -rf "$work"
  return "$rc"
}

# Direct invocation (success path or last resort). Never exec: we need the marker
# and a non-empty diagnostic when the binary exits non-zero with empty stderr.
run_direct() {
  local bin="$1"
  shift
  local errf rc=0 err_txt
  FAIL_STAGE="run_direct"
  ensure_owned_cache_root
  mkdir -p "$CACHE_ROOT" 2>/dev/null || die "cache dir ${CACHE_ROOT} not writable"
  chmod 700 "$CACHE_ROOT" 2>/dev/null || true
  errf="$(mktemp "${CACHE_ROOT}/direct-err-XXXXXX" 2>/dev/null)" || die "mktemp failed in ${CACHE_ROOT}"
  "$bin" "$@" 2>"$errf" || rc=$?
  if [ "$rc" -eq 0 ]; then
    if [ -s "$errf" ]; then
      cat "$errf" >&2
    fi
    rm -f "$errf"
    clear_failure_marker
    return 0
  fi
  err_txt="$(cat "$errf" 2>/dev/null || true)"
  rm -f "$errf"
  fail_loud "run_direct" "$rc" "$err_txt"
  return "$rc"
}

emit_auth_check_success() {
  local how="$1" note
  note="$(recent_failure_note || true)"
  if [ -n "$note" ]; then
    echo "claude-via-gui: auth ok (${how}), but ${note}"
  else
    echo "claude-via-gui: auth ok (${how})"
  fi
  clear_failure_marker
}

# ---------------------------------------------------------------- main

REAL="$(find_real_claude)" || die "claude binary not found (install the coding-agent CLI, or set CLAUDE_BIN)"

if [ "${1:-}" = "--studio-auth-check" ]; then
  if direct_auth_ok "$REAL"; then
    emit_auth_check_success "direct"
    exit 0
  fi
  if gui_auth_ok "$REAL"; then
    emit_auth_check_success "GUI session"
    exit 0
  fi
  echo "claude-via-gui: auth unavailable (direct and GUI probe failed — run: claude auth login on the Studio desktop)" >&2
  # Name both stages so an empty probe no longer yields "exited 1:".
  direct_msg="${DIRECT_AUTH_ERR:-}"
  if [ -z "$direct_msg" ]; then
    if [ -n "${DIRECT_AUTH_CODE:-}" ] && [ "${DIRECT_AUTH_CODE}" != "0" ]; then
      direct_msg="$(empty_stderr_hint "${DIRECT_AUTH_CODE}")"
    else
      direct_msg="loggedIn is not true"
    fi
  fi
  echo "claude-via-gui: direct_auth_ok failed: exit ${DIRECT_AUTH_CODE:-unknown}: ${direct_msg}" >&2
  gui_msg="${GUI_AUTH_ERR:-}"
  if [ -z "$gui_msg" ]; then
    gui_msg="${GUI_AUTH_REASON:-$(empty_stderr_hint "${GUI_AUTH_CODE:-1}")}"
  elif [ -n "$GUI_AUTH_REASON" ]; then
    gui_msg="${GUI_AUTH_REASON}: ${gui_msg}"
  fi
  echo "claude-via-gui: gui_auth_ok failed: exit ${GUI_AUTH_CODE:-unknown}: ${gui_msg}" >&2
  write_failure_marker "gui_auth_ok" "auth unavailable; direct_auth_ok exit ${DIRECT_AUTH_CODE:-unknown}; gui_auth_ok ${GUI_AUTH_REASON:-exit ${GUI_AUTH_CODE:-unknown}}"
  exit 1
fi

FORCE_GUI="${SECURITY_CLAUDE_GUI_FORCE:-0}"

if [ "$FORCE_GUI" != "1" ] && direct_auth_ok "$REAL"; then
  run_direct "$REAL" "$@"
  exit $?
fi

if is_darwin && launchctl print "gui/$(id -u)" >/dev/null 2>&1; then
  # Prefer GUI when direct auth is false (typical SSH) or forced.
  run_via_gui "$REAL" "$@"
  exit $?
fi

# Last resort: invoke real binary (may fail auth the same way).
run_direct "$REAL" "$@"
exit $?
