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
#
# Exit: passes through claude's exit code; 3 = setup error (no binary / no GUI session).

set -euo pipefail

SELF_NAME="$(basename "$0")"
CACHE_ROOT="${HOME:-/tmp}/.cache/security-claude-gui"
TIMEOUT_S="${SECURITY_CLAUDE_GUI_TIMEOUT_S:-300}"

die() { echo "claude-via-gui: $*" >&2; exit 3; }

is_darwin() { [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]; }

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
  local bin="$1" out
  out="$("$bin" auth status 2>/dev/null || true)"
  printf '%s' "$out" | grep -q '"loggedIn"[[:space:]]*:[[:space:]]*true'
}

# Probe auth through a short GUI-domain job (writes status JSON to a file).
gui_auth_ok() {
  local bin="$1" work label uidn plist runner code
  is_darwin || return 1
  uidn="$(id -u)"
  command -v launchctl >/dev/null 2>&1 || return 1
  # Need an active Aqua session for this UID.
  launchctl print "gui/${uidn}" >/dev/null 2>&1 || return 1

  mkdir -p "$CACHE_ROOT"
  work="$(mktemp -d "${CACHE_ROOT}/auth-XXXXXX")"
  label="com.amoxidx.claude-auth.$$.$RANDOM"
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

  if [ ! -f "${work}/status.json" ]; then
    rm -rf "$work"
    return 1
  fi
  if grep -q '"loggedIn"[[:space:]]*:[[:space:]]*true' "${work}/status.json"; then
    rm -rf "$work"
    return 0
  fi
  rm -rf "$work"
  return 1
}

run_via_gui() {
  local bin="$1"
  shift
  local work label uidn plist runner
  is_darwin || die "GUI fallback only available on macOS"
  uidn="$(id -u)"
  command -v launchctl >/dev/null 2>&1 || die "launchctl not available"
  launchctl print "gui/${uidn}" >/dev/null 2>&1 || die "no active GUI session for uid ${uidn} (log into the Mac desktop once)"

  mkdir -p "$CACHE_ROOT"
  work="$(mktemp -d "${CACHE_ROOT}/run-XXXXXX")"
  label="com.amoxidx.claude-run.$$.$RANDOM"
  runner="${work}/run.sh"
  plist="${work}/job.plist"

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
    rm -rf "$work"
    die "launchctl bootstrap gui/${uidn} failed"
  fi

  local waited=0 code=""
  while [ "$waited" -lt "$TIMEOUT_S" ]; do
    if [ -f "${work}/code" ]; then
      code="$(cat "${work}/code" 2>/dev/null || echo 1)"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true

  if [ -z "$code" ]; then
    # Best-effort dump for diagnosis (no secrets expected in stderr).
    if [ -f "${work}/err.txt" ]; then
      echo "claude-via-gui: GUI job timed out after ${TIMEOUT_S}s" >&2
      head -c 500 "${work}/err.txt" >&2 || true
    fi
    rm -rf "$work"
    die "GUI claude job timed out after ${TIMEOUT_S}s"
  fi

  if [ -f "${work}/out.txt" ]; then
    cat "${work}/out.txt"
  fi
  if [ "$code" != "0" ] && [ -f "${work}/err.txt" ]; then
    cat "${work}/err.txt" >&2
  fi
  local rc="$code"
  rm -rf "$work"
  return "$rc"
}

# ---------------------------------------------------------------- main

REAL="$(find_real_claude)" || die "claude binary not found (install the coding-agent CLI, or set CLAUDE_BIN)"

if [ "${1:-}" = "--studio-auth-check" ]; then
  if direct_auth_ok "$REAL"; then
    echo "claude-via-gui: auth ok (direct)"
    exit 0
  fi
  if gui_auth_ok "$REAL"; then
    echo "claude-via-gui: auth ok (GUI session)"
    exit 0
  fi
  echo "claude-via-gui: auth unavailable (direct and GUI probe failed — run: claude auth login on the Studio desktop)" >&2
  exit 1
fi

FORCE_GUI="${SECURITY_CLAUDE_GUI_FORCE:-0}"

if [ "$FORCE_GUI" != "1" ] && direct_auth_ok "$REAL"; then
  exec "$REAL" "$@"
fi

if is_darwin && launchctl print "gui/$(id -u)" >/dev/null 2>&1; then
  # Prefer GUI when direct auth is false (typical SSH) or forced.
  run_via_gui "$REAL" "$@"
  exit $?
fi

# Last resort: invoke real binary (may fail auth the same way).
exec "$REAL" "$@"
