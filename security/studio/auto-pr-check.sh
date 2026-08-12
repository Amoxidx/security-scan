#!/usr/bin/env bash
#
# Auto-run Studio security checks on ready-for-review PRs (non-draft, open).
#
# Default: ON when the LaunchAgent is installed.
# Disable (without uninstalling launchd):
#   security/studio/auto-pr-check.sh --off
#   # or: touch ~/.config/security-scan/auto-pr-check.off
#   # or: SECURITY_SCAN_AUTO_PR_CHECK=0
# Re-enable:
#   security/studio/auto-pr-check.sh --on
#
# Usage:
#   auto-pr-check.sh --once|--run     one tick (launchd calls --run)
#   auto-pr-check.sh --status
#   auto-pr-check.sh --on|--off
#   auto-pr-check.sh --install-agent  install launchd (default ON)
#   auto-pr-check.sh --uninstall-agent
#
# Exit: 0 always for launchd hygiene unless setup is broken (then 3).

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CFG_FILE="${SECURITY_SCAN_AUTO_CONFIG:-$ROOT/security/studio/auto-pr-check.config.json}"
TARGETS_FILE="$ROOT/security/studio/targets.json"
CHECK_PR="$ROOT/security/studio/check-pr.mjs"
STATE_DIR="${SECURITY_SCAN_AUTO_STATE_DIR:-$HOME/.cache/security-scan/auto-pr-check}"
STATE_FILE="$STATE_DIR/state.json"
LOG_DIR="$STATE_DIR/logs"
OFF_FILE="${SECURITY_SCAN_AUTO_OFF_FILE:-$HOME/.config/security-scan/auto-pr-check.off}"
PLIST_LABEL_DEFAULT="com.amoxidx.security-scan-auto-pr"
PLIST_PATH="${HOME}/Library/LaunchAgents/${PLIST_LABEL_DEFAULT}.plist"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$(dirname "$OFF_FILE")" 2>/dev/null || true

log() { printf '%s %s\n' "$(date -Iseconds 2>/dev/null || date)" "$*" | tee -a "$LOG_DIR/auto-pr-check.log" >&2; }

die() { log "ERROR: $*"; exit 3; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

cfg_get() {
  # cfg_get <jq-path> [default]
  local path="$1" def="${2:-}"
  if [ ! -f "$CFG_FILE" ]; then
    printf '%s' "$def"
    return
  fi
  python3 - "$CFG_FILE" "$path" "$def" <<'PY'
import json, sys
cfg_path, path, default = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(cfg_path) as f:
        d = json.load(f)
except Exception:
    print(default)
    raise SystemExit
cur = d
for part in path.split("."):
    if not isinstance(cur, dict) or part not in cur:
        print(default)
        raise SystemExit
    cur = cur[part]
if isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, list):
    print("\n".join(str(x) for x in cur))
else:
    print(cur if cur is not None else default)
PY
}

is_disabled() {
  # Explicit env wins: 0/false/off → disabled; 1/true/on → enabled
  case "${SECURITY_SCAN_AUTO_PR_CHECK:-}" in
    0|false|FALSE|off|OFF|no|NO) return 0 ;;
    1|true|TRUE|on|ON|yes|YES) return 1 ;;
  esac
  # File kill switch (JK pattern: *.off means disabled)
  if [ -f "$OFF_FILE" ]; then
    return 0
  fi
  return 1
}

cmd_on() {
  rm -f "$OFF_FILE"
  log "auto-pr-check ENABLED (removed $OFF_FILE)"
  echo "auto-pr-check: ON (default). Kill switch cleared."
}

cmd_off() {
  mkdir -p "$(dirname "$OFF_FILE")"
  date -Iseconds >"$OFF_FILE" 2>/dev/null || date >"$OFF_FILE"
  echo "disabled $(date -Iseconds 2>/dev/null || date)" >>"$OFF_FILE"
  log "auto-pr-check DISABLED (wrote $OFF_FILE)"
  echo "auto-pr-check: OFF. Remove $OFF_FILE or run --on to re-enable."
}

cmd_status() {
  local agent="not-installed" disabled="no"
  if [ -f "$PLIST_PATH" ]; then
    if launchctl print "gui/$(id -u)/${PLIST_LABEL_DEFAULT}" >/dev/null 2>&1; then
      agent="loaded"
    else
      agent="installed-not-loaded"
    fi
  fi
  if is_disabled; then disabled="yes"; fi
  echo "auto-pr-check status"
  echo "  kill_switch_file: $OFF_FILE"
  echo "  disabled:         $disabled"
  echo "  env SECURITY_SCAN_AUTO_PR_CHECK=${SECURITY_SCAN_AUTO_PR_CHECK:-<unset>}"
  echo "  launch_agent:     $agent"
  echo "  plist:            $PLIST_PATH"
  echo "  config:           $CFG_FILE"
  echo "  state:            $STATE_FILE"
  echo "  targets:"
  cfg_get targets | sed 's/^/    - /'
  if [ -f "$STATE_FILE" ]; then
    echo "  last_state_keys: $(python3 -c "import json;d=json.load(open('$STATE_FILE'));print(len(d.get('checked',{})))" 2>/dev/null || echo 0)"
  fi
  if is_disabled; then
    echo "  effective:        SKIP (disabled)"
  elif [ "$agent" = "loaded" ]; then
    echo "  effective:        ON (launchd + no kill switch)"
  else
    echo "  effective:        idle (no kill switch; install agent with --install-agent)"
  fi
}

write_plist() {
  local interval root label
  interval="$(cfg_get intervalSeconds 1800)"
  root="$ROOT"
  label="$PLIST_LABEL_DEFAULT"
  mkdir -p "$(dirname "$PLIST_PATH")"
  # Minimal plist — no external DOCTYPE (static host gate).
  cat >"$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${root}/security/studio/auto-pr-check.sh</string>
    <string>--run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${root}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${HOME}</string>
    <key>USER</key>
    <string>${USER:-$(id -un)}</string>
    <key>PATH</key>
    <string>${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>OLLAMA_API_KEY</key>
    <string>ollama</string>
  </dict>
  <key>StartInterval</key>
  <integer>${interval}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/launchd.err.log</string>
</dict>
</plist>
EOF
}

cmd_install_agent() {
  need launchctl
  write_plist
  local uidn label
  uidn="$(id -u)"
  label="$PLIST_LABEL_DEFAULT"
  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/${uidn}" "$PLIST_PATH" || die "launchctl bootstrap failed"
  # Ensure default ON
  rm -f "$OFF_FILE"
  log "installed and loaded $label (interval=$(cfg_get intervalSeconds 1800)s); kill switch OFF file cleared"
  echo "Installed LaunchAgent $label → $PLIST_PATH"
  echo "Default: ON. Disable: $0 --off"
  cmd_status
}

cmd_uninstall_agent() {
  local uidn label
  uidn="$(id -u)"
  label="$PLIST_LABEL_DEFAULT"
  launchctl bootout "gui/${uidn}/${label}" >/dev/null 2>&1 || true
  rm -f "$PLIST_PATH"
  log "uninstalled $label"
  echo "Uninstalled LaunchAgent $label"
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    cat "$STATE_FILE"
  else
    echo '{"checked":{}}'
  fi
}

save_checked() {
  local key="$1" head="$2" exit_code="$3" when
  when="$(date -Iseconds 2>/dev/null || date)"
  python3 - "$STATE_FILE" "$key" "$head" "$exit_code" "$when" <<'PY'
import json, sys, os
path, key, head, exit_code, when = sys.argv[1:6]
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    d = {"checked": {}}
d.setdefault("checked", {})[key] = {
    "headRefOid": head,
    "exitCode": int(exit_code),
    "at": when,
}
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
}

already_checked() {
  local key="$1" head="$2"
  python3 - "$STATE_FILE" "$key" "$head" <<'PY'
import json, sys
path, key, head = sys.argv[1:4]
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    raise SystemExit(1)
entry = d.get("checked", {}).get(key) or {}
raise SystemExit(0 if entry.get("headRefOid") == head else 1)
PY
}

list_ready_prs() {
  local repo="$1"
  local include
  include="$(cfg_get includeDrafts false)"
  # Open PRs only; filter drafts unless includeDrafts=true.
  INCLUDE_DRAFTS="$include" gh pr list --repo "$repo" --state open --limit 40 \
    --json number,title,isDraft,headRefOid,url,updatedAt 2>/dev/null \
    | INCLUDE_DRAFTS="$include" python3 -c '
import json, os, sys
include = os.environ.get("INCLUDE_DRAFTS", "false") == "true"
raw = sys.stdin.read()
try:
    prs = json.loads(raw) if raw.strip() else []
except Exception:
    prs = []
for p in prs:
    if p.get("isDraft") and not include:
        continue
    title = (p.get("title") or "").replace("\t", " ")
    print("%s\t%s\t%s\t%s" % (
        p.get("number", ""),
        p.get("headRefOid", ""),
        p.get("url", ""),
        title,
    ))
'
}

repo_for_target() {
  local tid="$1"
  python3 - "$TARGETS_FILE" "$tid" <<'PY'
import json, sys
path, tid = sys.argv[1:3]
with open(path) as f:
    d = json.load(f)
t = (d.get("targets") or {}).get(tid) or {}
repo = t.get("repo")
print(repo or "")
PY
}

run_one_pr() {
  local target="$1" pr="$2" head="$3"
  local out args=()
  out="$STATE_DIR/runs/${target}-pr${pr}-${head:0:8}"
  mkdir -p "$out"
  args=(node "$CHECK_PR" --target "$target" --pr "$pr" --out "$out")
  if [ "$(cfg_get skipAi false)" = "true" ]; then
    args+=(--skip-ai)
  fi
  if [ "$(cfg_get noLab false)" = "true" ]; then
    args+=(--no-lab)
  fi
  if [ "$(cfg_get postComment false)" = "true" ]; then
    args+=(--post)
  fi
  log "RUN target=$target pr=$pr head=${head:0:8} out=$out"
  set +e
  (
    export PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:${PATH:-}"
    export OLLAMA_API_KEY="${OLLAMA_API_KEY:-ollama}"
    export SECURITY_CLAUDE_WRAPPER="${SECURITY_CLAUDE_WRAPPER:-$ROOT/security/studio/claude-via-gui.sh}"
    if [ -S "${HOME}/.colima/default/docker.sock" ]; then
      export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"
    fi
    cd "$ROOT"
    "${args[@]}"
  ) >>"$out/auto-runner.log" 2>&1
  local rc=$?
  set -u
  log "DONE target=$target pr=$pr exit=$rc"
  echo "$rc" >"$out/exit.code"
  return "$rc"
}

cmd_run() {
  need gh
  need node
  need python3

  if is_disabled; then
    log "SKIP tick — auto-pr-check disabled (kill switch or SECURITY_SCAN_AUTO_PR_CHECK=0)"
    exit 0
  fi

  if [ ! -f "$CHECK_PR" ]; then
    die "check-pr.mjs missing at $CHECK_PR"
  fi
  if [ ! -f "$TARGETS_FILE" ]; then
    die "targets.json missing"
  fi

  local max_n ran=0
  max_n="$(cfg_get maxPrsPerTick 2)"
  # shellcheck disable=SC2207
  local targets=()
  while IFS= read -r t; do
    [ -n "$t" ] && targets+=("$t")
  done < <(cfg_get targets)

  if [ "${#targets[@]}" -eq 0 ]; then
    log "no targets configured"
    exit 0
  fi

  log "TICK start targets=${targets[*]} max=$max_n"

  local tid repo line pr head url title key rc
  for tid in "${targets[@]}"; do
    [ "$ran" -ge "$max_n" ] && break
    repo="$(repo_for_target "$tid")"
    if [ -z "$repo" ]; then
      log "skip target=$tid (no repo)"
      continue
    fi
    while IFS=$'\t' read -r pr head url title; do
      [ -n "$pr" ] || continue
      [ "$ran" -ge "$max_n" ] && break
      key="${repo}#${pr}"
      if already_checked "$key" "$head"; then
        log "skip $key head=${head:0:8} (already checked)"
        continue
      fi
      run_one_pr "$tid" "$pr" "$head"
      rc=$?
      save_checked "$key" "$head" "$rc"
      ran=$((ran + 1))
    done < <(list_ready_prs "$repo")
  done

  log "TICK end ran=$ran"
  exit 0
}

usage() {
  cat <<EOF
Usage: auto-pr-check.sh <command>

  --run | --once     Run one scan tick (ready-for-review PRs)
  --status           Show kill switch + launchd status
  --on               Enable (default); remove kill-switch file
  --off              Disable without uninstalling launchd
  --install-agent    Install + load LaunchAgent (interval from config)
  --uninstall-agent  Unload + remove LaunchAgent

Kill switch (any one disables):
  $OFF_FILE
  SECURITY_SCAN_AUTO_PR_CHECK=0

Default after --install-agent: ON.
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    --run|--once) cmd_run ;;
    --status) cmd_status ;;
    --on) cmd_on ;;
    --off) cmd_off ;;
    --install-agent) cmd_install_agent ;;
    --uninstall-agent) cmd_uninstall_agent ;;
    -h|--help|"") usage; exit 0 ;;
    *) usage; die "unknown command: $cmd" ;;
  esac
}

main "$@"
