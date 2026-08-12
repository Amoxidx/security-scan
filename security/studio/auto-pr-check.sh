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
  # cfg_get <dot.path> [default]
  local path="$1" def="${2:-}" val
  if [ ! -f "$CFG_FILE" ]; then
    printf '%s' "$def"
    return
  fi
  # shellcheck disable=SC2016
  val="$(jq -r --arg p "$path" --arg d "$def" '
    ($p | split(".")) as $parts
    | getpath($parts) as $v
    | if $v == null then $d
      elif ($v|type) == "boolean" then (if $v then "true" else "false" end)
      elif ($v|type) == "array" then ($v | map(tostring) | join("\n"))
      else ($v|tostring)
      end
  ' "$CFG_FILE" 2>/dev/null || true)"
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    printf '%s' "$def"
  else
    printf '%s' "$val"
  fi
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
  echo "  orgs:"
  jq -r '(.orgs // [])[] | "    - \(.org) (exclude: \((.exclude // [])|join(", ")))"' "$CFG_FILE" 2>/dev/null || echo "    - (none)"
  if [ -f "$STATE_FILE" ]; then
    echo "  last_state_keys: $(jq -r '(.checked // {}) | length' "$STATE_FILE" 2>/dev/null || echo 0)"
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

save_checked() {
  local key="$1" head="$2" exit_code="$3" when tmp
  when="$(date -Iseconds 2>/dev/null || date)"
  mkdir -p "$(dirname "$STATE_FILE")"
  if [ ! -f "$STATE_FILE" ]; then
    printf '%s\n' '{"checked":{}}' >"$STATE_FILE"
  fi
  tmp="$(mktemp "${STATE_DIR}/state.XXXXXX")"
  jq --arg k "$key" --arg h "$head" --argjson e "$exit_code" --arg t "$when" '
    .checked = (.checked // {})
    | .checked[$k] = {headRefOid: $h, exitCode: $e, at: $t}
  ' "$STATE_FILE" >"$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" || rm -f "$tmp"
}

already_checked() {
  local key="$1" head="$2" prev
  [ -f "$STATE_FILE" ] || return 1
  prev="$(jq -r --arg k "$key" '.checked[$k].headRefOid // empty' "$STATE_FILE" 2>/dev/null || true)"
  [ -n "$prev" ] && [ "$prev" = "$head" ]
}

list_ready_prs() {
  local repo="$1" include
  include="$(cfg_get includeDrafts false)"
  # Open PRs only; filter drafts unless includeDrafts=true.
  gh pr list --repo "$repo" --state open --limit 40 \
    --json number,title,isDraft,headRefOid,url,updatedAt 2>/dev/null \
    | jq -r --arg inc "$include" '
      .[]
      | select(($inc == "true") or (.isDraft | not))
      | [
          (.number|tostring),
          .headRefOid,
          (.url // ""),
          ((.title // "") | gsub("\t"; " "))
        ]
      | @tsv
    ' 2>/dev/null || true
}

repo_for_target() {
  local tid="$1"
  jq -r --arg t "$tid" '.targets[$t].repo // empty' "$TARGETS_FILE" 2>/dev/null || true
}

# run_one_pr <label> <repo> <pr> <head> [hostAllowPipeSeparated]
run_one_pr() {
  local label="$1" repo="$2" pr="$3" head="$4" hosts="${5:-}"
  local out args=() slug
  slug="$(printf '%s' "$repo" | tr '/' '-')"
  out="$STATE_DIR/runs/${slug}-pr${pr}-${head:0:8}"
  mkdir -p "$out"
  args=(node "$CHECK_PR" --repo "$repo" --pr "$pr" --out "$out")
  # Prefer named target when the repo is registered (localPaths + defaults).
  local tid
  tid="$(jq -r --arg r "$repo" '
    .targets | to_entries[] | select(.value.repo == $r) | .key
  ' "$TARGETS_FILE" 2>/dev/null | head -1 || true)"
  if [ -n "$tid" ]; then
    args=(node "$CHECK_PR" --target "$tid" --repo "$repo" --pr "$pr" --out "$out")
  fi
  if [ -n "$hosts" ]; then
    local h
    IFS='|' read -r -a _host_parts <<<"$hosts"
    for h in "${_host_parts[@]}"; do
      [ -n "$h" ] && args+=(--host-allow-extra "$h")
    done
  fi
  if [ "$(cfg_get skipAi false)" = "true" ]; then
    args+=(--skip-ai)
  fi
  if [ "$(cfg_get noLab false)" = "true" ]; then
    args+=(--no-lab)
  fi
  if [ "$(cfg_get postComment false)" = "true" ]; then
    args+=(--post)
  fi
  log "RUN label=$label repo=$repo pr=$pr head=${head:0:8} out=$out"
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
  log "DONE repo=$repo pr=$pr exit=$rc"
  echo "$rc" >"$out/exit.code"
  return "$rc"
}

# List non-archived, non-fork repos for an org (name only, not full path).
list_org_repo_names() {
  local org="$1"
  gh repo list "$org" --limit 100 --json name,isArchived,isFork 2>/dev/null \
    | jq -r '.[] | select((.isArchived|not) and (.isFork|not)) | .name' 2>/dev/null || true
}

org_host_allow() {
  local org="$1"
  jq -r --arg o "$org" '
    (.orgs // [])[] | select(.org == $o) | (.hostAllowExtra // []) | join("|")
  ' "$CFG_FILE" 2>/dev/null || true
}

org_exclude_contains() {
  local org="$1" name="$2"
  jq -e --arg o "$org" --arg n "$name" '
    (.orgs // [])[] | select(.org == $o) | (.exclude // []) | index($n) != null
  ' "$CFG_FILE" >/dev/null 2>&1
}

# Process ready PRs for one repo; updates ran counter via nameref-like globals.
# process_repo_prs <label> <repo> <hosts>  — uses max_n/ran from cmd_run scope
process_repo_prs() {
  local label="$1" repo="$2" hosts="$3"
  local pr head url title key rc
  while IFS=$'\t' read -r pr head url title; do
    [ -n "$pr" ] || continue
    [ "$ran" -ge "$max_n" ] && return 0
    key="${repo}#${pr}"
    if already_checked "$key" "$head"; then
      log "skip $key head=${head:0:8} (already checked)"
      continue
    fi
    run_one_pr "$label" "$repo" "$pr" "$head" "$hosts"
    rc=$?
    save_checked "$key" "$head" "$rc"
    ran=$((ran + 1))
  done < <(list_ready_prs "$repo")
}

cmd_run() {
  need gh
  need node
  need jq

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
  local targets=()
  while IFS= read -r t; do
    [ -n "$t" ] && targets+=("$t")
  done < <(cfg_get targets)

  local seen_repos=""
  mark_seen() {
    local r="$1"
    seen_repos="${seen_repos}"$'\n'"${r}"
  }
  was_seen() {
    printf '%s\n' "$seen_repos" | grep -qxF "$1"
  }

  log "TICK start named_targets=${#targets[@]} max=$max_n"

  local tid repo hosts
  # 1) Named targets first (prefer localPaths via --target).
  for tid in "${targets[@]}"; do
    [ "$ran" -ge "$max_n" ] && break
    repo="$(repo_for_target "$tid")"
    if [ -z "$repo" ]; then
      log "skip target=$tid (no repo)"
      continue
    fi
    if was_seen "$repo"; then
      continue
    fi
    mark_seen "$repo"
    hosts="$(jq -r --arg t "$tid" '(.targets[$t].hostAllowExtra // []) | join("|")' "$TARGETS_FILE" 2>/dev/null || true)"
    process_repo_prs "$tid" "$repo" "$hosts"
  done

  # 2) Org discovery: DFXswiss, RealUnitCH, zk-coins, …
  local org name full
  while IFS= read -r org; do
    [ -n "$org" ] || continue
    [ "$ran" -ge "$max_n" ] && break
    hosts="$(org_host_allow "$org")"
    log "ORG scan org=$org"
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      [ "$ran" -ge "$max_n" ] && break
      if org_exclude_contains "$org" "$name"; then
        log "skip $org/$name (excluded)"
        continue
      fi
      full="${org}/${name}"
      if was_seen "$full"; then
        continue
      fi
      mark_seen "$full"
      process_repo_prs "$full" "$full" "$hosts"
    done < <(list_org_repo_names "$org")
  done < <(jq -r '(.orgs // [])[].org' "$CFG_FILE" 2>/dev/null || true)

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
