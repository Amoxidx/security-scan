#!/usr/bin/env bash
#
# Prepare a Studio (or any Mac with Ollama + Colima) to run the full security-scan
# pipeline against PRs: scanners, AI CLI providers, local lab sandbox.
#
# Safe to re-run. Does not touch GitHub secrets, branch protection, or remote state.
#
# Usage:
#   security/studio/bootstrap.sh
#   security/studio/bootstrap.sh --check            # doctor only, no installs
#   security/studio/bootstrap.sh --install-auto     # install LaunchAgent (auto PR checks, default ON)
#   security/studio/bootstrap.sh --uninstall-auto
#
# Exit: 0 ready, 1 missing required pieces after install attempt, 2 usage error.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# Preferred lab model tag on Studio (must match security/redteam/config.json → lab.model).
LAB_MODEL_DEFAULT="${SECURITY_LAB_MODEL:-qwen3-coder-next:q4_K_M}"

CHECK_ONLY=0
INSTALL_AUTO=0
UNINSTALL_AUTO=0
case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  --install-auto) INSTALL_AUTO=1 ;;
  --uninstall-auto) UNINSTALL_AUTO=1 ;;
  "") ;;
  *)
    echo "Usage: security/studio/bootstrap.sh [--check|--install-auto|--uninstall-auto]" >&2
    exit 2
    ;;
esac

# Non-interactive Studio shells often miss brew / OrbStack / go bins.
export PATH="${HOME}/.local/bin:/usr/local/bin:/opt/homebrew/bin:/opt/homebrew/opt/docker/bin:${HOME}/go/bin:${PATH:-}"

PASS=0
FAIL=0
WARN=0

ok()   { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m     %s\n' "$*"; }
warn() { WARN=$((WARN + 1)); printf '  \033[33mwarn\033[0m   %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m   %s\n' "$*"; }
head() { printf '\n\033[1m%s\033[0m\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Resolved docker binary for daemon checks (set by ensure_path_docker).
DOCKER_RESOLVED=""

link_docker() {
  # brew formula often lives under Cellar without a PATH link on non-interactive shells.
  # OrbStack installs a shim at /usr/local/bin/docker.
  local candidates=(
    /usr/local/bin/docker
    /opt/homebrew/bin/docker
    /opt/homebrew/opt/docker/bin/docker
    /usr/local/opt/docker/bin/docker
    "${HOME}/.docker/bin/docker"
  )
  local bin
  for bin in "${candidates[@]}"; do
    if [ -x "$bin" ]; then
      echo "$bin"
      return 0
    fi
  done
  if [ -d /opt/homebrew/Cellar/docker ]; then
    bin="$(ls -1 /opt/homebrew/Cellar/docker/*/bin/docker 2>/dev/null | sort -r | head -1 || true)"
    if [ -n "$bin" ] && [ -x "$bin" ]; then
      echo "$bin"
      return 0
    fi
  fi
  return 1
}

ensure_path_docker() {
  local bin
  if have docker; then
    DOCKER_RESOLVED="$(command -v docker)"
    export DOCKER_BIN="${DOCKER_BIN:-$DOCKER_RESOLVED}"
    ok "docker on PATH: $DOCKER_RESOLVED"
    return 0
  fi
  if ! bin="$(link_docker)"; then
    fail "docker CLI not found (brew install docker, or install OrbStack/Docker Desktop)"
    return 1
  fi
  DOCKER_RESOLVED="$bin"
  export DOCKER_BIN="$bin"
  if [ "$CHECK_ONLY" = 1 ]; then
    # Still usable for daemon probe via DOCKER_BIN / absolute path.
    ok "docker off-PATH at $bin (DOCKER_BIN set for this session)"
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  ln -sfn "$bin" "$HOME/.local/bin/docker"
  export PATH="$HOME/.local/bin:$PATH"
  if have docker; then
    DOCKER_RESOLVED="$(command -v docker)"
    export DOCKER_BIN="$DOCKER_RESOLVED"
    ok "linked docker → $HOME/.local/bin/docker ($bin)"
  else
    fail "could not put docker on PATH from $bin"
    return 1
  fi
}

# Returns 0 if a model name matching the needle is present (via API tags, then ollama list).
ollama_has_model() {
  local needle="$1"
  local tags
  tags="$(curl -sf --max-time 3 http://127.0.0.1:11434/api/tags 2>/dev/null || true)"
  if [ -n "$tags" ]; then
    printf '%s' "$tags" | grep -q "$needle" && return 0
  fi
  ollama list 2>/dev/null | grep -q "$needle"
}

docker_info_ok() {
  local bin="${1:-}"
  local sock="${HOME}/.colima/default/docker.sock"
  # Under `set -u`, empty arrays cannot be expanded as "${arr[@]}" on bash 3.2 / some 5.x.
  # Always prefix with `env` and only inject DOCKER_HOST when the colima socket exists.
  local -a run_prefix=(env)
  if [ -S "$sock" ]; then
    run_prefix=(env "DOCKER_HOST=unix://${sock}")
  fi
  try_docker() {
    local d="$1"
    [ -n "$d" ] && [ -x "$d" ] || return 1
    "${run_prefix[@]}" "$d" info >/dev/null 2>&1
  }
  if try_docker "$bin"; then return 0; fi
  if have docker && try_docker "$(command -v docker)"; then return 0; fi
  local cand
  for cand in \
    "${DOCKER_BIN:-}" \
    "$HOME/.local/bin/docker" \
    /usr/local/bin/docker \
    /opt/homebrew/bin/docker \
    /opt/homebrew/opt/docker/bin/docker
  do
    if try_docker "$cand"; then return 0; fi
  done
  return 1
}

colima_is_running() {
  # Prefer the docker socket — `colima status` exit codes vary by version.
  if [ -S "${HOME}/.colima/default/docker.sock" ]; then
    return 0
  fi
  colima status 2>/dev/null | grep -qi 'running'
}

install_scanners() {
  head "Scanners"
  if have semgrep; then
    ok "semgrep $(semgrep --version 2>/dev/null | head -1)"
  elif [ "$CHECK_ONLY" = 1 ]; then
    fail "semgrep not installed"
  else
    echo "  installing semgrep..."
    installed=0
    # Prefer brew (avoids PEP 668 on Homebrew Python).
    if have brew && brew install semgrep >/tmp/security-scan-semgrep-brew.log 2>&1; then
      export PATH="$(brew --prefix)/bin:$PATH"
      installed=1
    fi
    # pipx manages its own venv.
    if [ "$installed" = 0 ] && have pipx; then
      if pipx install "semgrep==1.172.0" >/tmp/security-scan-semgrep-pipx.log 2>&1 \
        || pipx upgrade semgrep >/tmp/security-scan-semgrep-pipx.log 2>&1; then
        export PATH="$HOME/.local/bin:$PATH"
        installed=1
      fi
    fi
    # Last resort: dedicated venv (never touch system site-packages).
    if [ "$installed" = 0 ]; then
      VENV="$HOME/.cache/security-scan/venv"
      mkdir -p "$(dirname "$VENV")"
      if python3 -m venv "$VENV" \
        && "$VENV/bin/pip" install --quiet 'semgrep==1.172.0'; then
        mkdir -p "$HOME/.local/bin"
        ln -sfn "$VENV/bin/semgrep" "$HOME/.local/bin/semgrep"
        export PATH="$HOME/.local/bin:$PATH"
        installed=1
      fi
    fi
    if have semgrep; then
      ok "semgrep installed ($(command -v semgrep))"
    else
      fail "semgrep install failed (tried brew, pipx, venv) — see /tmp/security-scan-semgrep-*.log"
    fi
  fi

  if have go; then
    export PATH="$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
  fi

  if have osv-scanner; then
    ok "osv-scanner present"
  elif [ "$CHECK_ONLY" = 1 ]; then
    fail "osv-scanner not installed"
  elif have go; then
    echo "  installing osv-scanner..."
    if go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.5.0; then
      export PATH="$HOME/go/bin:$(go env GOPATH)/bin:$PATH"
      if have osv-scanner; then ok "osv-scanner installed"; else fail "osv-scanner install ok but not on PATH"; fi
    else
      fail "osv-scanner install failed"
    fi
  else
    fail "osv-scanner needs go (brew install go)"
  fi

  if have gitleaks; then
    ok "gitleaks present"
  elif [ "$CHECK_ONLY" = 1 ]; then
    fail "gitleaks not installed"
  elif have go; then
    echo "  installing gitleaks..."
    if go install github.com/zricethezav/gitleaks/v8@v8.30.1; then
      export PATH="$HOME/go/bin:$(go env GOPATH)/bin:$PATH"
      if have gitleaks; then ok "gitleaks installed"; else fail "gitleaks install ok but not on PATH"; fi
    else
      fail "gitleaks install failed"
    fi
  else
    fail "gitleaks needs go"
  fi
}

check_runtime() {
  head "Runtime"
  if have node; then
    local nv
    nv="$(node -v | sed 's/^v//')"
    # Need ≥22.18 for prove strip-types; studio pipeline itself runs on ≥20.
    case "$nv" in
      22.*|23.*|24.*) ok "node v$nv" ;;
      *) warn "node v$nv — recommend ≥22.18 for prove/probes" ;;
    esac
  else
    fail "node not installed"
  fi

  if have gh; then
    ok "gh $(gh --version 2>/dev/null | head -1)"
  else
    fail "gh not installed (needed for --pr / --post)"
  fi

  if have git; then ok "git present"; else fail "git missing"; fi
}

install_claude_gui_wrapper() {
  # Symlink security/studio/claude-via-gui.sh → ~/.local/bin so standalone harness runs work.
  local src="$ROOT/security/studio/claude-via-gui.sh"
  local dest="$HOME/.local/bin/claude-via-gui"
  if [ ! -f "$src" ]; then
    warn "claude-via-gui.sh missing in checkout"
    return 1
  fi
  chmod +x "$src" 2>/dev/null || true
  if [ "$CHECK_ONLY" = 1 ]; then
    if [ -x "$src" ]; then
      ok "claude-via-gui present at $src"
    else
      warn "claude-via-gui not executable: $src"
    fi
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  ln -sfn "$src" "$dest"
  export PATH="$HOME/.local/bin:$PATH"
  if [ -x "$dest" ] || [ -L "$dest" ]; then
    ok "linked claude-via-gui → $dest"
  else
    warn "could not link claude-via-gui into ~/.local/bin"
  fi
}

check_ai() {
  head "AI providers (CLI subscriptions — no metered keys required)"
  if have codex; then
    ok "codex (triage/final judge)"
  else
    warn "codex not on PATH — triage/judge stages skip (npm i -g @openai/codex && codex login)"
  fi
  if have claude; then
    ok "claude binary on PATH: $(command -v claude)"
  else
    warn "claude not on PATH — verify stage may be unverified"
  fi
  install_claude_gui_wrapper || true
  # Prefer the in-repo wrapper (absolute) for auth probe — same path check-pr exports.
  local wrap="$ROOT/security/studio/claude-via-gui.sh"
  if [ -x "$wrap" ]; then
    local auth_out
    if auth_out="$("$wrap" --studio-auth-check 2>&1)"; then
      ok "coding-agent CLI subscription reachable ($(printf '%s' "$auth_out" | tr '\n' ' ' | cut -c1-100))"
    else
      warn "coding-agent CLI auth not reachable from this shell — on the Studio desktop run: claude auth login"
      warn "  (SSH cannot read the login keychain; claude-via-gui uses the Aqua GUI domain when a desktop session exists)"
      warn "  detail: $(printf '%s' "$auth_out" | tr '\n' ' ' | cut -c1-160)"
    fi
  fi
  if have kimi; then
    ok "kimi present"
  else
    warn "kimi not on PATH — optional hunt backbone"
  fi
}

check_lab() {
  head "Local lab (Ollama + sandbox)"
  if have ollama; then
    ok "ollama present"
    if curl -sf --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      ok "ollama serving on :11434"
    else
      if [ "$CHECK_ONLY" = 1 ]; then
        warn "ollama not serving — start with: ollama serve"
      else
        echo "  starting ollama serve in background..."
        nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
        sleep 2
        if curl -sf --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
          ok "ollama serve started"
        else
          warn "could not start ollama serve — see /tmp/ollama-serve.log"
        fi
      fi
    fi
    # Prefer the exact Studio tag, then any qwen3-coder-next variant.
    if ollama_has_model "$LAB_MODEL_DEFAULT"; then
      ok "lab model available: $LAB_MODEL_DEFAULT"
    elif ollama_has_model 'qwen3-coder-next'; then
      ok "qwen3-coder-next variant available (preferred tag: $LAB_MODEL_DEFAULT)"
    else
      if [ "$CHECK_ONLY" = 1 ]; then
        warn "lab model missing — ollama pull $LAB_MODEL_DEFAULT"
      else
        echo "  pulling $LAB_MODEL_DEFAULT (large — may take a while)..."
        if ollama pull "$LAB_MODEL_DEFAULT"; then
          ok "model pulled: $LAB_MODEL_DEFAULT"
        else
          warn "model pull failed — lab will be unavailable until fixed"
        fi
      fi
    fi
  else
    fail "ollama not installed (brew install ollama)"
  fi

  if have colima; then
    if colima_is_running; then
      ok "colima running (socket or status)"
    else
      if [ "$CHECK_ONLY" = 1 ]; then
        warn "colima not running (colima start)"
      else
        echo "  starting colima..."
        if colima start; then ok "colima started"; else fail "colima start failed"; fi
      fi
    fi
  else
    warn "colima not installed — docker Desktop/OrbStack may still work"
  fi

  ensure_path_docker || true

  if [ -n "${DOCKER_RESOLVED:-}" ] || have docker || [ -n "${DOCKER_BIN:-}" ]; then
    if [ -S "${HOME}/.colima/default/docker.sock" ]; then
      export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"
    fi
    if docker_info_ok "${DOCKER_RESOLVED:-${DOCKER_BIN:-}}"; then
      ok "docker daemon reachable"
    else
      fail "docker CLI found but daemon not reachable (colima start / Docker Desktop)"
    fi
  fi
}

check_repo() {
  head "security-scan checkout"
  if [ -f "$ROOT/security/studio/check-pr.mjs" ]; then
    ok "studio orchestrator present"
  else
    fail "check-pr.mjs missing — is this an old checkout?"
  fi
  if [ -d "$ROOT/.git" ]; then
    local branch
    branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
    ok "repo at $ROOT ($branch)"
  fi
}

check_auto_pr() {
  head "Auto PR-ready check (LaunchAgent)"
  local auto="$ROOT/security/studio/auto-pr-check.sh"
  if [ ! -x "$auto" ] && [ -f "$auto" ]; then
    chmod +x "$auto" 2>/dev/null || true
  fi
  if [ ! -f "$auto" ]; then
    warn "auto-pr-check.sh missing"
    return 0
  fi
  # Parse --status without failing the doctor.
  local st
  st="$("$auto" --status 2>/dev/null || true)"
  if echo "$st" | grep -q 'disabled:[[:space:]]*yes'; then
    warn "auto-pr-check kill switch ON — re-enable: security/studio/auto-pr-check.sh --on"
  elif echo "$st" | grep -q 'launch_agent:[[:space:]]*loaded'; then
    ok "auto-pr-check ON (launchd loaded, no kill switch)"
  elif echo "$st" | grep -q 'launch_agent:[[:space:]]*installed'; then
    warn "auto-pr-check plist installed but not loaded — bootstrap --install-auto"
  else
    warn "auto-pr-check not installed — security/studio/bootstrap.sh --install-auto (default ON)"
  fi
  if [ -f "$HOME/.config/security-scan/auto-pr-check.off" ]; then
    warn "kill switch file: $HOME/.config/security-scan/auto-pr-check.off"
  fi
}

# ---------------------------------------------------------------- main

if [ "$INSTALL_AUTO" = 1 ]; then
  bash "$ROOT/security/studio/auto-pr-check.sh" --install-agent
  exit $?
fi
if [ "$UNINSTALL_AUTO" = 1 ]; then
  bash "$ROOT/security/studio/auto-pr-check.sh" --uninstall-agent
  exit $?
fi

printf '\033[1msecurity-scan · Studio bootstrap\033[0m\n'
printf 'root: %s\n' "$ROOT"
if [ "$CHECK_ONLY" = 1 ]; then
  printf 'mode: check only\n'
else
  printf 'mode: install + verify\n'
fi

check_runtime
install_scanners
check_ai
check_lab
check_repo
check_auto_pr

head "Summary"
printf '  ok=%s  warn=%s  fail=%s\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\033[31mStudio is NOT ready for a full PR check.\033[0m\n'
  printf 'Fix the FAIL lines, then re-run: security/studio/bootstrap.sh\n'
  exit 1
fi
printf '\033[32mStudio ready.\033[0m Run a PR check:\n'
printf '  node security/studio/check-pr.mjs --target dfx-api --pr <N> --post\n'
printf '  node security/studio/check-pr.mjs --local --target security-scan --base origin/master\n'
printf '  Lab model default: ollama:%s\n' "$LAB_MODEL_DEFAULT"
printf 'Auto PR-ready checks (LaunchAgent, default ON):\n'
printf '  security/studio/bootstrap.sh --install-auto\n'
printf '  security/studio/auto-pr-check.sh --off   # pause without uninstall\n'
printf '  security/studio/auto-pr-check.sh --on    # resume (default)\n'
exit 0
