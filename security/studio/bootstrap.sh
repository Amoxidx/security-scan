#!/usr/bin/env bash
#
# Prepare a Studio (or any Mac with Ollama + Colima) to run the full security-scan
# pipeline against PRs: scanners, AI CLI providers, local lab sandbox.
#
# Safe to re-run. Does not touch GitHub secrets, branch protection, or remote state.
#
# Usage:
#   security/studio/bootstrap.sh
#   security/studio/bootstrap.sh --check   # doctor only, no installs
#
# Exit: 0 ready, 1 missing required pieces after install attempt, 2 usage error.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then
  CHECK_ONLY=1
elif [ -n "${1:-}" ]; then
  echo "Usage: security/studio/bootstrap.sh [--check]" >&2
  exit 2
fi

PASS=0
FAIL=0
WARN=0

ok()   { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m     %s\n' "$*"; }
warn() { WARN=$((WARN + 1)); printf '  \033[33mwarn\033[0m   %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m   %s\n' "$*"; }
head() { printf '\n\033[1m%s\033[0m\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

link_docker() {
  # brew formula often lives under Cellar without a PATH link on non-interactive shells.
  local candidates=(
    /opt/homebrew/bin/docker
    /usr/local/bin/docker
    /opt/homebrew/opt/docker/bin/docker
    /usr/local/opt/docker/bin/docker
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
    ok "docker on PATH: $(command -v docker)"
    return 0
  fi
  if ! bin="$(link_docker)"; then
    fail "docker CLI not found (brew install docker, or install OrbStack/Docker Desktop)"
    return 1
  fi
  if [ "$CHECK_ONLY" = 1 ]; then
    warn "docker exists at $bin but is not on PATH — export DOCKER_BIN=$bin or add to PATH"
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  ln -sfn "$bin" "$HOME/.local/bin/docker"
  export PATH="$HOME/.local/bin:$PATH"
  if have docker; then
    ok "linked docker → $HOME/.local/bin/docker ($bin)"
  else
    fail "could not put docker on PATH from $bin"
    return 1
  fi
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

check_ai() {
  head "AI providers (CLI subscriptions — no metered keys required)"
  if have codex; then
    ok "codex (triage/final judge)"
  else
    warn "codex not on PATH — triage/judge stages skip (npm i -g @openai/codex && codex login)"
  fi
  if have claude; then
    ok "claude (adversarial refuter)"
  else
    warn "claude not on PATH — verify stage may be unverified"
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
    if ollama list 2>/dev/null | grep -q 'qwen3-coder-next'; then
      ok "qwen3-coder-next model available"
    else
      if [ "$CHECK_ONLY" = 1 ]; then
        warn "qwen3-coder-next not pulled (ollama pull qwen3-coder-next:q4_K_M)"
      else
        echo "  pulling qwen3-coder-next:q4_K_M (large — may take a while)..."
        if ollama pull qwen3-coder-next:q4_K_M; then
          ok "model pulled"
        else
          warn "model pull failed — lab will be unavailable until fixed"
        fi
      fi
    fi
    if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      ok "ollama serving on :11434"
    else
      if [ "$CHECK_ONLY" = 1 ]; then
        warn "ollama not serving — start with: ollama serve"
      else
        echo "  starting ollama serve in background..."
        nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
        sleep 2
        if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
          ok "ollama serve started"
        else
          warn "could not start ollama serve — see /tmp/ollama-serve.log"
        fi
      fi
    fi
  else
    fail "ollama not installed (brew install ollama)"
  fi

  if have colima; then
    if colima status 2>/dev/null | grep -qi 'running'; then
      ok "colima running"
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

  if have docker || [ -n "${DOCKER_BIN:-}" ]; then
    export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
    if docker info >/dev/null 2>&1 || "$HOME/.local/bin/docker" info >/dev/null 2>&1 || \
       /opt/homebrew/opt/docker/bin/docker info >/dev/null 2>&1; then
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

# ---------------------------------------------------------------- main

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

head "Summary"
printf '  ok=%s  warn=%s  fail=%s\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\033[31mStudio is NOT ready for a full PR check.\033[0m\n'
  printf 'Fix the FAIL lines, then re-run: security/studio/bootstrap.sh\n'
  exit 1
fi
printf '\033[32mStudio ready.\033[0m Run a PR check:\n'
printf '  node security/studio/check-pr.mjs --pr <N> --repo <owner/name> --post\n'
printf '  node security/studio/check-pr.mjs --local --base origin/master\n'
exit 0
