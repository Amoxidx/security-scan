#!/usr/bin/env bash
#
# Stage A of the security gate — deterministic, no AI, no network, seconds to run.
#
# This is the part that must never be skipped and never be flaky. It covers the class of
# attack a language model is the wrong tool for: a contributor whose PR is malicious rather
# than buggy. Everything here blocks.
#
# Usage: security/gate/static-checks.sh <base-ref>
#
# Exit: 0 clean, 1 blocking finding.

set -uo pipefail

BASE="${1:-origin/master}"
FAIL=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '  \033[31mBLOCK\033[0m  %s\n' "$*"; FAIL=1; }
warn() { printf '  \033[33mnote\033[0m   %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m     %s\n' "$*"; }

CHANGED=$(git diff --name-only --diff-filter=d "$BASE"...HEAD)

added_lines() { # added_lines [pathspec...] -> the '+' lines of the diff, without headers
  git diff --unified=0 "$BASE"...HEAD -- "$@" | grep -E '^\+' | grep -Ev '^\+\+\+' || true
}

ADDED=$(added_lines .)

# Prose is not code. Documentation that *describes* a dangerous pattern, and the scanner that
# *defines* it, must not trip the scanner — a checker that flags its own patterns is the
# fastest way to get the whole gate ignored.
CODE_ADDED=$(added_lines . ':(exclude)*.md' ':(exclude)security/gate/*')

if [ -z "$CHANGED" ]; then
  echo "No changed files against $BASE."
  exit 0
fi

printf 'Changed files (%s):\n' "$(echo "$CHANGED" | wc -l | tr -d ' ')"
echo "$CHANGED" | sed 's/^/  /'

# ---------------------------------------------------------------- secrets
say '1. Secret material in added lines'
# Deliberately narrow patterns. A noisy secret scanner gets muted, which is worse than none.
SECRET_PATTERNS='(AKIA[0-9A-Z]{16})|(gh[pousr]_[A-Za-z0-9]{36,})|(sk-[A-Za-z0-9]{32,})|(xox[baprs]-[A-Za-z0-9-]{10,})|(-----BEGIN [A-Z ]*PRIVATE KEY-----)|(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})'
if HITS=$(echo "$ADDED" | grep -nE "$SECRET_PATTERNS"); then
  fail "possible credential in added lines:"
  echo "$HITS" | sed 's/^/         /' | cut -c1-160
else
  ok 'no credential patterns'
fi

# ---------------------------------------------------------------- CI privilege
say '2. CI / workflow changes'
if echo "$CHANGED" | grep -qE '^\.github/(workflows/|actions/)'; then
  fail 'this PR modifies CI configuration — requires explicit human review'
  echo "$CHANGED" | grep -E '^\.github/(workflows/|actions/)' | sed 's/^/         /'
  # pull_request_target with a checkout of the PR head is the classic CI takeover.
  # Match it only as a YAML key, so a comment explaining why it is avoided does not trip.
  if added_lines '.github/workflows/*' '.github/actions/*' \
    | grep -Eq '^\+[[:space:]]*pull_request_target[[:space:]]*:'; then
    fail 'adds pull_request_target — runs with repo secrets against untrusted code'
  fi
else
  ok 'no CI configuration touched'
fi

# ---------------------------------------------------------------- install hooks
say '3. Dependency install hooks'
if echo "$CHANGED" | grep -q 'package.json'; then
  if echo "$ADDED" | grep -qE '"(pre|post)?install"[[:space:]]*:'; then
    fail 'adds an install/postinstall script — arbitrary code on every npm install'
  else
    ok 'no install hooks added'
  fi
else
  ok 'package.json unchanged'
fi

# ---------------------------------------------------------------- lockfile drift
say '4. Lockfile / manifest consistency'
LOCK=$(echo "$CHANGED" | grep -cE '(package-lock\.json|yarn\.lock)$' || true)
MANIFEST=$(echo "$CHANGED" | grep -cE 'package\.json$' || true)
if [ "$LOCK" -gt 0 ] && [ "$MANIFEST" -eq 0 ]; then
  fail 'lockfile changed without a manifest change — dependency substitution risk'
elif [ "$LOCK" -gt 0 ]; then
  warn 'dependencies changed — check the diff of added packages'
else
  ok 'no dependency changes'
fi

# ---------------------------------------------------------------- code execution
say '5. Shell pipelines in added lines'
# Narrowed deliberately. Matching `child_process` wholesale flagged execFileSync(cmd, [args])
# — the *safe* form — and a checker that fires on correct code gets muted. Semgrep now owns
# this class precisely (shell-out-with-interpolation, dynamic-code-execution), which can tell
# an interpolated exec from a fixed argument list. What stays here is the one pattern with no
# legitimate use in application code.
EXEC_PATTERNS='((curl|wget)[^|]*\|[[:space:]]*(ba|z|k)?sh)'
if HITS=$(echo "$CODE_ADDED" | grep -nE "$EXEC_PATTERNS"); then
  fail 'download piped into a shell:'
  echo "$HITS" | sed 's/^/         /' | cut -c1-160
else
  ok 'none'
fi

# ---------------------------------------------------------------- outbound network
say '6. New outbound endpoints in added lines'
# Code only: a link in a markdown file is a citation, not an exfiltration channel.
if HITS=$(echo "$CODE_ADDED" | grep -noE 'https?://[a-zA-Z0-9.-]+' | sort -u -t: -k2 | grep -vE '(github\.com|githubusercontent\.com|npmjs\.(org|com)|schema\.org|www\.w3\.org|opensource\.org)'); then
  warn 'new external hosts referenced — confirm they are expected:'
  echo "$HITS" | sed 's/^/         /'
else
  ok 'no unexpected external hosts'
fi

# ---------------------------------------------------------------- verdict
echo
if [ "$FAIL" -ne 0 ]; then
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi
printf '\033[32mStatic security gate: passed\033[0m\n'
exit 0
