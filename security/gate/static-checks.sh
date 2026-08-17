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

# An unresolvable base is a blocking configuration error, not an empty result.
if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  fail "base ref does not resolve: $BASE"
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi

# --mode tree passes the empty-tree object (every file counts as added) instead of a real
# base commit. "..." needs two commits to compute a merge-base; a tree object has no commit
# ancestry, so that syntax fails outright ("is a tree, not a commit") and blocked every tree
# scan's static gate before this file's own findings were even read. ".." is a plain diff
# against the given tree-ish and works for both a real commit and the empty tree.
if [ "$(git cat-file -t "$BASE" 2>/dev/null)" = "commit" ]; then
  RANGE="$BASE...HEAD"
else
  RANGE="$BASE..HEAD"
fi

if ! CHANGED=$(git diff --name-only --diff-filter=d "$RANGE"); then
  fail "git diff failed against base ref: $BASE"
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi

# Does not call fail() — callers that capture stdout via $(...) would otherwise swallow the
# BLOCK line into the added-lines payload. Return non-zero and let the caller fail loudly.
added_lines() { # added_lines [pathspec...] -> the '+' lines of the diff, without headers
  local diff_out
  if ! diff_out=$(git diff --unified=0 "$RANGE" -- "$@"); then
    return 1
  fi
  echo "$diff_out" | grep -E '^\+' | grep -Ev '^\+\+\+' || true
}

if ! ADDED=$(added_lines .); then
  fail "git diff failed while collecting added lines against: $BASE"
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi

# Prose is not code, and neither is a rule that *describes* a dangerous pattern or a fixture
# that deliberately contains one. A checker that flags its own rule definitions and its own
# test corpus is the fastest way to get the whole gate ignored.
#
# The first CI run of this gate proved the point: it blocked its own pull request three times,
# twice on its own material — the Semgrep rule listing "postinstall", and a corpus fixture
# whose whole purpose is to contain the string `curl | sh`.
if ! CODE_ADDED=$(added_lines . \
  ':(exclude)*.md' \
  ':(exclude)security/gate/*' \
  ':(exclude)security/scanners/semgrep/rules/*' \
  ':(exclude)security/eval/corpus/*' \
  ':(exclude)security/redteam/prompts/*' \
  ':(exclude)security/lab/fixtures/*'); then
  fail "git diff failed while collecting added lines against: $BASE"
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi

if [ -z "$CHANGED" ]; then
  echo "No changed files against $BASE."
  exit 0
fi

printf 'Changed files (%s):\n' "$(echo "$CHANGED" | wc -l | tr -d ' ')"
echo "$CHANGED" | sed 's/^/  /'

# ---------------------------------------------------------------- secrets
say '1. Secret material in added lines'
# Deliberately narrow patterns. A noisy secret scanner gets muted, which is worse than none.
# sk-ant- / sk-proj- accept hyphen/underscore in the body; plain sk- stays alphanumeric only
# so prose like "sk-" does not fire.
# Deliberately prefix-anchored. github_pat_ / glpat- cover fine-grained GitHub and GitLab
# tokens that the older gh[pousr]_ class misses; npm_ stays alphanumeric to limit prose hits.
SECRET_PATTERNS='(AKIA[0-9A-Z]{16})|(gh[pousr]_[A-Za-z0-9]{36,})|(github_pat_[A-Za-z0-9_]{20,})|(glpat-[A-Za-z0-9_-]{20,})|(npm_[A-Za-z0-9]{36,})|(sk-ant-[A-Za-z0-9_-]{32,})|(sk-proj-[A-Za-z0-9_-]{32,})|(sk-[A-Za-z0-9]{32,})|(xox[baprs]-[A-Za-z0-9-]{10,})|(-----BEGIN [A-Z ]*PRIVATE KEY-----)|(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})'
if HITS=$(echo "$ADDED" | grep -nE "$SECRET_PATTERNS"); then
  fail "possible credential in added lines:"
  echo "$HITS" | sed 's/^/         /' | cut -c1-160
else
  ok 'no credential patterns'
fi

# ---------------------------------------------------------------- CI privilege
say '2. CI / workflow changes'
if echo "$CHANGED" | grep -qE '^\.github/(workflows/|actions/)'; then
  # A note, not a block. Blocking every CI change makes the gate unmaintainable: as a
  # required check it would deadlock its own updates — no fix to the gate could ever merge.
  # The dangerous shapes are caught precisely instead, here and by the Semgrep rules
  # workflow-command-injection and pull-request-target-with-head-checkout.
  warn 'this PR modifies CI configuration — review the diff deliberately'
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
  # CODE_ADDED, not ADDED: the Semgrep rule that detects install hooks quotes the very
  # strings it looks for, and matching those marked the gate's own ruleset as an attack.
  if echo "$CODE_ADDED" | grep -qE '"(pre|post)?install"[[:space:]]*:'; then
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
# Tests, e2e specs, snapshots and license files cite fixtures (RFC reserved names,
# lookalike sanitiser cases) and license URLs — those are not outbound channels.
# An unknown host in src/ still blocks (see M3). A warn-only check never stops
# exfiltration endpoints.
#
# Matching is case-insensitive and host-anchored: an extra `fonts.googleapis.com`
# allows that host and its subdomains, not `evilfonts.googleapis.com` and not
# `fonts.googleapis.com.evil.example`. Userinfo is stripped so
# `https://allowed.example@evil.example/` is scored as `evil.example`.
# Adopters / Studio targets extend via SECURITY_HOST_ALLOW_EXTRA
# (pipe-separated regex fragments, no outer parens),
# e.g. SECURITY_HOST_ALLOW_EXTRA='api\.dfx\.swiss|dev\.dfx\.swiss'
#
# `invalid` is the RFC 6761 special-use TLD: names under it never resolve on
# the public internet and are used as URL-constructor sentinels. `.example`
# stays blocking — it is the documented stand-in for an unknown host (M3).
HOST_ALLOW_CORE='github\.com|githubusercontent\.com|npmjs\.(org|com)|schema\.org|www\.w3\.org|opensource\.org|api\.moonshot\.ai|api\.anthropic\.com|api\.openai\.com|opencode\.ai|localhost|127\.0\.0\.1|invalid'
if [ -n "${SECURITY_HOST_ALLOW_EXTRA:-}" ]; then
  HOST_ALLOW="(${HOST_ALLOW_CORE}|${SECURITY_HOST_ALLOW_EXTRA})"
else
  HOST_ALLOW="(${HOST_ALLOW_CORE})"
fi
# Exact host or a subdomain of an allowed host. The leading `(.+\.)?` is what
# stops `evilfonts.googleapis.com` from riding on `fonts.googleapis.com`.
HOST_ALLOW_RE="^(.+\\.)?${HOST_ALLOW}$"

if ! HOST_CODE_ADDED=$(added_lines . \
  ':(exclude)*.md' \
  ':(exclude)security/gate/*' \
  ':(exclude)security/scanners/semgrep/rules/*' \
  ':(exclude)security/eval/corpus/*' \
  ':(exclude)security/redteam/prompts/*' \
  ':(exclude)security/lab/fixtures/*' \
  ':(exclude)*.test.*' \
  ':(exclude)*.spec.*' \
  ':(exclude)*.snap' \
  ':(exclude)e2e/**' \
  ':(exclude)e2e-stack/**' \
  ':(exclude)**/__tests__/**' \
  ':(exclude)**/__mocks__/**' \
  ':(exclude)LICENSE' \
  ':(exclude)LICENSE.*' \
  ':(exclude)**/LICENSE' \
  ':(exclude)**/LICENSE.*' \
  ':(exclude)OFL.txt' \
  ':(exclude)**/OFL.txt' \
  ':(exclude)COPYING' \
  ':(exclude)COPYING.*' \
  ':(exclude)NOTICE' \
  ':(exclude)NOTICE.*'); then
  fail "git diff failed while collecting host-check lines against: $BASE"
  printf '\033[31mStatic security gate: BLOCKED\033[0m\n'
  exit 1
fi

# Strip the scheme, then any userinfo (`user@host` / `allowed@evil`), lowercase.
HOST_EXTRACTED=$(printf '%s\n' "$HOST_CODE_ADDED" \
  | grep -oE 'https?://[a-zA-Z0-9.@-]+' \
  | sed -E 's#^https?://##' \
  | sed -E 's/^.*@//' \
  | tr '[:upper:]' '[:lower:]' \
  | sort -u || true)

HOST_HITS=
if [ -n "$HOST_EXTRACTED" ]; then
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    if ! printf '%s\n' "$host" | grep -qE "$HOST_ALLOW_RE"; then
      HOST_HITS="${HOST_HITS}${host}"$'\n'
    fi
  done <<EOF
$HOST_EXTRACTED
EOF
fi

if [ -n "$HOST_HITS" ]; then
  fail 'new external hosts in code — extend the allowlist only when intentional:'
  printf '%s' "$HOST_HITS" | sed 's/^/         /'
  if [ -n "${SECURITY_HOST_ALLOW_EXTRA:-}" ]; then
    warn "SECURITY_HOST_ALLOW_EXTRA is set but did not cover the host(s) above"
  fi
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
