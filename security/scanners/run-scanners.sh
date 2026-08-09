#!/usr/bin/env bash
#
# Stage 1 — run every scanner, collect SARIF.
#
# Each scanner is optional. A missing binary or an unreachable backend degrades that one
# scanner to "skipped" and is recorded as such; it never fails the run. What must not happen
# is a silent skip — a gate that quietly stopped scanning looks exactly like a gate that
# found nothing.
#
# Usage: security/scanners/run-scanners.sh <target-dir> <out-dir>
#
# Writes <out-dir>/{semgrep,osv,gitleaks}.sarif and <out-dir>/scanners.json.
# Always exits 0. The blocking decision belongs to normalize.mjs.

set -uo pipefail

TARGET="${1:-.}"
OUT="${2:-security-report/sarif}"
RULES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/semgrep/rules"

mkdir -p "$OUT"
STATUS="$OUT/scanners.json"
: > "$OUT/.log"

note() { printf '  %s\n' "$*" | tee -a "$OUT/.log"; }

entries=()
record() { entries+=("{\"tool\":\"$1\",\"status\":\"$2\",\"detail\":\"$3\"}"); }

# ---------------------------------------------------------------- semgrep
printf '\nSemgrep\n'
if command -v semgrep >/dev/null 2>&1; then
  # --metrics=off keeps the scan offline; the registry is not consulted, only local rules.
  semgrep --metrics=off --disable-version-check --quiet --config "$RULES" --sarif --output "$OUT/semgrep.sarif" \
    "$TARGET" >>"$OUT/.log" 2>&1
  rc=$?
  # semgrep exits 1 when it found something, and 2 for anything from "a rule failed to
  # parse" to "the scan died". Both previous readings of this were wrong: treating 2 as
  # success hides a broken rule, treating it as failure hides seven valid findings that
  # were produced anyway. So judge by the report, and report the exit code separately.
  n=$(grep -o '"ruleId"' "$OUT/semgrep.sarif" 2>/dev/null | wc -l | tr -d ' ')
  ruleerr=$(grep -o 'Rule parse error in rule [^"\\]*' "$OUT/semgrep.sarif" 2>/dev/null | head -5)

  if [ ! -s "$OUT/semgrep.sarif" ]; then
    note "error (exit $rc) — no report produced, see $OUT/.log"
    record semgrep error "exit $rc, no report"
  elif [ -n "$ruleerr" ]; then
    # A rule that does not compile is a silently missing check, which is the failure mode
    # this whole gate exists to avoid. Loud, but not fatal: the other rules still ran.
    note "DEGRADED — $n result(s), but a rule failed to compile and did NOT run:"
    printf '%s\n' "$ruleerr" | sed 's/^/    /' | tee -a "$OUT/.log"
    record semgrep degraded "$n results, rule parse error"
  elif [ $rc -le 1 ]; then
    note "ok — $n result(s)"
    record semgrep ok "$n results"
  else
    note "ok with warnings (exit $rc) — $n result(s), see $OUT/.log"
    record semgrep ok "$n results, exit $rc"
  fi
else
  note "skipped — semgrep not installed (pip install semgrep)"
  record semgrep skipped "not installed"
fi

# ---------------------------------------------------------------- osv-scanner
printf '\nOSV-Scanner\n'
if ! command -v osv-scanner >/dev/null 2>&1; then
  note "skipped — osv-scanner not installed"
  record osv skipped "not installed"
elif ! ls "$TARGET"/package-lock.json "$TARGET"/yarn.lock "$TARGET"/pnpm-lock.yaml >/dev/null 2>&1; then
  note "skipped — no lockfile in target"
  record osv skipped "no lockfile"
else
  osv_out=$(osv-scanner scan source --format sarif --output "$OUT/osv.sarif" -r "$TARGET" 2>&1)
  echo "$osv_out" >>"$OUT/.log"
  if echo "$osv_out" | grep -qi 'api.osv.dev.*\(forbidden\|no such host\|timeout\|refused\)'; then
    # The vulnerability database is remote. Without it the scan produces an empty report that
    # is indistinguishable from a clean one, which is the dangerous case.
    note "SKIPPED — api.osv.dev unreachable, result is NOT a clean bill of health"
    record osv skipped "api.osv.dev unreachable"
  else
    note "ok"
    record osv ok "scanned"
  fi
fi

# ---------------------------------------------------------------- gitleaks
printf '\nGitleaks\n'
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks dir "$TARGET" --report-format sarif --report-path "$OUT/gitleaks.sarif" \
    --no-banner --exit-code 0 >>"$OUT/.log" 2>&1
  note "ok"
  record gitleaks ok "scanned"
else
  note "skipped — gitleaks not installed"
  record gitleaks skipped "not installed"
fi

# ---------------------------------------------------------------- status
printf '[%s]\n' "$(IFS=,; echo "${entries[*]}")" > "$STATUS"
printf '\nSARIF in %s\n' "$OUT"
exit 0
