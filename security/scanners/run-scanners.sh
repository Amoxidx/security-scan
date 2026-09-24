#!/usr/bin/env bash
#
# Stage 1 — run every scanner, collect SARIF.
#
# The runner is report-only: it always exits 0, while scanners.json records whether each
# requested scanner completed. Only a target with no supported lockfile makes OSV
# "not applicable"; missing executables, unreachable backends and partial reports are errors
# or degraded coverage and must not be mistaken for a clean scan.
#
# Usage: security/scanners/run-scanners.sh <target-dir> <out-dir>
#
# Writes <out-dir>/{semgrep,osv,gitleaks}.sarif and scanners.json records with tool, status, reasonCode and detail.
# Always exits 0. The blocking decision belongs to normalize.mjs.

set -uo pipefail

TARGET="${1:-.}"
OUT="${2:-security-report/sarif}"
RULES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/semgrep/rules"

mkdir -p "$OUT"
STATUS="$OUT/scanners.json"
: > "$OUT/.log"

note() { printf '  %s\n' "$*" | tee -a "$OUT/.log"; }

# node is already required by normalize.mjs, so the report is judged with a JSON parser and
# not with grep. A grep for '"results":' calls the truncated write `{"runs":[{"results":`
# a valid report, and grepping "ruleId" counts a rule id that appears inside a message
# string. Both previous readings of this were wrong: treating exit 0 as ok hides a scan that
# wrote nothing, and treating an unparsable report as a crash hides the results that are
# there. Exit codes used here: 0 report usable, 2 file missing or empty, 3 truncated or
# malformed JSON, 4..10 parsable JSON with the wrong SARIF shape.
sarif_report() { # <findings|shape> <file> -> stdout findings count, exit 0 = usable
  node -e '
const fs = require("fs");
const [mode, file] = process.argv.slice(1);
const die = (c, m) => { process.stderr.write(m + "\n"); process.exit(c); };
let raw;
try { raw = fs.readFileSync(file, "utf8"); } catch { die(2, "report missing"); }
if (!raw.trim()) die(2, "report is empty");
let doc;
try { doc = JSON.parse(raw); } catch { die(3, "report is not JSON"); }
if (!doc || typeof doc !== "object" || Array.isArray(doc)) die(4, "report is not a JSON object");
if (typeof doc.version !== "string") die(5, "report has no SARIF version");
if (!Array.isArray(doc.runs) || !doc.runs.length) die(6, "report has no runs");
let n = 0;
for (const run of doc.runs) {
  if (!run || typeof run !== "object") die(7, "run is not an object");
  const driver = run.tool && run.tool.driver;
  if (!driver || typeof driver.name !== "string") die(8, "run has no tool driver name");
  // results is optional in SARIF 2.1.0; a report without it is a completed scan with
  // nothing to report, one with it must carry an array of result objects.
  if (run.results === undefined) continue;
  if (!Array.isArray(run.results)) die(9, "run results is not an array");
  for (const r of run.results) {
    if (!r || typeof r !== "object" || Array.isArray(r)) die(10, "result is not an object");
    n++;
  }
}
if (mode === "findings") process.stdout.write(String(n));
' "$1" "$2" 2>/dev/null
}
sarif_finding_count() { sarif_report findings "$1" 2>/dev/null || echo 0; }
sarif_reason() {
  case "$1" in
    2) echo report_missing ;;
    3) echo report_malformed ;;
    *) echo report_invalid_shape ;;
  esac
}

entries=()
record() {
  entries+=("{\"tool\":\"$1\",\"status\":\"$2\",\"reasonCode\":\"$3\",\"detail\":\"$4\"}")
}

# ---------------------------------------------------------------- semgrep
printf '\nSemgrep\n'
rm -f "$OUT/semgrep.sarif"
if command -v semgrep >/dev/null 2>&1; then
  # --metrics=off keeps the scan offline; the registry is not consulted, only local rules.
  # Both streams go into one file: the report says what was found, and the "Rule parse
  # error in rule ..." line that semgrep prints outside the report says whether a rule
  # silently did not run.
  semgrep --metrics=off --disable-version-check --quiet --config "$RULES" --sarif --output "$OUT/semgrep.sarif" \
    "$TARGET" >>"$OUT/.log" 2>&1
  rc=$?
  # semgrep exits 1 when it found something, and 2 for anything from "a rule failed to
  # parse" to "the scan died". Both previous readings of this were wrong: treating 2 as
  # success hides a broken rule, treating it as failure hides seven valid findings that
  # were produced anyway. So the report decides what was found, and the exit code decides
  # whenever the report cannot: an exit above 1 that no rule error explains is a run that
  # ended abnormally, and gets a worse record than a clean one.
  n=$(sarif_finding_count "$OUT/semgrep.sarif")
  ruleerr=$(grep -o 'Rule parse error in rule [^"\\]*' "$OUT/semgrep.sarif" "$OUT/.log" 2>/dev/null | head -5)

  if sarif_report shape "$OUT/semgrep.sarif"; then
    report_ok=1
  else
    report_rc=$?
    report_ok=0
    report_reason=$(sarif_reason "$report_rc")
    note "error (exit $rc) — no usable report, see $OUT/.log"
    record semgrep error "$report_reason" "exit $rc, no usable report"
  fi
  if [ "$report_ok" -eq 1 ] && [ -n "$ruleerr" ]; then
    # A rule that does not compile is a silently missing check, which is the failure mode
    # this whole gate exists to avoid. The runner remains report-only (exit 0), while the
    # degraded status must make the consumer stage incomplete.
    # Only this documented status is kept when the report is usable AND names the broken
    # rule; a bare non-zero exit is not evidence of a rule error.
    note "DEGRADED — $n result(s), but a rule failed to compile and did NOT run:"
    printf '%s\n' "$ruleerr" | sed 's/^/    /' | tee -a "$OUT/.log"
    record semgrep degraded semgrep_rule_parse_error "$n results, rule parse error"
  elif [ "$report_ok" -eq 1 ] && [ $rc -gt 1 ]; then
    note "error (exit $rc) — abnormal exit, report may be partial, see $OUT/.log"
    record semgrep error scanner_exit_failure "exit $rc, abnormal exit, report may be partial"
  elif [ "$report_ok" -eq 1 ]; then
    note "ok — $n result(s)"
    record semgrep ok completed "$n results"
  fi
else
  note "error — semgrep not installed (pip install semgrep)"
  record semgrep error executable_missing "not installed"
fi

# ---------------------------------------------------------------- osv-scanner
printf '\nOSV-Scanner\n'
rm -f "$OUT/osv.sarif"
if ! command -v osv-scanner >/dev/null 2>&1; then
  note "error — osv-scanner not installed"
  record osv error executable_missing "not installed"
elif [ ! -e "$TARGET/package-lock.json" ] && [ ! -e "$TARGET/yarn.lock" ] \
  && [ ! -e "$TARGET/pnpm-lock.yaml" ] && [ ! -e "$TARGET/Cargo.lock" ]; then
  note "skipped — no lockfile in target"
  record osv skipped not_applicable_no_lockfile "no lockfile"
else
  # A Cargo.lock admits the scan on its own: the JS-only guard skipped the Rust wallet
  # entirely. The scope stays recursive — `-r` is what looked into every subdirectory, so
  # naming only the root lockfiles would narrow it. `--lockfile` only ADDS the root
  # lockfiles explicitly, which is what makes a Rust target scannable at all; `--no-resolve`
  # keeps it to what a lockfile pins instead of consulting the registry for manifests that
  # have none, which osv-scanner reports as extraction errors rather than as findings.
  # The report path is this run's own output. Deleting only that file before the scan runs
  # means a leftover from an earlier run can never make this run look clean: if the process
  # dies before it writes, there is no report to believe.
  osv_args=(scan source --format sarif --no-resolve -r "$TARGET" --output-file "$OUT/osv.sarif")
  [ -e "$TARGET/package-lock.json" ] && osv_args+=(--lockfile "$TARGET/package-lock.json")
  [ -e "$TARGET/yarn.lock" ] && osv_args+=(--lockfile "$TARGET/yarn.lock")
  [ -e "$TARGET/pnpm-lock.yaml" ] && osv_args+=(--lockfile "$TARGET/pnpm-lock.yaml")
  [ -e "$TARGET/Cargo.lock" ] && osv_args+=(--lockfile "$TARGET/Cargo.lock")
  osv_rc=0
  osv_out=$(osv-scanner "${osv_args[@]}" 2>&1) || osv_rc=$?
  echo "$osv_out" >>"$OUT/.log"
  # The vulnerability database is remote. A failed query batch leaves an empty report that
  # is indistinguishable from a clean one; osv reports it as "Error during extraction" and
  # can still exit 0, so neither the exit code nor the report alone can carry this.
  if printf '%s\n' "$osv_out" | grep -qiE 'max retries exceeded|api\.osv\.dev[^[:space:]]*(forbidden|no such host|timeout|refused)|dial tcp'; then
    note "ERROR — api.osv.dev unreachable, result is NOT a clean bill of health"
    record osv error osv_backend_unreachable "api.osv.dev unreachable"
  elif [ $osv_rc -eq 0 ] && sarif_report shape "$OUT/osv.sarif"; then
    n=$(sarif_finding_count "$OUT/osv.sarif")
    if [ "$n" != 0 ]; then
      note "ok — $n vulnerable package link(s)"
      record osv ok completed "$n findings"
    else
      note "ok — no known vulnerabilities in the locked dependencies"
      record osv ok completed "scanned, 0 findings"
    fi
  elif [ $osv_rc -eq 1 ] && sarif_report shape "$OUT/osv.sarif"; then
    # Exit 1 is also how osv-scanner spells "vulnerabilities found", so a usable report is
    # the evidence; an empty one is not a pass and is reported as the exit it came with.
    n=$(sarif_finding_count "$OUT/osv.sarif")
    if [ "$n" != 0 ]; then
      note "ok — $n vulnerable package link(s) (exit 1)"
      record osv ok completed "$n findings"
    else
      note "error (exit 1) — report has no results, see $OUT/.log"
      record osv error report_invalid_shape "exit 1, report has no results"
    fi
  else
    # A usable report paired with an abnormal exit is still an execution failure; preserve
    # that distinction from a missing or malformed report.
    if sarif_report shape "$OUT/osv.sarif"; then
      note "error (exit $osv_rc) — abnormal exit with usable report, see $OUT/.log"
      record osv error scanner_exit_failure "exit $osv_rc, usable report"
    else
      report_rc=$?
      note "error (exit $osv_rc) — no usable report, see $OUT/.log"
      record osv error "$(sarif_reason "$report_rc")" "exit $osv_rc, no usable report"
    fi
  fi
fi

# ---------------------------------------------------------------- gitleaks
printf '\nGitleaks\n'
rm -f "$OUT/gitleaks.sarif"
if command -v gitleaks >/dev/null 2>&1; then
  # --exit-code 0 keeps findings from changing the exit code, so any non-zero status here is
  # gitleaks itself failing (stat error, unwritable report path). Record it instead of
  # asserting ok, and check the report shape regardless.
  gitleaks dir "$TARGET" --report-format sarif --report-path "$OUT/gitleaks.sarif" \
    --no-banner --exit-code 0 >>"$OUT/.log" 2>&1
  gl_rc=$?
  if [ $gl_rc -ne 0 ]; then
    note "error (exit $gl_rc) — gitleaks failed, see $OUT/.log"
    record gitleaks error scanner_exit_failure "exit $gl_rc, gitleaks failed"
  elif sarif_report shape "$OUT/gitleaks.sarif"; then
    n=$(sarif_finding_count "$OUT/gitleaks.sarif")
    if [ "$n" != 0 ]; then
      note "ok — $n potential secret(s)"
      record gitleaks ok completed "$n findings"
    else
      note "ok — no secrets found"
      record gitleaks ok completed "scanned, 0 findings"
    fi
  else
    report_rc=$?
    note "error (exit 0) — no usable report, see $OUT/.log"
    record gitleaks error "$(sarif_reason "$report_rc")" "exit 0, no usable report"
  fi
else
  note "error — gitleaks not installed"
  record gitleaks error executable_missing "not installed"
fi

# ---------------------------------------------------------------- status
printf '[%s]\n' "$(IFS=,; echo "${entries[*]}")" > "$STATUS"
err=$(grep -o '"status":"error"' "$STATUS" 2>/dev/null | wc -l | tr -d ' ')
[ "$err" != "0" ] && note "warning — $err scanner(s) recorded error, see $STATUS and $OUT/.log"
printf '\nSARIF in %s\n' "$OUT"
exit 0
