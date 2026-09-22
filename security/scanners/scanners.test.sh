#!/usr/bin/env bash
#
# Regression for security/scanners/run-scanners.sh — scanner AUFTRITT and result accounting.
# No network, no live model, no real scanner: every tool on PATH is a fake in a mktemp bin,
# so the runner is tested offline on a machine that has none of the three installed.
#
# What this locks down (all of it measured on the 97d7bd7 baseline first):
#   - Cargo.lock admits the OSV scan (a Rust wallet was skipped entirely before), and each
#     JS lockfile admits it on its own; no lockfile at all is the only "no lockfile" skip.
#   - The scan is invoked through `osv-scanner scan source` with the report flag, and only
#     the lockfiles that exist are passed — a Rust target never sees a JS lockfile flag.
#   - The OSV backend being unreachable is "error" with reasonCode osv_backend_unreachable,
#     exits 0 (measured: osv-scanner 2.5.0 prints "max retries exceeded" and exits 0).
#   - A scanner crash, a missing report and a malformed report are "error", not "ok";
#     a genuine finding is "ok" with a count, not an execution failure.
#   - Gitleaks can no longer record ok unconditionally.
#   - Missing executables are errors unless a target is not applicable; the runner still exits 0.
#   - The runner itself always exits 0 (report-only convention) and scanners.json stays a
#     JSON array of {tool,status,reasonCode,detail}.
#   - normalize.mjs still turns status "error" into exit 1 under --no-gate, and still does
#     not turn a clean scan into a failure — otherwise these records would be decoration.
#
# Exit: 0 all passed, 1 one or more failed. Summary: "N/M Fälle bestanden"

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNNER="$ROOT/security/scanners/run-scanners.sh"
NORMALIZE="$ROOT/security/scanners/normalize.mjs"
# The counterprobe suite runs the same cases against the pre-fix runner (see CP-0 below).
BASELINE_RUNNER="${BASELINE_RUNNER:-}"

PASS=0
FAIL=0
TOTAL=0

WORK=
cleanup() {
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT
WORK="$(mktemp -d "${TMPDIR:-/tmp}/scanners-test.XXXXXX")"

# The runner's report check needs node, and the isolated PATH below deliberately does not
# include /opt/homebrew/bin where this machine's node lives. Captured once here, while the
# ambient PATH is still in view, and linked into a directory the scenarios may use.
NODE_BIN="$(command -v node)"
[ -n "$NODE_BIN" ] || { echo "node is required to run this suite" >&2; exit 1; }
CBIN="$WORK/common-bin"
mkdir -p "$CBIN"
ln -s "$NODE_BIN" "$CBIN/node"

# All cases write into $WORK. Everything below lives in there or in this file's own scope —
# no case ever touches a path that was not created by a mktemp above.
#
# Case bodies run inline (never inside a command substitution), so the PASS/FAIL/TOTAL
# increments they make are the global ones. Helpers that only report a value (status_of,
# detail_of, available_path) are read-only and safe to capture.

case_result() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL + 1))
  if [ "$ok" = "1" ]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"
    [ -n "$detail" ] && printf '         %s\n' "$detail"
  fi
}

# Run command; set RUN_RC and RUN_OUT (stdout+stderr). Never aborts the suite.
run() {
  set +e
  RUN_OUT="$("$@" 2>&1)"
  RUN_RC=$?
  set -e
  return 0
}

short() { echo "$1" | tr '\n' ' ' | cut -c1-220; }

# ---------------------------------------------------------------- fixtures
#
# One bin directory per scenario directory (the environment is a flat namespace; scenario
# names are distinct). The fakes obey the real interfaces measured on this machine:
#   semgrep    --sarif --output <file> <dir>, exit 1 with findings, 2 with a broken rule
#   osv-scanner scan source --format sarif [--output-file f] [--lockfile f] [-r dir],
#              exit 0 on a clean scan and also on an unreachable backend
#   gitleaks   dir <dir> --report-format sarif --report-path f --exit-code 0, exit 0 for
#              any finding count; non-zero only when gitleaks itself failed
# Every fake writes what it wrote and how it was called to $FAKE_CALLS.

LOCKFILE_NAMES=(package-lock.json yarn.lock pnpm-lock.yaml Cargo.lock)

new_case() { # <name> -> sets BIN, TG, OUT, FAKE_CALLS; target dir is empty
  local name="$1"
  BIN="$WORK/bin-$name"
  TG="$WORK/tgt-$name"
  OUT="$WORK/out-$name"
  mkdir -p "$BIN" "$TG" "$OUT"
  FAKE_CALLS="$WORK/calls-$name"
  : > "$FAKE_CALLS"
}

put_fake() { # <name> <tool> <script-body>
  local name="$1" tool="$2" body="$3"
  printf '#!/bin/sh\n%s\n' "$body" > "$WORK/bin-$name/$tool"
  chmod +x "$WORK/bin-$name/$tool"
}

# Common prologue: record argv, extract the report path from the supported flag spellings,
# and honour FAKE_EXIT so a case can override the exit code without writing a new fake
# (FAKE_EXIT=2 is the "the scanner process died" knob).
CALLS_PROLOGUE='printf "TOOL=%s ARGS=%s\n" "$0" "$*" >> "${FAKE_CALLS:-/dev/null}"
out=""
prev=""
for a in "$@"; do
  case "$prev" in
    --output|--output-file|--report-path) out="$a" ;;
  esac
  prev="$a"
done
[ -n "${FAKE_EXIT:-}" ] && exit "$FAKE_EXIT"'

SARIF_EMPTY='{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"FAKE","rules":[]}},"results":[]}]}'
# One error-level finding on src/main.rs line 1 — blocking for normalize.mjs.
SARIF_FINDING='{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"FAKE","rules":[]}},"results":[{"ruleId":"fake-finding","level":"error","message":{"text":"fake finding for scanner accounting test"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/main.rs"},"region":{"startLine":1}}}]}]}]}'

# semgrep that finds nothing (exit 0) and writes an empty report.
fake_semgrep_clean() {
  put_fake "$1" semgrep "$CALLS_PROLOGUE
printf '%s\n' '$SARIF_EMPTY' > \"\$out\"
exit 0"
}

# osv-scanner that scans successfully: $2 = empty|finding|malformed|missing.
fake_osv() { # <name> <report> [extra exit override]
  local name="$1" report="$2" rc="${3:-0}" body
  case "$report" in
    empty) body="printf '%s\n' '$SARIF_EMPTY' > \"\$out\"" ;;
    finding) body="printf '%s\n' '$SARIF_FINDING' > \"\$out\"" ;;
    malformed) body="printf '%s\n' '{\"runs\": [{\"results\":' > \"\$out\"" ;;
    missing) body="" ;;
    *) echo "fake_osv: unknown report kind: $report" >&2; return 2 ;;
  esac
  put_fake "$name" osv-scanner "$CALLS_PROLOGUE
$body
exit $rc"
}

# gitleaks that scans successfully. GITLEAKS_FINDINGS=1 reports a real secret; gitleaks
# still exits 0 for a finding because the runner passes --exit-code 0.
fake_gitleaks() { # <name> [finding|clean|crash]
  local name="$1" kind="${2:-clean}" body rc=0
  case "$kind" in
    clean) body="printf '%s\n' '$SARIF_EMPTY' > \"\$out\"" ;;
    finding) body="printf '%s\n' '$SARIF_FINDING' > \"\$out\"" ;;
    crash) body="printf '%s\n' 'fake gitleaks crash' >&2" ;;
  esac
  [ "$kind" = "crash" ] && rc=1
  put_fake "$name" gitleaks "$CALLS_PROLOGUE
$body
exit $rc"
}

# Only this scenario's fakes are on PATH, plus the node captured below and the system
# directories. Nothing installed by the machine (a real osv-scanner, semgrep or gitleaks in
# /opt/homebrew/bin) is reachable, so "not installed" scenarios really do lack the binary;
# a case that fakes nothing sees no scanner at all.
run_runner() { # <name> [runner path] — runs the real runner with only this scenario's fakes
  local name="$1" runner="${2:-$RUNNER}"
  run env PATH="$WORK/bin-$name:$CBIN:/usr/bin:/bin" \
    FAKE_CALLS="$WORK/calls-$name" \
    bash "$runner" "$TG" "$OUT"
}

# Extract one tool's record from scanners.json without jq.
status_of() {
  node -e '
    const fs = require("fs");
    const list = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const hit = list.find((s) => s.tool === process.argv[2]);
    process.stdout.write(hit ? hit.status : "absent");
  ' "$OUT/scanners.json" "$1" 2>/dev/null || echo "unreadable"
}
detail_of() {
  node -e '
    const fs = require("fs");
    const list = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const hit = list.find((s) => s.tool === process.argv[2]);
    process.stdout.write(hit ? hit.detail : "");
  ' "$OUT/scanners.json" "$1" 2>/dev/null || echo ""
}
reason_of() {
  local dir="${2:-$OUT}"
  node -e '
    const fs = require("fs");
    const list = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const hit = list.find((s) => s.tool === process.argv[2]);
    process.stdout.write(hit ? hit.reasonCode : "");
  ' "$dir/scanners.json" "$1" 2>/dev/null || echo ""
}

# Assert a case: name, condition command, and the evidence string to print on failure.
check() { # <name> <condition-argv...>
  local name="$1"; shift
  if "$@"; then
    case_result "$name" 1
  else
    case_result "$name" 0 "rc=$RUN_RC status=$(status_of osv)/$(status_of gitleaks)/$(status_of semgrep) detail=$(detail_of osv) calls=$(tr '\n' '|' < "$FAKE_CALLS" | cut -c1-160) out=$(short "$RUN_OUT")"
  fi
}

# Run the real normalize.mjs against a case's OUT directory; exit code lands in
# $NORMALIZE_RC, its output in $WORK/normalize.log and the findings in the out file.
# $2 is passed through verbatim, so "--no-gate" records findings without gating on them.
# Node is called by absolute path, so this never depends on the ambient PATH.
normalize_exit() { # <sarif dir> [extra normalize flags] [out file]
  local out="${3:-$WORK/normalize-findings.json}"
  set +e
  if [ -n "${2:-}" ]; then
    "$NODE_BIN" "$NORMALIZE" --sarif "$1" --out "$out" $2 >"$WORK/normalize.log" 2>&1
  else
    "$NODE_BIN" "$NORMALIZE" --sarif "$1" --out "$out" >"$WORK/normalize.log" 2>&1
  fi
  NORMALIZE_RC=$?
  set -e
  NORMALIZE_OUT="$out"
}

# ---------------------------------------------------------------- 1–5: OSV admission

echo "=== OSV-Scanner: lockfile admission ==="

# 1. Cargo.lock alone. This is the defect: the baseline skipped the whole dependency scan
#    of the Rust wallet, and the record read "skipped — no lockfile".
{
  new_case admit-cargo
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv admit-cargo empty
  fake_gitleaks admit-cargo
  fake_semgrep_clean admit-cargo
  run_runner admit-cargo
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "ok" ]; then
    case_result "admission: Cargo.lock alone runs the OSV scan" 1
  else
    case_result "admission: Cargo.lock alone runs the OSV scan" 0 \
      "rc=$RUN_RC osv=$(status_of osv) detail=$(detail_of osv) out=$(short "$RUN_OUT")"
  fi
}

# 2. The interface must stay `osv-scanner scan source`, otherwise the pinned 2.x interface
#    is replaced by the deprecated top-level command.
{
  if grep -q 'ARGS=scan source' "$FAKE_CALLS"; then
    case_result "admission: invoked as 'osv-scanner scan source'" 1
  else
    case_result "admission: invoked as 'osv-scanner scan source'" 0 "calls=$(short "$(cat "$FAKE_CALLS")")"
  fi
}

# 3–5. Each JS lockfile admits the scan on its own (measured baseline: all three also
#      recorded "skipped — no lockfile", because `ls a b c` under `!` skipped unless ALL
#      were absent — so the guard was wrong for one-or-two-present, not just for Rust).
for lf in package-lock.json yarn.lock pnpm-lock.yaml; do
  name="admit-$(echo "$lf" | tr -cd 'a-z.-' | tr '.' '-')"
  {
    new_case "$name"
    echo '{}' > "$TG/$lf"
    fake_osv "$name" empty
    fake_gitleaks "$name"
    fake_semgrep_clean "$name"
    run_runner "$name"
    if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "ok" ]; then
      case_result "admission: $lf alone runs the OSV scan" 1
    else
      case_result "admission: $lf alone runs the OSV scan" 0 \
        "rc=$RUN_RC osv=$(status_of osv) detail=$(detail_of osv) out=$(short "$RUN_OUT")"
    fi
  }
done

# 6. No lockfile at all is a genuine skip, and no OSV process may run.
{
  new_case admit-none
  echo 'fn main() {}' > "$TG/main.rs"
  fake_osv admit-none empty
  fake_gitleaks admit-none
  fake_semgrep_clean admit-none
  printf '%s\n' "$SARIF_FINDING" > "$OUT/osv.sarif"
  printf '%s\n' 'preserve unrelated report' > "$OUT/unrelated.sarif"
  run_runner admit-none
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "skipped" ] \
    && [ "$(reason_of osv)" = "not_applicable_no_lockfile" ] \
    && [ "$(detail_of osv)" = "no lockfile" ] \
    && ! grep -q 'TOOL=.*osv' "$FAKE_CALLS" \
    && [ ! -e "$OUT/osv.sarif" ] && [ -f "$OUT/unrelated.sarif" ]; then
    case_result "admission: no lockfile skips the OSV scan and runs no process" 1
  else
    case_result "admission: no lockfile skips the OSV scan and runs no process" 0 \
      "rc=$RUN_RC osv=$(status_of osv)/$(detail_of osv) calls=$(short "$(cat "$FAKE_CALLS")")"
  fi
}

# 7. Only present lockfiles are passed as --lockfile. Passing a JS lockfile for a Rust tree
#    is how a scan silently becomes a 127 "failed to resolve path".
{
  new_case args-cargo
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv args-cargo empty
  fake_gitleaks args-cargo
  fake_semgrep_clean args-cargo
  run_runner args-cargo
  calls="$(cat "$WORK/calls-args-cargo")"
  if printf '%s' "$calls" | grep -q -- '--lockfile .*Cargo.lock' \
    && ! printf '%s' "$calls" | grep -q -- '--lockfile .*package-lock.json' \
    && ! printf '%s' "$calls" | grep -q -- '--lockfile .*yarn.lock' \
    && ! printf '%s' "$calls" | grep -q -- '--lockfile .*pnpm-lock.yaml'; then
    case_result "args: a Cargo.lock target is scanned with the Cargo lockfile only" 1
  else
    case_result "args: a Cargo.lock target is scanned with the Cargo lockfile only" 0 \
      "calls=$(short "$calls")"
  fi
}

# 8. And the JS side keeps working: two JS lockfiles present, both passed, Cargo absent.
{
  new_case args-js
  echo '{}' > "$TG/package-lock.json"
  echo 'fake' > "$TG/yarn.lock"
  fake_osv args-js empty
  fake_gitleaks args-js
  fake_semgrep_clean args-js
  run_runner args-js
  calls="$(cat "$WORK/calls-args-js")"
  if printf '%s' "$calls" | grep -q -- '--lockfile .*package-lock.json' \
    && printf '%s' "$calls" | grep -q -- '--lockfile .*yarn.lock' \
    && ! printf '%s' "$calls" | grep -q -- '--lockfile .*Cargo.lock'; then
    case_result "args: present JS lockfiles are passed, absent Cargo is not" 1
  else
    case_result "args: present JS lockfiles are passed, absent Cargo is not" 0 "calls=$(short "$calls")"
  fi
}

# 9. The report flag must be one the installed interface supports. `--output` is deprecated
#    in osv-scanner 2.x and is the sibling of the flag that silently swallowed output before.
{
  calls="$(cat "$WORK/calls-args-js")"
  if printf '%s' "$calls" | grep -qE -- '--output(-file)? '; then
    case_result "args: OSV report path passed via a supported report flag" 1
  else
    case_result "args: OSV report path passed via a supported report flag" 0 "calls=$(short "$calls")"
  fi
}

# ---------------------------------------------------------------- 10–15: OSV accounting

echo "=== OSV-Scanner: result accounting ==="

# 10. Backend unreachable, process exits 0. Measured on this machine with a dead proxy:
#     osv-scalibr prints "Error during extraction: ... max retries exceeded ... connection
#     refused", writes an empty report and exits 0. An empty report cannot be a pass.
{
  new_case osv-backend
  echo 'version = 3' > "$TG/Cargo.lock"
  put_fake osv-backend osv-scanner "$CALLS_PROLOGUE
printf '%s\n' '$SARIF_EMPTY' > \"\$out\"
printf '%s\n' 'Error during extraction: (extracting as vulnmatch/osvdev) max retries exceeded: attempt 4: request failed: Post \"https://api.osv.dev/v1/querybatch\": proxyconnect tcp: dial tcp 127.0.0.1:1: connect: connection refused' >&2
exit 0"
  fake_gitleaks osv-backend
  fake_semgrep_clean osv-backend
  run_runner osv-backend
  check "accounting: unreachable OSV backend is an error with a machine reason" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "error" \
      -a "$(reason_of osv)" = "osv_backend_unreachable"
}

# 11. An abnormal exit with a usable report is still an execution error.
{
  new_case osv-crash
  echo 'version = 3' > "$TG/Cargo.lock"
  put_fake osv-crash osv-scanner "$CALLS_PROLOGUE
printf '%s\n' '$SARIF_EMPTY' > \"\$out\"
printf '%s\n' 'panic: runtime error: index out of range [0] with length 0' >&2
exit 2"
  fake_gitleaks osv-crash
  fake_semgrep_clean osv-crash
  run_runner osv-crash
  check "accounting: OSV abnormal exit with report is scanner_exit_failure" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "error" \
      -a "$(reason_of osv)" = "scanner_exit_failure"
}

# 12. Exit 0 but the report was never written — the exact shape a pass-if-exit-code-only
#     implementation would score as clean.
{
  new_case osv-missing-report
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv osv-missing-report missing 0
  fake_gitleaks osv-missing-report
  fake_semgrep_clean osv-missing-report
  run_runner osv-missing-report
  check "accounting: exit 0 with no OSV report is report_missing" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "error" \
      -a "$(reason_of osv)" = "report_missing"
}

# 13. A report that is not SARIF (truncated write) is an error.
{
  new_case osv-malformed
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv osv-malformed malformed 0
  fake_gitleaks osv-malformed
  fake_semgrep_clean osv-malformed
  run_runner osv-malformed
  check "accounting: a malformed OSV report has report_malformed reason" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "error" \
      -a "$(reason_of osv)" = "report_malformed"
}

# 14. A genuine finding is a successful scan. The exit code and the record must not read as
#     an execution failure, or every vulnerable dependency turns the gate red for nothing.
{
  new_case osv-finding
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv osv-finding finding 0
  fake_gitleaks osv-finding
  fake_semgrep_clean osv-finding
  run_runner osv-finding
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "ok" ] && [ -s "$OUT/osv.sarif" ]; then
    case_result "accounting: an OSV finding is ok with a report on disk" 1
  else
    case_result "accounting: an OSV finding is ok with a report on disk" 0 \
      "rc=$RUN_RC osv=$(status_of osv) detail=$(detail_of osv) sarif=$([ -s "$OUT/osv.sarif" ] && echo yes || echo no)"
  fi
}

# 15. A clean scan with a valid empty report is ok.
{
  new_case osv-clean
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv osv-clean empty 0
  fake_gitleaks osv-clean
  fake_semgrep_clean osv-clean
  run_runner osv-clean
  check "accounting: a clean OSV scan is ok" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "ok"
}

# ---------------------------------------------------------------- 16–19: gitleaks accounting

echo "=== Gitleaks: result accounting ==="

# 16. The baseline recorded ok unconditionally — a gitleaks that died without a report
#     looked identical to a clean scan.
{
  new_case gl-crash
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv gl-crash empty
  fake_gitleaks gl-crash crash
  fake_semgrep_clean gl-crash
  run_runner gl-crash
  check "gitleaks: a crash is an error with scanner_exit_failure reason" \
    test "$RUN_RC" -eq 0 -a "$(status_of gitleaks)" = "error" \
      -a "$(reason_of gitleaks)" = "scanner_exit_failure"
}

# 17. Exit 0 with no report at all.
{
  new_case gl-noreport
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv gl-noreport empty
  put_fake gl-noreport gitleaks "$CALLS_PROLOGUE
exit 0"
  fake_semgrep_clean gl-noreport
  run_runner gl-noreport
  check "gitleaks: exit 0 with no report is report_missing" \
    test "$RUN_RC" -eq 0 -a "$(status_of gitleaks)" = "error" \
      -a "$(reason_of gitleaks)" = "report_missing"
}

# 18. A real secret is not an execution failure; the runner passes --exit-code 0 precisely
#     so findings cannot change the exit code.
{
  new_case gl-finding
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv gl-finding empty
  fake_gitleaks gl-finding finding
  fake_semgrep_clean gl-finding
  run_runner gl-finding
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of gitleaks)" = "ok" ] \
    && grep -q -- '--exit-code 0' "$WORK/calls-gl-finding"; then
    case_result "gitleaks: a finding is ok and --exit-code 0 is kept" 1
  else
    case_result "gitleaks: a finding is ok and --exit-code 0 is kept" 0 \
      "rc=$RUN_RC gl=$(status_of gitleaks) calls=$(short "$(cat "$WORK/calls-gl-finding")")"
  fi
}

# 19. Clean scan stays ok.
{
  new_case gl-clean
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv gl-clean empty
  fake_gitleaks gl-clean clean
  fake_semgrep_clean gl-clean
  run_runner gl-clean
  check "gitleaks: a clean scan is ok" \
    test "$RUN_RC" -eq 0 -a "$(status_of gitleaks)" = "ok"
}

# ---------------------------------------------------------------- 20–22: conventions

echo "=== konventionen: exit, schema, missing binaries ==="

# 20. One tool missing, the others fine: the run still exits 0 and the missing tool is
#     recorded as an execution error. Missing executables are not authorized optional skips.
{
  new_case no-osv
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_gitleaks no-osv
  fake_semgrep_clean no-osv
  run_runner no-osv
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "error" ]     && [ "$(reason_of osv)" = "executable_missing" ] && [ "$(status_of gitleaks)" = "ok" ]; then
    case_result "convention: a missing scanner is an executable error, runner exits 0" 1
  else
    case_result "convention: a missing scanner is an executable error, runner exits 0" 0 \
      "rc=$RUN_RC osv=$(status_of osv) gl=$(status_of gitleaks)"
  fi
}

# 21. Report-only exit convention: every tool failing at once must not make the runner
#     exit non-zero. The blocking decision belongs to normalize.mjs.
{
  new_case all-broken
  echo 'version = 3' > "$TG/Cargo.lock"
  put_fake all-broken osv-scanner "$CALLS_PROLOGUE
exit 2"
  put_fake all-broken gitleaks "$CALLS_PROLOGUE
exit 1"
  put_fake all-broken semgrep "$CALLS_PROLOGUE
exit 2"
  run_runner all-broken
  check "convention: the runner always exits 0, even with every scanner broken" \
    test "$RUN_RC" -eq 0
}

# 22. scanners.json stays a JSON array of the three records with the documented keys, and
#     the error records are readable JSON (an unescaped detail would break normalize.mjs).
{
  new_case schema
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv schema empty
  fake_gitleaks schema crash
  fake_semgrep_clean schema
  run_runner schema
  run node -e '
    const fs = require("fs");
    const list = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!Array.isArray(list)) process.exit(2);
    const tools = list.map((s) => s.tool).sort().join(",");
    if (tools !== "gitleaks,osv,semgrep") process.exit(3);
    for (const s of list) {
      if (typeof s.status !== "string" || typeof s.reasonCode !== "string" ||
          typeof s.detail !== "string") process.exit(4);
      if (!["ok", "skipped", "error", "degraded"].includes(s.status)) process.exit(5);
    }
  ' "$OUT/scanners.json"
  check "schema: scanners.json stays an array of {tool,status,reasonCode,detail}" \
    test "$RUN_RC" -eq 0
}

# ---------------------------------------------------------------- 22b–22e: report-shape accounting
#
# Four behaviours the grep-based check could not tell apart. Each one is a report the runner
# must judge from its content, not from the process' exit code.

# Valid SARIF with the optional "results" property omitted is a completed clean scan.
{
  new_case osv-noresults
  echo 'version = 3' > "$TG/Cargo.lock"
  put_fake osv-noresults osv-scanner "$CALLS_PROLOGUE
printf '%s\n' '{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"FAKE\"}}}]}' > \"\$out\"
exit 0"
  fake_gitleaks osv-noresults
  fake_semgrep_clean osv-noresults
  run_runner osv-noresults
  check "accounting: valid clean SARIF without the optional results field is ok" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "ok"
}

# A report left over from an earlier run must not vouch for this one: the process is called
# and writes nothing, so the only report on disk is stale.
{
  new_case osv-stale
  echo 'version = 3' > "$TG/Cargo.lock"
  printf '%s\n' "$SARIF_EMPTY" > "$OUT/osv.sarif"
  put_fake osv-stale osv-scanner "$CALLS_PROLOGUE
exit 0"
  fake_gitleaks osv-stale
  fake_semgrep_clean osv-stale
  run_runner osv-stale
  check "accounting: a stale OSV report is not a pass for this run" \
    test "$RUN_RC" -eq 0 -a "$(status_of osv)" = "error"
}

# OSV's own "findings found" spelling is exit 1. With a report that really carries a
# result, that is a completed scan, not a crash.
{
  new_case osv-exit1-finding
  echo 'version = 3' > "$TG/Cargo.lock"
  fake_osv osv-exit1-finding finding 1
  fake_gitleaks osv-exit1-finding
  fake_semgrep_clean osv-exit1-finding
  run_runner osv-exit1-finding
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of osv)" = "ok" ]; then
    case_result "accounting: OSV exit 1 with a finding report is ok, not an error" 1
  else
    case_result "accounting: OSV exit 1 with a finding report is ok, not an error" 0 \
      "rc=$RUN_RC osv=$(status_of osv)/$(detail_of osv)"
  fi
  normalize_exit "$OUT"
  # Same evidence as the finding case below, only with the findings gate left active: a
  # genuine vulnerability found through OSV exit 1 must block like any other finding and
  # must not be swallowed as a tool failure.
  if [ "$NORMALIZE_RC" -eq 1 ] && grep -q 'fake-finding' "$WORK/normalize-findings.json" \
    && grep -q '1 blocking' "$WORK/normalize.log"; then
    case_result "normalize: the OSV exit 1 finding blocks like any other finding" 1
  else
    case_result "normalize: the OSV exit 1 finding blocks like any other finding" 0 \
      "rc=$NORMALIZE_RC log=$(short "$(cat "$WORK/normalize.log")")"
  fi
}

# Semgrep's exit 2 covers both "a rule failed to parse" and "the scan died". A valid partial
# report is only ok when the run says which rule broke; otherwise it is not a pass.
{
  new_case semgrep-rc2-partial
  echo 'fn main() {}' > "$TG/main.rs"
  put_fake semgrep-rc2-partial semgrep "$CALLS_PROLOGUE
printf '%s\n' 'Rule parse error in rule \"fake.rule.a\": invalid pattern' >&2
printf '%s\n' '$SARIF_FINDING' > \"\$out\"
exit 2"
  fake_osv semgrep-rc2-partial empty
  fake_gitleaks semgrep-rc2-partial
  run_runner semgrep-rc2-partial
  if [ "$RUN_RC" -eq 0 ] && [ "$(status_of semgrep)" = "degraded" ] \
    && [ "$(reason_of semgrep)" = "semgrep_rule_parse_error" ] \
    && printf '%s' "$(detail_of semgrep)" | grep -qi 'rule parse error'; then
    case_result "semgrep: exit 2 naming a broken rule is degraded with the reason" 1
  else
    case_result "semgrep: exit 2 naming a broken rule is degraded with the reason" 0 \
      "rc=$RUN_RC semgrep=$(status_of semgrep)/$(detail_of semgrep)"
  fi
}

# The same exit 2 with a valid report that says nothing about a rule error is an
# unexplained abnormal end — never recorded ok.
{
  new_case semgrep-rc2-silent
  echo 'fn main() {}' > "$TG/main.rs"
  put_fake semgrep-rc2-silent semgrep "$CALLS_PROLOGUE
printf '%s\n' '$SARIF_FINDING' > \"\$out\"
exit 2"
  fake_osv semgrep-rc2-silent empty
  fake_gitleaks semgrep-rc2-silent
  run_runner semgrep-rc2-silent
  check "semgrep: exit 2 with a valid but unexplained report is scanner_exit_failure" \
    test "$RUN_RC" -eq 0 -a "$(status_of semgrep)" = "error" \
      -a "$(reason_of semgrep)" = "scanner_exit_failure"
}

# ---------------------------------------------------------------- 23–26: the records have teeth

echo "=== normalize.mjs liest die Status (H2-Kette) ==="

# The runner's records only matter if the next stage acts on them. These run the real
# normalize.mjs (helper above) against the OUT directories the cases above produced.
# No network, no model.

# 23. The error case must make normalize exit non-zero even under --no-gate, and name both
#     the tool and the detail.
{
  normalize_exit "$WORK/out-osv-crash"
  if [ "$NORMALIZE_RC" -ne 0 ] && [ "$(reason_of osv "$WORK/out-osv-crash")" = "scanner_exit_failure" ] \
    && grep -q 'osv' "$WORK/normalize.log"; then
    case_result "normalize: OSV error record exits non-zero naming tool and detail" 1
  else
    case_result "normalize: OSV error record exits non-zero naming tool and detail" 0 \
      "rc=$NORMALIZE_RC log=$(short "$(cat "$WORK/normalize.log")")"
  fi
}

# 24. A backend-unreachable record is an execution error even though the report-only runner
#     exits 0. normalize must fail before any empty result can look clean.
{
  normalize_exit "$WORK/out-osv-backend"
  if [ "$NORMALIZE_RC" -ne 0 ] && grep -q 'osv' "$WORK/normalize.log" \
    && grep -q 'api.osv.dev unreachable' "$WORK/normalize.log"; then
    case_result "normalize: unreachable backend exits non-zero with detail" 1
  else
    case_result "normalize: unreachable backend exits non-zero with detail" 0 \
      "rc=$NORMALIZE_RC log=$(short "$(cat "$WORK/normalize.log")")"
  fi
}

# 25. A clean scan must not become a failure.
{
  normalize_exit "$WORK/out-osv-clean"
  if [ "$NORMALIZE_RC" -eq 0 ]; then
    case_result "normalize: a clean OSV scan exits 0" 1
  else
    case_result "normalize: a clean OSV scan exits 0" 0 \
      "rc=$NORMALIZE_RC log=$(short "$(cat "$WORK/normalize.log")")"
  fi
}

# 26. The finding must reach findings.json and block. Findings gate active, so exit 1 here
#     is the FINDINGS decision, not a tool failure (normalize's own convention).
{
  set +e
  node "$NORMALIZE" --sarif "$WORK/out-osv-finding" --out "$WORK/finding-findings.json" \
    >"$WORK/normalize-finding.log" 2>&1
  NORMALIZE_RC=$?
  set -e
  HIT="0"
  if [ -f "$WORK/finding-findings.json" ]; then
    HIT="$(node -e '
      const fs = require("fs");
      const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const hit = (j.findings || []).some((f) => f.tool === "osv-scanner" || f.ruleId === "fake-finding");
      process.stdout.write(hit ? "1" : "0");
    ' "$WORK/finding-findings.json" 2>/dev/null)"
  fi
  if [ "$NORMALIZE_RC" -eq 1 ] && [ "$HIT" = "1" ]; then
    case_result "normalize: the OSV finding reaches findings.json and blocks" 1
  else
    case_result "normalize: the OSV finding reaches findings.json and blocks" 0 \
      "rc=$NORMALIZE_RC hit=$HIT log=$(short "$(cat "$WORK/normalize-finding.log")")"
  fi
}

# ---------------------------------------------------------------- counterprobe: the wrong fix
#
# "Trust the exit code." osv-scanner exits 0 for a clean scan, for a backend that never
# answered, and — the trap — for a scan that produced nothing at all. Same code, three
# different stories, so the accounting must come from the report. This suite runs the same
# cases against the pre-fix runner; the OSV cases below are expected to FAIL there.

echo "=== gegenprobe: 'exit 0 heißt ok' (Baseline 97d7bd7) ==="
{
  if [ -z "$BASELINE_RUNNER" ] || [ ! -f "$BASELINE_RUNNER" ]; then
    echo "  (BASELINE_RUNNER nicht gesetzt — Gegenprobe übersprungen)"
  else
    # CP-0 sanity: the baseline copy must still carry the JS-only guard, otherwise this
    # counterprobe says nothing about the pre-fix behaviour.
    if grep -q 'ls "\$TARGET"/package-lock.json' "$BASELINE_RUNNER" \
      && ! grep -q 'Cargo.lock' "$BASELINE_RUNNER"; then
      case_result "counterprobe baseline is the pre-fix runner (JS-only guard, no Cargo)" 1
    else
      case_result "counterprobe baseline is the pre-fix runner (JS-only guard, no Cargo)" 0 \
        "baseline=$BASELINE_RUNNER"
    fi

    cp_baseline_case() { # <name> <lockfile-or-none> — the lockfile gets plausible content
      local name="$1"; shift
      new_case "cp-$name"
      local lf="${1:-}"; shift || true
      if [ "$lf" = package-lock.json ] || [ "$lf" = yarn.lock ] || [ "$lf" = pnpm-lock.yaml ]; then
        echo '{}' > "$TG/$lf"
      elif [ -n "$lf" ]; then
        echo 'version = 3' > "$TG/$lf"
      fi
      fake_osv "cp-$name" empty
      fake_gitleaks "cp-$name"
      fake_semgrep_clean "cp-$name"
    }

    # CP-1: on the baseline, a Cargo.lock target must read "skipped — no lockfile".
    {
      cp_baseline_case cargo Cargo.lock
      run_runner "cp-cargo" "$BASELINE_RUNNER"
      if [ "$(status_of osv)" = "skipped" ] && [ "$(detail_of osv)" = "no lockfile" ]; then
        case_result "counterprobe (expected FAIL after the fix): baseline skips a Cargo-only target" 1
      else
        case_result "counterprobe (expected FAIL after the fix): baseline skips a Cargo-only target" 0 \
          "osv=$(status_of osv)/$(detail_of osv) — die Baseline-Ziffer ist damit nicht belegt"
      fi
    }

    # CP-2: exit 0 + no report at all must read "ok" on the baseline — the wrong
    # implementation the report-shape check exists to prevent. The baseline's `ls` guard
    # requires all three JS lockfiles; Cargo-only never gets that far (CP-1).
    {
      cp_baseline_case noreport package-lock.json
      echo '{}' > "$TG/yarn.lock"
      echo '{}' > "$TG/pnpm-lock.yaml"
      # The baseline reads exit 0 as ok, so this fake passes the guard, writes nothing and
      # exits 0; the fake's own argv is irrelevant to the record being probed.
      put_fake "cp-noreport" osv-scanner 'printf "TOOL=%s ARGS=%s\n" "$0" "$*" >> "${FAKE_CALLS:-/dev/null}"
exit 0'
      run_runner "cp-noreport" "$BASELINE_RUNNER"
      if [ "$(status_of osv)" = "ok" ]; then
        case_result "counterprobe (expected FAIL after the fix): baseline calls exit 0 without a report ok" 1
      else
        case_result "counterprobe (expected FAIL after the fix): baseline calls exit 0 without a report ok" 0 \
          "osv=$(status_of osv)/$(detail_of osv)"
      fi

      # The same run against the fixed runner must read "error": same fake, same missing
      # report, only the reader changed.
      new_case cp-noreport-fixed
      echo '{}' > "$TG/package-lock.json"
      put_fake cp-noreport-fixed osv-scanner "$CALLS_PROLOGUE
exit 0"
      fake_gitleaks cp-noreport-fixed
      fake_semgrep_clean cp-noreport-fixed
      run_runner cp-noreport-fixed
      if [ "$(status_of osv)" = "error" ] && [ -n "$(reason_of osv)" ]; then
        case_result "counterprobe: the fixed runner reads that same missing report as error" 1
      else
        case_result "counterprobe: the fixed runner reads that same missing report as error" 0 \
          "osv=$(status_of osv)/$(detail_of osv)"
      fi
    }

    # CP-3: a crashing gitleaks must read "ok" on the baseline (unconditional record).
    {
      cp_baseline_case glcrash Cargo.lock
      put_fake "cp-glcrash" gitleaks "$CALLS_PROLOGUE
printf '%s\n' 'fake gitleaks crash' >&2
exit 1"
      run_runner "cp-glcrash" "$BASELINE_RUNNER"
      if [ "$(status_of gitleaks)" = "ok" ]; then
        case_result "counterprobe (expected FAIL after the fix): baseline records a crashed gitleaks as ok" 1
      else
        case_result "counterprobe (expected FAIL after the fix): baseline records a crashed gitleaks as ok" 0 \
          "gitleaks=$(status_of gitleaks)/$(detail_of gitleaks)"
      fi
    }
  fi
}

# ---------------------------------------------------------------- summary

echo
printf '%s/%s Fälle bestanden\n' "$PASS" "$TOTAL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
