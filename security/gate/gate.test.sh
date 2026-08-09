#!/usr/bin/env bash
#
# Self-contained gate regression tests for F2/F3/F4/F9/F12 hardening fixes.
# Uses only bash, git, and node. Fixtures live under a mktemp directory.
#
# Exit: 0 all passed, 1 one or more failed.
# Summary line: "N/M Fälle bestanden"

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATIC="$ROOT/security/gate/static-checks.sh"
TRIAGE="$ROOT/security/redteam/triage.mjs"
HARNESS="$ROOT/security/redteam/harness.mjs"

PASS=0
FAIL=0
TOTAL=0

WORK=
cleanup() {
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gate-test.XXXXXX")"

case_result() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL + 1))
  if [ "$ok" = "1" ]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"
    if [ -n "$detail" ]; then
      printf '         %s\n' "$detail"
    fi
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

# Create a tiny git repo under $1 with an initial commit.
make_repo() {
  local dir="$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b master
  git -C "$dir" config user.email "gate-test@example.com"
  git -C "$dir" config user.name "gate-test"
  echo "base" > "$dir/README"
  git -C "$dir" add README
  git -C "$dir" commit -q -m "base"
  mkdir -p "$dir/security/gate"
  cp "$STATIC" "$dir/security/gate/static-checks.sh"
  chmod +x "$dir/security/gate/static-checks.sh"
}

commit_file() {
  local dir="$1" path="$2" content="$3" msg="${4:-change}"
  mkdir -p "$(dirname "$dir/$path")"
  printf '%s\n' "$content" > "$dir/$path"
  git -C "$dir" add "$path"
  git -C "$dir" commit -q -m "$msg"
}

short() {
  echo "$1" | tr '\n' ' ' | cut -c1-220
}

# Disable errexit for the suite body; each case captures its own status.
set +e

# ---------------------------------------------------------------- 1–6: static-checks (F2, F4)

echo "=== static-checks (F2, F4) ==="

# 1. F2: nonexistent base ref -> exit != 0
{
  make_repo "$WORK/f2-bad-base"
  commit_file "$WORK/f2-bad-base" "src/a.js" "console.log(1);" "add a"
  run bash -c "cd '$WORK/f2-bad-base' && bash security/gate/static-checks.sh origin/nonexistent-branch"
  if [ "$RUN_RC" -ne 0 ]; then
    case_result "F2: bad base-ref exits non-zero" 1
  else
    case_result "F2: bad base-ref exits non-zero" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# 2. F2: valid base, clean change -> exit 0
{
  make_repo "$WORK/f2-clean"
  BASE_SHA="$(git -C "$WORK/f2-clean" rev-parse HEAD)"
  commit_file "$WORK/f2-clean" "src/clean.js" "export const n = 1;" "clean change"
  run bash -c "cd '$WORK/f2-clean' && bash security/gate/static-checks.sh '$BASE_SHA'"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "F2: valid base + clean change exits 0" 1
  else
    case_result "F2: valid base + clean change exits 0" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# 3. F4: sk-ant- key blocks
{
  make_repo "$WORK/f4-ant"
  BASE_SHA="$(git -C "$WORK/f4-ant" rev-parse HEAD)"
  commit_file "$WORK/f4-ant" "src/keys.js" \
    "const k = 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh-AAAAAA';" \
    "add ant key"
  run bash -c "cd '$WORK/f4-ant' && bash security/gate/static-checks.sh '$BASE_SHA'"
  if [ "$RUN_RC" -ne 0 ]; then
    case_result "F4: sk-ant- key blocks" 1
  else
    case_result "F4: sk-ant- key blocks" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# 4. F4: sk-proj- key blocks
{
  make_repo "$WORK/f4-proj"
  BASE_SHA="$(git -C "$WORK/f4-proj" rev-parse HEAD)"
  commit_file "$WORK/f4-proj" "src/keys.js" \
    "const k = 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf';" \
    "add proj key"
  run bash -c "cd '$WORK/f4-proj' && bash security/gate/static-checks.sh '$BASE_SHA'"
  if [ "$RUN_RC" -ne 0 ]; then
    case_result "F4: sk-proj- key blocks" 1
  else
    case_result "F4: sk-proj- key blocks" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# 5. Counter: ghp_ still blocks
{
  make_repo "$WORK/f4-ghp"
  BASE_SHA="$(git -C "$WORK/f4-ghp" rev-parse HEAD)"
  commit_file "$WORK/f4-ghp" "src/keys.js" \
    "const t = 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';" \
    "add ghp"
  run bash -c "cd '$WORK/f4-ghp' && bash security/gate/static-checks.sh '$BASE_SHA'"
  if [ "$RUN_RC" -ne 0 ]; then
    case_result "counter: ghp_ still blocks" 1
  else
    case_result "counter: ghp_ still blocks" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# 6. Counter: prose "sk-" does not block
{
  make_repo "$WORK/f4-prose"
  BASE_SHA="$(git -C "$WORK/f4-prose" rev-parse HEAD)"
  commit_file "$WORK/f4-prose" "src/note.js" \
    "// users often write sk- as a shorthand for secret-key in docs" \
    "prose sk"
  run bash -c "cd '$WORK/f4-prose' && bash security/gate/static-checks.sh '$BASE_SHA'"
  if [ "$RUN_RC" -eq 0 ]; then
    case_result "counter: prose sk- does not block" 1
  else
    case_result "counter: prose sk- does not block" 0 "rc=$RUN_RC out=$(short "$RUN_OUT")"
  fi
}

# ---------------------------------------------------------------- 7: F3 triage never weaker than scanner

echo "=== triage (F3) ==="

{
  TDIR="$WORK/f3-triage"
  mkdir -p "$TDIR/bin" "$TDIR/src" "$TDIR/out"
  cat > "$TDIR/bin/fake-triage" <<'EOF'
#!/bin/sh
cat >/dev/null
printf '%s\n' '{"verdict":"needs_human","severity":"medium","reason":"reachability unclear","reachable_from":null,"what_would_change_my_mind":"more context"}'
EOF
  chmod +x "$TDIR/bin/fake-triage"

  cat > "$TDIR/config.json" <<EOF
{
  "defaultProvider": "fake",
  "maxConcurrency": 1,
  "providers": {
    "fake": {
      "type": "cli",
      "command": ["$TDIR/bin/fake-triage"],
      "timeoutMs": 10000
    }
  },
  "gate": { "blockOn": ["critical", "high", "error"], "maxDiffBytes": 400000 },
  "triage": { "model": "fake:m" },
  "report": { "model": "fake:m" },
  "hunt": { "lenses": [], "models": {} },
  "verify": { "models": [], "refuteThreshold": 2 }
}
EOF

  echo "const x = 1;" > "$TDIR/src/app.js"
  cat > "$TDIR/findings.json" <<'EOF'
{
  "findings": [
    {
      "tool": "semgrep",
      "ruleId": "test.rule",
      "file": "src/app.js",
      "line": 1,
      "severity": "error",
      "message": "test finding",
      "cwe": null,
      "class": null
    }
  ]
}
EOF

  run node "$TRIAGE" \
    --findings "$TDIR/findings.json" \
    --repo "$TDIR" \
    --out "$TDIR/out/triaged.json" \
    --config "$TDIR/config.json"

  BLOCKING="0"
  if [ -f "$TDIR/out/triaged.json" ]; then
    BLOCKING="$(node -e "const j=require('$TDIR/out/triaged.json'); process.stdout.write(String(j.blocking||0))")"
  fi
  if [ "$RUN_RC" -eq 1 ] && [ "$BLOCKING" = "1" ]; then
    case_result "F3: needs_human+medium keeps scanner error blocking" 1
  else
    case_result "F3: needs_human+medium keeps scanner error blocking" 0 \
      "rc=$RUN_RC blocking=$BLOCKING out=$(short "$RUN_OUT")"
  fi
}

# ---------------------------------------------------------------- 8: F9 verifier error is not a refutation

echo "=== harness verify (F9) ==="

{
  HDIR="$WORK/f9-verify"
  mkdir -p "$HDIR/bin" "$HDIR/out"
  cat > "$HDIR/bin/fake-hunt" <<'EOF'
#!/bin/sh
cat >/dev/null
printf '%s\n' '{"findings":[{"title":"Test finding","file":"src/x.js","line":1,"severity":"high","root_cause":"test root cause for dedupe","attacker":"remote","confidence":"high"}]}'
EOF
  chmod +x "$HDIR/bin/fake-hunt"
  cat > "$HDIR/bin/fake-verify" <<'EOF'
#!/bin/sh
cat >/dev/null
echo "verifier boom" >&2
exit 1
EOF
  chmod +x "$HDIR/bin/fake-verify"

  cat > "$HDIR/config.json" <<EOF
{
  "defaultProvider": "hunt",
  "maxConcurrency": 1,
  "providers": {
    "hunt": {
      "type": "cli",
      "command": ["$HDIR/bin/fake-hunt"],
      "timeoutMs": 10000
    },
    "verify": {
      "type": "cli",
      "command": ["$HDIR/bin/fake-verify"],
      "timeoutMs": 10000
    }
  },
  "hunt": {
    "lenses": ["fallback"],
    "models": { "fallback": "hunt:m" }
  },
  "verify": {
    "models": ["verify:m"],
    "refuteThreshold": 1
  },
  "report": { "model": "hunt:m" },
  "gate": { "blockOn": ["critical", "high", "error"], "maxDiffBytes": 400000 },
  "triage": { "model": "hunt:m" }
}
EOF

  cat > "$HDIR/pr.diff" <<'EOF'
diff --git a/src/x.js b/src/x.js
--- a/src/x.js
+++ b/src/x.js
@@ -0,0 +1 @@
+export const x = 1;
EOF

  run node "$HARNESS" \
    --diff "$HDIR/pr.diff" \
    --out "$HDIR/out" \
    --config "$HDIR/config.json"

  SURVIVED="missing"
  if [ -f "$HDIR/out/findings.json" ]; then
    SURVIVED="$(node -e "
      const fs=require('fs');
      const j=JSON.parse(fs.readFileSync('$HDIR/out/findings.json','utf8'));
      const f=j[0]||{};
      process.stdout.write(String(!!f.survived)+','+String(!!f.unverified)+','+String(f.refutations||0));
    ")"
  fi
  if [ "$RUN_RC" -eq 1 ] && [ "$SURVIVED" = "true,true,0" ]; then
    case_result "F9: verifier error does not refute finding" 1
  else
    case_result "F9: verifier error does not refute finding" 0 \
      "rc=$RUN_RC survived=$SURVIVED out=$(short "$RUN_OUT")"
  fi
}

# ---------------------------------------------------------------- 9: F12 critical finding reaches report and blocks

echo "=== harness hunt (F12) ==="

{
  HDIR="$WORK/f12-hunt"
  mkdir -p "$HDIR/bin" "$HDIR/out"
  cat > "$HDIR/bin/fake-hunt" <<'EOF'
#!/bin/sh
cat >/dev/null
printf '%s\n' '{"findings":[{"title":"Critical injection","file":"src/x.js","line":1,"severity":"critical","root_cause":"interpolated shell spawn without sanitise","attacker":"remote","confidence":"high"}]}'
EOF
  chmod +x "$HDIR/bin/fake-hunt"
  # Verifier confirms (refuted: false) so the finding is not dropped by k-of-n.
  cat > "$HDIR/bin/fake-verify" <<'EOF'
#!/bin/sh
cat >/dev/null
printf '%s\n' '{"refuted":false,"severity":"critical","reason":"confirmed"}'
EOF
  chmod +x "$HDIR/bin/fake-verify"

  cat > "$HDIR/config.json" <<EOF
{
  "defaultProvider": "hunt",
  "maxConcurrency": 1,
  "providers": {
    "hunt": {
      "type": "cli",
      "command": ["$HDIR/bin/fake-hunt"],
      "timeoutMs": 10000
    },
    "verify": {
      "type": "cli",
      "command": ["$HDIR/bin/fake-verify"],
      "timeoutMs": 10000
    }
  },
  "hunt": {
    "lenses": ["fallback"],
    "models": { "fallback": "hunt:m" }
  },
  "verify": {
    "models": ["verify:m"],
    "refuteThreshold": 1
  },
  "report": { "model": "hunt:m" },
  "gate": { "blockOn": ["critical", "high", "error"], "maxDiffBytes": 400000 },
  "triage": { "model": "hunt:m" }
}
EOF

  cat > "$HDIR/pr.diff" <<'EOF'
diff --git a/src/x.js b/src/x.js
--- a/src/x.js
+++ b/src/x.js
@@ -0,0 +1 @@
+export const x = 1;
EOF

  run node "$HARNESS" \
    --diff "$HDIR/pr.diff" \
    --out "$HDIR/out" \
    --config "$HDIR/config.json"

  HAS_CRITICAL="0"
  RAW_COUNT="0"
  if [ -f "$HDIR/out/findings.json" ]; then
    HAS_CRITICAL="$(node -e "
      const fs=require('fs');
      const j=JSON.parse(fs.readFileSync('$HDIR/out/findings.json','utf8'));
      const hit=j.some(f => f.severity==='critical' && f.survived);
      process.stdout.write(hit ? '1' : '0');
    ")"
    RAW_COUNT="$(node -e "
      const fs=require('fs');
      const j=JSON.parse(fs.readFileSync('$HDIR/out/findings.json','utf8'));
      process.stdout.write(String(j.length));
    ")"
  fi
  # Critical finding must reach findings.json, survive, and block (exit 1).
  if [ "$RUN_RC" -eq 1 ] && [ "$HAS_CRITICAL" = "1" ] && [ "$RAW_COUNT" -ge 1 ]; then
    case_result "F12: critical finding reaches report and blocks" 1
  else
    case_result "F12: critical finding reaches report and blocks" 0 \
      "rc=$RUN_RC has_critical=$HAS_CRITICAL raw=$RAW_COUNT out=$(short "$RUN_OUT")"
  fi
}

# ---------------------------------------------------------------- summary

echo
printf '%s/%s Fälle bestanden\n' "$PASS" "$TOTAL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
