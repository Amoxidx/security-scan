#!/usr/bin/env bash
#
# Claude Code PreToolUse hook: scan the file about to be edited.
#
# Reads the tool payload on stdin, extracts the target path, runs the local Semgrep rules
# against it. Exit 2 blocks the edit; anything else lets it through.
#
# Deliberately non-blocking when semgrep is missing: a hook that fails closed on a missing
# optional tool makes the editor unusable, and an unusable hook gets deleted.

set -uo pipefail
command -v semgrep >/dev/null 2>&1 || exit 0

PAYLOAD=$(cat)
FILE=$(printf '%s' "$PAYLOAD" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
print(d.get('tool_input',{}).get('file_path','') or '')
" 2>/dev/null)

[ -z "$FILE" ] || [ ! -f "$FILE" ] && exit 0
case "$FILE" in
  *security/eval/corpus/*) exit 0 ;;   # fixtures are vulnerable on purpose
esac

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
OUT=$(semgrep --metrics=off --disable-version-check --quiet --error --config "$ROOT/security/scanners/semgrep/rules" "$FILE" 2>&1)
RC=$?

# semgrep: 0 = clean, 1 = findings, 2+ = the scan itself failed. Only 1 is a reason to block.
# Blocking on 2 turns any scanner hiccup into an editor that refuses to write files, and a
# hook that does that gets removed rather than fixed.
if [ "$RC" -ge 2 ]; then
  echo "security hook: semgrep could not scan $FILE (exit $RC) — allowing the edit" >&2
  exit 0
fi
[ "$RC" -eq 0 ] && exit 0

echo "Security rules flagged $FILE:" >&2
echo "$OUT" | head -30 >&2
exit 2
