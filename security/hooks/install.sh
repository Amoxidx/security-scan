#!/usr/bin/env bash
# Point git at the tracked hooks directory. Reversible: git config --unset core.hooksPath
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel)
chmod +x "$ROOT/security/hooks/pre-commit"
git -C "$ROOT" config core.hooksPath security/hooks
echo "core.hooksPath -> security/hooks"
echo "Bypass a single commit with: git commit --no-verify"
