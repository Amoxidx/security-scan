# Studio security check

Optimized for **your PRs on Studio** (scanners + Codex/Claude + Ollama lab).
The same entry point can later scan **any other codebase** without rewiring.

```text
targets.json  →  which repo / local path / host allowlist
--mode        →  pr | local | tree   (what slice of code)
check-pr.mjs  →  static → scanners → triage → harness → lab → gate
```

## Primary: your PRs

```bash
cd ~/Amoxidx/security-scan
bash security/studio/bootstrap.sh          # once per machine

# DFX API PR (uses local ~/DFXswiss/api if present — no full re-clone)
node security/studio/check-pr.mjs --target dfx-api --pr 1234 --post

# DFX services
node security/studio/check-pr.mjs --target dfx-services --pr 99 --post

# This gate repo
node security/studio/check-pr.mjs --target security-scan --pr 12 --post

# Infer target from --repo / cwd
node security/studio/check-pr.mjs --pr 42 --repo DFXswiss/api
```

Local branch (no PR number):

```bash
node security/studio/check-pr.mjs --local --target dfx-api
node security/studio/check-pr.mjs --dir ~/DFXswiss/services --base origin/develop --skip-ai
```

## Secondary: other codebases

Full-tree audit (empty-tree..HEAD — every tracked file is in scope):

```bash
# Any checkout
node security/studio/check-pr.mjs --dir /path/to/other-code --mode tree

# Deterministic first (no models)
node security/studio/check-pr.mjs --dir /path/to/other-code --mode tree --skip-ai

# Custom hosts for static gate
node security/studio/check-pr.mjs --dir ~/scratch/lib --mode tree \
  --host-allow-extra 'api\.example\.com|cdn\.example\.com'
```

Add a permanent profile in `targets.json` when a codebase becomes regular:

```json
"my-lib": {
  "label": "My library",
  "repo": "me/my-lib",
  "defaultBase": "main",
  "localPaths": ["~/code/my-lib"],
  "hostAllowExtra": ["api\\.example\\.com"]
}
```

```bash
node security/studio/check-pr.mjs --list-targets
```

## Modes

| Mode | Scope | Typical use |
|---|---|---|
| `pr` | `base...head` of a PR | **Primary** — daily PR review on Studio |
| `local` | current branch vs `--base` | Pre-push / worktree check |
| `tree` | empty-tree..HEAD (whole repo) | Test / audit another codebase |

## Targets (built-in)

| id | Repo | Default base |
|---|---|---|
| `security-scan` ★ | Amoxidx/security-scan | master |
| `dfx-api` | DFXswiss/api | develop |
| `dfx-services` | DFXswiss/services | develop |
| `herbert-hq` | Amoxidx/Herbert-HQ | main |
| `generic` | (any `--dir`) | origin/master |

★ = primary. Local paths are tried in order; first existing `.git` wins (Studio + Pro paths listed).

## Optimizations for the primary path

1. **Local checkout preferred** — if `~/DFXswiss/api` exists, PR mode creates a disposable **git worktree** instead of cloning from GitHub.
2. **Target host allowlist** — DFX targets ship `api.dfx.swiss` etc. so static does not false-block product URLs (`SECURITY_HOST_ALLOW_EXTRA`).
3. **Studio env** — PATH/docker/colima/ollama defaults injected for non-interactive shells; `DOCKER_BIN` resolved even when OrbStack is off-PATH.
4. **Coding-agent CLI via GUI keychain** — SSH cannot read the login keychain. `check-pr` sets `SECURITY_CLAUDE_WRAPPER` to `claude-via-gui.sh`, which re-runs the agent in the Aqua `gui/$UID` domain when direct auth is false.
5. **Lab only for survivors** — Qwen sandbox runs only on findings that would block, capped by `--max-lab` / `config.lab.maxFindings`.
6. **Lab model auto-pick** — `config.lab.model` (`ollama:qwen3-coder-next:q4_K_M`) with `preferredModels` fallback if the primary tag is not pulled.

## Subscription-agent auth from SSH

```bash
bash security/studio/claude-via-gui.sh --studio-auth-check
# ok (direct)  → this shell already sees the keychain
# ok (GUI)     → desktop session has the seat login; wrapper will use launchctl gui/$UID
# fail         → log into the Studio GUI and run: claude auth login
```

`bootstrap.sh` links the wrapper to `~/.local/bin/claude-via-gui` and probes auth the same way.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass |
| 1 | Block |
| 2 | Block with inconclusive lab on blocking severity |
| 3 | Setup / usage error |

### Lab → gate

| Lab verdict | Effect |
|---|---|
| `reproduced` | **Block** |
| `not-reproduced` | Drop from blocking set |
| `inconclusive` | Keep severity decision (fail closed) |
| skipped | Keep harness severity decision |

## Authority

Tools always run from **this** `security-scan` checkout (absolute paths). When the subject is security-scan itself, `security/` is overlaid from the orchestrator tree so a PR cannot neuter the gate.

## Setup

```bash
bash security/studio/bootstrap.sh
bash security/studio/bootstrap.sh --check
bash security/studio/studio.test.sh
```

## Auto PR-ready checks (LaunchAgent)

Watches **open, non-draft** PRs for configured targets (`dfx-api`, `dfx-services`,
`security-scan` by default) and runs `check-pr.mjs` once per head SHA.

```bash
# Install (default ON)
bash security/studio/bootstrap.sh --install-auto
# or: npm run studio:auto:install

# Pause without uninstalling (kill switch)
security/studio/auto-pr-check.sh --off
# Resume (default)
security/studio/auto-pr-check.sh --on

# One manual tick
security/studio/auto-pr-check.sh --once
security/studio/auto-pr-check.sh --status
```

| Kill switch | Effect |
|---|---|
| `~/.config/security-scan/auto-pr-check.off` exists | **OFF** |
| `SECURITY_SCAN_AUTO_PR_CHECK=0` | **OFF** |
| neither (and agent loaded) | **ON** (default) |

Config: `security/studio/auto-pr-check.config.json` (`targets`, `postComment`, `maxPrsPerTick`,
`intervalSeconds`, `skipAi`). State/logs under `~/.cache/security-scan/auto-pr-check/`.

## What this is not

- Not GitHub-hosted Actions (lab needs Ollama + Colima; no token next to model code).
- Not a replacement for branch protection on `static` / `scanners` / `verify`.
