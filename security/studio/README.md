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
3. **Studio env** — PATH/docker/colima/ollama defaults injected for non-interactive shells.
4. **Lab only for survivors** — Qwen sandbox runs only on findings that would block, capped by `--max-lab`.

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

## What this is not

- Not GitHub-hosted Actions (lab needs Ollama + Colima; no token next to model code).
- Not automatic until you schedule it (cron / launchd / self-hosted runner calling this CLI).
- Not a replacement for branch protection on `static` / `scanners` / `verify`.
