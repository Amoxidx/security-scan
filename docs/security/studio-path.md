# Studio-Pfad: PR-Checks mit lokalem Lab

**Stand: 2026-08-12** · Ergänzung zu [Implementierungsplan](./implementation-plan.md)
und Issue #7 (Evidence-Driven Multi-Model Pipeline).

## Warum ein eigener Pfad

GitHub-hosted CI fährt `static` / `scanners` / `verify` und optional `ai-review`.
Zwei Stufen **können dort nicht** laufen, ohne die Trust-Boundary zu brechen:

1. **CLI-Abo-Modelle** (`codex`, `claude`) — nicht in Actions installiert/authentifiziert
2. **Lokales Repro-Lab** (Qwen über Ollama + Colima-Sandbox) — braucht GPU/RAM und
   darf keinen Checkout-Token im selben Job sehen

Studio (`dfxai-remote`) hat genau diesen Stack: Node 22+, Ollama
`qwen3-coder-next:q4_K_M`, Colima, Codex, Claude, Semgrep, OSV, Gitleaks.

## Entry Point

```bash
bash security/studio/bootstrap.sh

# Primary — your PRs (target prefers local checkout → git worktree)
node security/studio/check-pr.mjs --target dfx-api --pr <N> --post
node security/studio/check-pr.mjs --target dfx-services --pr <N> --post

# Secondary — any other codebase (full tree)
node security/studio/check-pr.mjs --dir /path/to/code --mode tree
node security/studio/check-pr.mjs --list-targets
```

**Modes:** `pr` (primary) · `local` (branch) · `tree` (other codebases).  
**Targets:** `security/studio/targets.json` — add a profile when a repo becomes regular.

Details: [`security/studio/README.md`](../../security/studio/README.md).

## Gate mit Machine Evidence

| Lab-Verdict | Wirkung |
|---|---|
| `reproduced` | blockiert |
| `not-reproduced` | Finding fliegt aus dem Blocking-Set |
| `inconclusive` | Severity-Entscheidung bleibt (fail-closed, nie „sicher“) |

## Was von Anthropic übernommen wurde

Quellen:

- [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)
  — Discover ≠ Verify; executable witnesses; Judge-Muster
- [claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
  — diff-scoped PR-Review, ein upserteter Kommentar, FP-Filter-Idee

| Pattern | Umsetzung bei uns |
|---|---|
| Adversarial verify | `redteam/harness.mjs` k-of-n (Claude refuter) |
| Executable witness | `lab/run.mjs` Exit-Code-Contract in Sandbox |
| Ein PR-Kommentar | `--post` mit Marker `<!-- security-scan-studio -->` |
| Codify as rule | Report-Zeile nach `reproduced` |
| Threat-model first | noch nicht im Studio-Pfad (Phase optional) |

## Was absichtlich fehlt

- Kein Self-Hosted GitHub Runner (kann später `check-pr.mjs` aufrufen)
- Keine Branch-Protection von hier setzen (macht der Maintainer manuell)
- Kein automatischer Webhook — Orchestrierung ist CLI-first

## Messung

Bootstrap + `studio.test.sh` + Lab-Smoke gegen
`security/eval/corpus/vuln/006-proto-pollution` auf Studio (2026-08-12):
Verdict `reproduced`, Exit 0, 2 Turns.
