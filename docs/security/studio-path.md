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
`jk-coder`, Colima, Codex, coding-agent CLI (Max, Login-Keychain), Semgrep,
OSV, Gitleaks.

**Coding-agent CLI unter SSH:** OAuth liegt in der Login-Keychain. Nicht-interaktive
SSH-Sessions sehen oft `loggedIn: false`, obwohl die Desktop-Session eingeloggt ist.
Abhilfe: `security/studio/claude-via-gui.sh` — von `check-pr` über
`SECURITY_CLAUDE_WRAPPER` gesetzt; startet den Agenten bei Bedarf im Aqua-Domain
(`launchctl gui/$UID`).

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

## Auto PR-ready checks

LaunchAgent auf Studio (`bootstrap.sh --install-auto`): periodisch offene **non-draft**
PRs der konfigurierten Targets scannen. **Default ON** nach Install.

Ausschalten ohne Deinstall:

```bash
security/studio/auto-pr-check.sh --off    # schreibt ~/.config/security-scan/auto-pr-check.off
# oder: SECURITY_SCAN_AUTO_PR_CHECK=0
security/studio/auto-pr-check.sh --on     # wieder an
```

## Was absichtlich fehlt

- Kein Self-Hosted GitHub Runner als GitHub Required Check
- Keine Branch-Protection von hier setzen (macht der Maintainer manuell)
- Kein GitHub-Webhook — LaunchAgent-Polling statt Events

## Studio-Stack (Ist)

| Komponente | Rolle | Default |
|---|---|---|
| Codex CLI | Triage + Final Judge | `codex-cli:gpt-5.6-sol` |
| Claude CLI | Adversarial Refuter | `claude-cli:claude-opus-5` |
| Ollama Qwen | Machine Evidence (Lab) | `ollama:jk-coder` |
| Colima + Docker | Sandbox (`--network none`) | `node:22-bookworm-slim` |

Konfiguration: `security/redteam/config.json` → `lab.model` / `lab.preferredModels`.
`check-pr.mjs` wählt bei fehlendem Primary-Tag das erste verfügbare Preferred-Modell
auf Ollama (Fallback: jede `qwen3-coder-next*`-Variante).

Bootstrap setzt `DOCKER_BIN` und PATH für non-interactive Shells (OrbStack unter
`/usr/local/bin/docker`, brew Cellar, `~/.local/bin`).

## Messung

Bootstrap + `studio.test.sh` + Lab-Smoke auf Studio:

| Datum | Was | Ergebnis |
|---|---|---|
| 2026-08-12 | Lab gegen `006-proto-pollution/**after**` (Vuln-Tree) mit `jk-coder` | `reproduced`, Exit 0, 2 Turns, ~5 s |
| 2026-08-12 | `studio.test.sh` | 11/11 |
| 2026-08-12 | `bootstrap.sh --check` | ok=16 warn=1 fail=0 (kimi optional) |

Korpus-Konvention: `before/` = clean base, `after/` = PR der die Schwachstelle
**einführt**. Probes und Lab-Smokes laufen gegen `after/`.

```bash
bash security/studio/bootstrap.sh --check
bash security/studio/studio.test.sh
node security/lab/run.mjs \
  --finding security/lab/fixtures/finding-proto-pollution.json \
  --code-dir security/eval/corpus/vuln/006-proto-pollution/after
# Gate (deterministisch, ohne AI):
node security/studio/check-pr.mjs --local --target security-scan --skip-ai
# Voller Studio-Pfad inkl. Qwen-Lab:
node security/studio/check-pr.mjs --target dfx-api --pr <N> --post
```
