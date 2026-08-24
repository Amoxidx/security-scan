# Security Scan

[![Security Scan](https://github.com/Amoxidx/security-scan/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Amoxidx/security-scan/actions/workflows/security-scan.yml)
[![Security PR Trigger](https://github.com/Amoxidx/security-scan/actions/workflows/security-pr-trigger.yml/badge.svg)](https://github.com/Amoxidx/security-scan/actions/workflows/security-pr-trigger.yml)

Eine blockierende Security-Schwelle für Pull Requests — Werkzeuge suchen, ein Modell filtert,
und rot wird der Check nur für das, was eine adversarielle Verifikation überlebt hat.

Entstanden aus der Frage, wie das **Bitcoin Red Team** im August 2026 in 27,5 Stunden 4.962
Findings über 390 Repositories erzeugt hat — und was davon sich als wiederkehrender
CI-Check überhaupt sinnvoll nachbauen lässt.

---

## Warum das so gebaut ist

Drei Zahlen prägen jede Designentscheidung hier:

- Das Bitcoin Red Team produzierte 4.962 Findings, von denen zum Reportzeitpunkt **21,4 %
  reproduziert** waren. Eine Suchmaschine mit 16 Leuten Triage dahinter ist kein Gate.
- Im DARPA AIxCC erreichte **Buttercup** (Trail of Bits) 90 % Genauigkeit bei 181 USD/Punkt
  — mit ausschließlich Nicht-Reasoning-Modellen. Architektur schlägt Modellwahl.
- LLMs als **Filter** auf SAST-Output senken die Falsch-Positiv-Rate im OWASP-Benchmark von
  über 92 % auf **6 %**. Als *Finder* liegen dieselben Modelle bei 18–34 %.

Daraus folgt die Suchrichtung: **Werkzeuge suchen, das Modell filtert.** Nicht umgekehrt.

Die Herleitung im Detail:

| Dokument | Inhalt |
|---|---|
| [Rekonstruktion](docs/security/bitcoin-red-team-reconstruction.md) | Wie das Bitcoin Red Team gearbeitet hat — belegt, abgeleitet, rekonstruiert, mit Agent-Graph |
| [Setup-Evaluation](docs/security/setup-evaluation.md) | Welche Harness, welches Modell, welche Werkzeuge, Graphs, Hooks — mit Evidenz |
| [Implementierungsplan](docs/security/implementation-plan.md) | Phasen 0–7, Aufwand, Risiken, Definition of Done |
| [Messungen](docs/security/measurements.md) | Fortlaufendes Messprotokoll |
| [Studio-Pfad](docs/security/studio-path.md) | PR-Checks auf Studio mit Lab-Evidenz (Issue #7 Ende) |

---

## Stand

| Phase | Status |
|---|---|
| 0 — Messgrundlage | **fertig**, Baseline gemessen |
| 1 — Scanner + SARIF (Semgrep, OSV, Gitleaks, CodeQL) | **fertig**, in CI verifiziert |
| 2 — LLM-Triage auf SARIF | **gebaut**, Wirkung noch ungemessen |
| 3 — Lens-Kanal | **fertig**, fünf Lenses: `fallback`, `entropy`, `state`, `access-control`, `business-logic` |
| 4 — Beweisstufe | **gebaut**, 21/21 Korpus-Probes bestätigen ihren Fall |
| 5 — Graph-Kontext | offen (CodeQL-DB deckt den Bedarf vorerst) |
| 6 — Hooks (3 Ebenen) | **fertig** — Agent, Commit, CI |
| 7 — Scharfschalten | offen, wartet auf Phase-2-Messung |
| Studio-Pfad (Lab-Evidenz auf PRs) | **gebaut** — `security/studio/`, manuell / lokal, nie GitHub-hosted CI |

Die Spalte „Schwelle“ ist erzwungen: `eval/run.mjs` endet mit Exit ≠ 0, wenn Detection < 50 %
oder die Falsch-Positiv-Rate > 5 % (CI-Job `verify`). Im Modus `--no-ai` gilt die Detection-
Schwelle über die `static_detectable`-Fälle, im vollen Lauf über alle Vuln-Fälle. p95 ist
nicht erzwungen.

**Statischer Boden** (`node security/eval/run.mjs --no-ai`) — misst nur die Fälle, die ein
statischer Scanner finden können muss:

| Metrik | Wert | Schwelle |
|---|---|---|
| Detection Rate | **100 %** (6/6 static_detectable) | ≥ 50 % |
| Falsch-Positiv-Rate | **0 %** (0/13) | ≤ 5 % |

**Voller AI-Eval** (2026-08-23, 33 Korpus-Fälle; Hunt+Verify über `claude-opus-5`,
Report über `codex-cli:gpt-5.6-sol`; `node security/eval/run.mjs`):

| Metrik | Wert | Schwelle |
|---|---|---|
| Detection Rate | **95,0 %** (19/20) | ≥ 50 % |
| Falsch-Positiv-Rate | **0,0 %** (0/13) | ≤ 5 % |
| p95 Wall-Clock | 298 s | ≤ 480 s (nicht erzwungen) |

Einziger Fehlschlag (FN): `vuln-008-unbounded-recursion` — der subtilste inter-prozedurale Fall.

**Repro-Stufe** (`node security/eval/repro.mjs`, Sandbox, `claude-opus-5`, voller Korpus) —
reproduzierte, in der Docker-Sandbox echt ausgeführte Exploits:

| Metrik | Wert |
|---|---|
| Repro-Rate | **90,0 %** (18/20) |
| Falsch-Repro | **0/13** |

Zwei Fälle inconclusive (`vuln-010` GitHub-Workflow-YAML, `vuln-011` IDOR — im node-Sandbox
schwer deterministisch). Falsch-Repro 0/13, nachdem ein mis-spezifiziertes Fixture
(`benign-006`) korrigiert wurde (PR #33); der rohe Erstlauf hatte 1/13, Ursache war das
Fixture, nicht das Tool.

**Geltungsbereich.** Gemessen mit `claude-opus-5` (Hunt+Verify) und `codex-cli:gpt-5.6-sol`
(Report); bei abwesendem Kimi fielen die kimi-Lenses per Fallback auf opus. Der Korpus ist
ein kuratiertes Fixture-Set (bewusst gebaute Vuln/Benign-Paare, kein realweltlicher
CVE-Maßstab). p95 298 s heißt: der langsamste Fall dauert rund 5 min.

---

## Aufbau

```
security/
├── gate/
│   ├── static-checks.sh         Stufe 0 — deterministisch, Sekunden, blockiert immer
│   └── gate.test.sh             Regression der Gate-Härtung (bash/node, ohne Framework)
├── scanners/
│   ├── semgrep/rules/           12 eigene Regeln für Klassen ohne Standardregel
│   ├── run-scanners.sh          Semgrep + OSV + Gitleaks → SARIF
│   └── normalize.mjs            SARIF → ein Finding-Stream, auf Diff-Scope beschränkt
├── redteam/
│   ├── triage.mjs               Stufe 2 — LLM filtert Scanner-Output
│   ├── harness.mjs              Stufe 3 — Lens-Hunt → dedupe → k-of-n verify → report
│   ├── providers.mjs            CLI / Anthropic / OpenAI, austauschbar
│   ├── config.json              Provider, Lenses, Modelle, Blocking-Schwelle
│   └── prompts/                 die sechs Pipeline-Stufen
├── prove/                       Stufe 4 — Probes, isoliert im Kindprozess
├── hooks/                       Agent- und Commit-Ebene
└── eval/
    ├── run.mjs                  Messharness
    └── corpus/                  20 Vuln-Fälle, 13 Negativkontrollen

.claude/settings.json            PreToolUse-Hook
.github/workflows/security-scan.yml
.github/CODEOWNERS               Review-Pflicht für Gate-, Scanner- und Workflow-Pfade
docs/security/
```

---

## Benutzen

```bash
# Stufe 0
security/gate/static-checks.sh origin/master

# Stufe 1 — Scanner
security/scanners/run-scanners.sh . security-report/sarif
git diff origin/master...HEAD > security-report/pr.diff
node security/scanners/normalize.mjs --sarif security-report/sarif --diff security-report/pr.diff \
  --out security-report/findings.json

# Stufe 2 — Triage
node security/redteam/triage.mjs --findings security-report/findings.json --repo .

# Stufe 3 — Lens-Kanal
node security/redteam/harness.mjs --diff security-report/pr.diff --out security-report/report

# Stufe 4 — Beweis
node security/prove/run-probes.mjs

# Selbsttest — das Gate gegen den eigenen Diff. Gehört in jede Runde:
# zwei Falsch-Positive lagen genau hier und in keinem Korpus-Fall.
security/gate/static-checks.sh master

# Messung — endet mit Exit ≠ 0, wenn Detection < 50 % oder Falsch-Positive > 5 %
node security/eval/run.mjs --no-ai      # statischer Boden
node security/eval/run.mjs              # voller AI-Eval
node security/eval/repro.mjs            # Repro-Stufe (Sandbox)

# Hooks installieren
security/hooks/install.sh

# Studio — voller PR-Check inkl. lokalem Lab (Ollama + Colima)
bash security/studio/bootstrap.sh
node security/studio/check-pr.mjs --pr <N> --repo <owner/name> --post
node security/studio/check-pr.mjs --local --base origin/master
```

Das Gate selbst (Suite, `static-checks`, `eval/run.mjs`) läuft unter Node ≥ 20 — im CI
belegt, Suite 23/23. Die Beweisstufe (`node security/prove/run-probes.mjs`) importiert
`.ts`-Fixtures aus dem Korpus und braucht ein Node, das TypeScript-Typen **ohne Flag**
strippt (gemessen: v22.22.3; laut Node/Amaro ab v22.18.0 standardmäßig aktiv). Zusätzlich
`git` und `bash`. Scanner optional, aber ohne sie bleibt nur das, was das statische Gate allein findet:

```bash
pip install semgrep
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
go install github.com/zricethezav/gitleaks/v8@latest
```

**Modelle laufen standardmäßig über Abo-CLIs**, nicht über metered APIs:

```bash
npm i -g @kimi-code/cli && kimi        # einmalig einloggen
```

Details und die Alternativen (Anthropic-kompatibel, OpenAI-kompatibel) in
[`security/README.md`](security/README.md).

---

## In ein anderes Repo übernehmen

`security/` und `.github/workflows/security-scan.yml` sind selbstständig. Anzupassen sind die
Host-Allowlist in `static-checks.sh`, die Lens-Auswahl und Blocking-Schwelle in
`security/redteam/config.json`, sowie der Korpus in `security/eval/corpus/` — echte,
historische Fixes aus dem eigenen Repo treffen das eigene Bedrohungsmodell besser als jeder
generische Korpus.

**Ohne Required Checks ist das Ganze eine Empfehlung.** Ein roter Check hält niemanden auf,
solange er nicht in den Branch-Protection-Rules steht. Authority läuft **nur** über
`workflow_run` vom Default-Branch (kein `pull_request`-Trigger am Gate-Workflow — sonst
könnte ein same-repo-PR die Required-Namen selbst grün melden). Check-Namen auf dem
PR-Head: `static`, `scanners`, `verify`:

```bash
gh api -X PUT repos/<owner>/<repo>/branches/<branch>/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": false, "contexts": ["static", "scanners", "verify"] },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

`require_code_owner_reviews: true` macht `.github/CODEOWNERS` bindend — ohne das ist die
Datei nur eine Vorschlagsliste. Environment `security-ai` (für `ai-review`) kann zusätzlich
Required Reviewers bekommen, bevor Model-Keys fließen.

---

## Was das nicht ist

Kein zuverlässiger Schwachstellen-Detektor. Das beste gemessene System der Welt (ATLANTIS,
AIxCC-Sieger) fand 61 % der Schwachstellen — in einem Wettbewerb mit maschinell prüfbarer
Ground Truth, die es in JavaScript/TypeScript nicht gibt. Realistisches Ziel ist ein Gate,
das die bekannten Klassen zuverlässig blockiert, den Rest gefiltert einem Menschen vorlegt,
und dessen Fehlerrate **gemessen und dokumentiert** ist.

---

## Hinweise

Der Code unter `security/eval/corpus/` ist **absichtlich verwundbar**. Er dient als
Messgrundlage, wird nie gebaut und nie ausgeliefert.

Das Repository steht unter der [MIT-Lizenz](LICENSE). Übernehmen, verändern und weitergeben
ist ausdrücklich erlaubt; der Copyright-Hinweis muss dabei erhalten bleiben. Der Code ist
vollständig eigener Code — es sind keine fremden Bestandteile enthalten, deren Lizenz
zusätzliche Auflagen mitbrächte.
