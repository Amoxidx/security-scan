# Security Scan

Eine blockierende Security-Schwelle für Pull Requests, abgeleitet aus der Methodik des
Bitcoin Red Teams. Die Herleitung — was belegt ist, was rekonstruiert — steht in
[`docs/security/bitcoin-red-team-reconstruction.md`](../docs/security/bitcoin-red-team-reconstruction.md).

## Aufbau

```
security/
├── gate/static-checks.sh        Stufe A — deterministisch, immer, blockiert immer
└── redteam/
    ├── harness.mjs              Stufe B — hunt → dedupe → verify → report
    ├── config.json              Lenses, Modelle, Blocking-Schwelle
    └── prompts/                 00-system, 01-recon, 02-hunt, 03-verify, 04-repro, 05-report
```

Verdrahtet in [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml).

## Die zwei Stufen

**Stufe A — `static-checks.sh`.** Kein Modell, kein Netz, Sekunden. Deckt die Klasse ab, für
die ein LLM das falsche Werkzeug ist: PRs, die *bösartig* sind statt fehlerhaft. Secrets in
neuen Zeilen, Änderungen an Workflow-Dateien, `pull_request_target`, neu hinzugefügte
Install-Hooks, Lockfile-Änderungen ohne Manifest-Änderung, `eval`/`child_process`/`curl | sh`,
neue externe Hosts. Läuft immer und blockiert hart.

**Stufe B — `harness.mjs`.** Das AI-Review auf dem Diff. Fan-out über Lenses mit
unterschiedlichen Modellen, Dedup, dann **adversarielle Verifikation**: k-of-n Refuter mit
dem Auftrag, das Finding zu widerlegen. Nur was das überlebt und `high`/`critical` ist,
macht den Check rot.

## Warum die Verify-Stufe nicht optional ist

Das Bitcoin Red Team hat 4.962 Findings produziert und davon zum Reportzeitpunkt **21,4 %
reproduziert**. Dieselbe Pipeline ohne Filterstufe als blockierendes Gate ergibt einen Check,
der überwiegend grundlos rot ist — und ein Gate, das man gewohnheitsmäßig überstimmt, ist
kein Gate. Die Red-Team-Pipeline ist eine *Such*maschine mit menschlicher Triage dahinter;
ein PR-Gate hat keine Triage und muss den Filter selbst mitbringen.

## Warum die Repro-Stufe nicht in CI läuft

`prompts/04-repro.md` erzeugt ausführbaren Code. Modellgenerierten Code in CI auszuführen —
mit Checkout und Token im selben Job — ist ein größeres Problem als das, welches dieses Gate
löst. Die Repro-Stufe gehört in den manuellen Audit-Lauf, in einer Sandbox, ohne Netz und
ohne Repo-Credentials. Deshalb sagt der PR-Kommentar explizit *verifiziert, nicht
reproduziert*: ein blockierendes Finding heißt "ein Mensch muss draufschauen", nicht
"bestätigter Exploit".

## Provider: Abo statt Pay-per-Use

Das Red Team hat OpenCode Zen benutzt (ein Key, viele Modelle, metered) und dafür >40.000 USD
ausgegeben. Für einen wiederkehrenden PR-Gate ist das die falsche Abrechnungsform. Die
Harness unterstützt deshalb drei Provider-Typen, pro Stufe mischbar:

| Typ | Wie | Kosten |
|---|---|---|
| **`cli`** | Ein Coding-Agent im Headless-Modus (`kimi -p`, `claude -p`, `opencode run`) | **im Abo enthalten** |
| `anthropic` | `/v1/messages`, inkl. Moonshots Anthropic-kompatiblem Adapter | metered |
| `openai` | `/chat/completions`, inkl. OpenCode Zen | metered |

**Der `cli`-Weg ist der Default.** Kimi K3 — genau das Modell, das beim Red Team gescannt hat
— ist über die Kimi-Membership im Terminal nutzbar:

```bash
npm i -g @kimi-code/cli
kimi                      # einmalig einloggen, danach läuft alles über das Abo
```

Kein API-Key, keine Token-Abrechnung. K3 braucht Tier *Moderato* oder höher; das 1M-Kontext-
fenster *Allegretto* oder höher. Die Limits liegen bei grob 300–1.200 Requests pro 5-h-Fenster
und ~30 gleichzeitigen Requests — deshalb hat `config.json` ein `maxConcurrency`, das die
Harness hart einhält. Dasselbe Muster funktioniert mit `claude -p` auf einem Claude-Abo.

Modelle werden als `provider:model` angegeben (`kimi-cli:kimi-k3`). Ein Provider, der nicht
erreichbar ist — CLI nicht im PATH, Key nicht gesetzt — wird sauber übersprungen und
gemeldet, statt den Lauf abzubrechen. Ist gar keiner erreichbar, endet Stufe B mit Exit 0;
Stufe A blockiert weiterhin.

> **Achtung bei `cli` in CI:** Coding-Agent-CLIs haben Tool-Zugriff auf Dateisystem und
> Shell. Sie in einem Job zu starten, der einen Checkout von *fremdem* PR-Code hält, gibt
> untrusted Input Werkzeuge in die Hand. Für PRs aus Forks nimm einen HTTP-Provider, oder
> starte die CLI mit den Read-only-/Permission-Flags des jeweiligen Agents. Lokal, gegen
> eigene Branches, ist der CLI-Weg unproblematisch — und dort spielt er seinen Kostenvorteil
> ohnehin am stärksten aus.

## Einrichtung

1. **Provider wählen.** Entweder eine CLI installieren und einloggen (siehe oben) — oder
   einen Key setzen: `MOONSHOT_API_KEY`, `ANTHROPIC_API_KEY` bzw. `SECURITY_AI_API_KEY`
   für Zen. In CI als Repository-Secret (optional unter Environment `security-ai`).
2. **Modelle eintragen:** `redteam/config.json` auf Provider und Modelle setzen, die du
   wirklich erreichst.
3. **Required Checks setzen:** In den Branch-Protection-Rules für `master` die Checks
   **`static`**, **`scanners`** und **`verify`** als *required* markieren (das sind die
   Check-Run-Namen, die der Authority-Workflow auf den PR-Head schreibt). Ohne diesen
   Schritt ist die Schwelle nur eine Anzeige. `ai-review` erst required setzen, nachdem
   die Falsch-Positiv-Rate über ein paar Wochen beobachtet wurde.
4. **Code-Owner-Reviews erzwingen** für `/.github/` und `/security/` (siehe
   `.github/CODEOWNERS`). Die Authority-Workflow-Datei kommt vom Default-Branch — Owner-
   Reviews verhindern, dass ein Merge die Authority selbst aushöhlt.
5. **Environment `security-ai`:** optional Required Reviewers aktivieren, damit Model-
   Keys auf `ai-review` nicht ohne menschliche Freigabe fließen.

## Lokal ausführen

```bash
security/gate/static-checks.sh origin/master

git diff origin/master...HEAD > /tmp/pr.diff
node security/redteam/harness.mjs --diff /tmp/pr.diff --out /tmp/report
```

Mit der Default-Konfiguration läuft das komplett über die Abos — kein Key im Environment.

## Audit-Modus (voller Repo-Scan)

Der PR-Gate deckt Diffs ab. Für einen Red-Team-Lauf gegen ein ganzes Repository ist die
Reihenfolge `01-recon.md` → pro Target `02-hunt.md` über mehrere Lenses → `03-verify.md` →
`04-repro.md` in einer Sandbox → `05-report.md`. Der Graph dazu steht in
[§3 der Rekonstruktion](../docs/security/bitcoin-red-team-reconstruction.md). `harness.mjs`
implementiert davon bewusst nur den Diff-Pfad.

## Anpassen für andere Repos

`security/`, `.github/workflows/security-scan.yml` und
`.github/workflows/security-pr-trigger.yml` sind selbstständig und lassen sich kopieren.
Repo-spezifisch anzupassen sind: die Host-Allowlist in Check 6 von `static-checks.sh`
(unbekannte Hosts blockieren), die Lens-Auswahl in `config.json` und die Blocking-Schwelle
in `gate.blockOn`.

Der PR-Pfad läuft über `workflow_run`: der Trigger-Workflow ist absichtlich minimal und
ohne Secrets; die Authority-Jobs laden ihre YAML vom Default-Branch. So kann ein PR die
Gate-Logik nicht umschreiben, indem er die Workflow-Datei auf seinem Branch ändert.
