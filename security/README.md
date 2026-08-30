# Security Scan

Eine blockierende Security-Schwelle für Pull Requests, abgeleitet aus der Methodik des
Bitcoin Red Teams. Die Herleitung — was belegt ist, was rekonstruiert — steht in
[`docs/security/bitcoin-red-team-reconstruction.md`](../docs/security/bitcoin-red-team-reconstruction.md).

## Aufbau

```
security/
├── gate/static-checks.sh        Stufe A — deterministisch, immer, blockiert immer
├── redteam/
│   ├── harness.mjs              Stufe B — hunt → dedupe → verify → report
│   ├── config.json              Lenses, Modelle, Blocking-Schwelle
│   └── prompts/                 00-system, 01-recon, 02-hunt, 03-verify, 04-repro, 05-report
├── lab/                         manuelles Repro-Lab (nie CI) — siehe Abschnitt unten
└── studio/                      Studio-Orchestrierung: PR-Check + Lab-Evidenz (nie GitHub-hosted CI)
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

## Studio-Check (`security/studio/`)

Pipeline **auf Studio** — primär für **deine PRs**, vorbereitet für **andere Codebasen**:

```bash
bash security/studio/bootstrap.sh
node security/studio/check-pr.mjs --list-targets

# Primär: PR mit Target (nutzt lokalen Clone als Worktree, wenn vorhanden)
node security/studio/check-pr.mjs --target dfx-api --pr 1234 --post
node security/studio/check-pr.mjs --target dfx-services --pr 99 --post

# Sekundär: beliebigen Tree testen
node security/studio/check-pr.mjs --dir /path/to/code --mode tree --skip-ai
```

Modi: `pr` | `local` | `tree`. Targets: `targets.json` (dfx-api, dfx-services, …).
Stufen: static → scanners → triage → harness → Lab → Gate.
Details: [`security/studio/README.md`](studio/README.md).

## Lokales Repro-Lab (`security/lab/`)

Umsetzung genau dieser Entscheidung als **manuelles** Kommandozeilenwerkzeug — nicht als
CI-Job. Findings, die die `verify`-Stufe (k-of-n Refutation) überstehen, sind sonst nur durch
Modell-Meinung abgesichert; das Lab holt **machine evidence**, indem es ein lokales
Coding-Modell (Standard: `jk-coder`, ein Qwen3.8-Flash-Next (MoE, 4-bit) über mlx-serve statt
Ollama; Endpunkt und Name sind gleich geblieben) einen Repro-Skript-Vorschlag
schreiben und in Isolation ausführen lässt.

**Läuft nur lokal, nur manuell, nie in GitHub Actions.** Die Workflows unter
`.github/workflows/` bleiben unberührt. Kein neuer Trigger, kein neuer Job.

### Was es macht

1. Liest ein Finding (Schema wie `harness.mjs` / `triage.mjs`) und den betroffenen Codebaum.
2. Spricht Ollama über die bestehende OpenAI-kompatible Provider-Route
   (`config.json` → Provider `ollama`, `type: "openai"`,
   `baseUrl: "http://localhost:11434/v1"`).
3. Treibt eine enge execute/conclude-Schleife: das Modell liefert JSON mit einem Skript,
   das Lab schreibt es in ein **ephemeres** Workdir und startet es in einem Container.
4. Schreibt einen Bericht nach `--out` mit Verdict
   `reproduced` | `not-reproduced` | `inconclusive`, Sandbox-Logs und Modell-Begründung.

### Sandbox

Container über colima/docker (auf dieser Maschine: `colima start`, danach `docker`):

| Maßnahme | Wert |
|---|---|
| Netzwerk | `--network none` |
| Lebensdauer | `--rm` (nach jedem Lauf weg) |
| Mount | nur das gestagte Workdir — **kein** `.git`, kein Host-Home, kein Docker-Socket |
| Credentials | Allowlist-Env im Container; `GH_TOKEN` / API-Keys / `SSH_AUTH_SOCK` leer |
| Ressourcen | `--memory` / `--cpus` (Defaults: 512m / 1) |
| Zeit | Wrapper-Timeout im Skript **und** `timeout` im Container — beides |

### Nicht-Konvergenz (fail closed)

Frühere Läufe mit demselben Modell konnten in Endlosschleifen hängen. Das Lab hat deshalb:

- harten **Turn-Cap** (`--max-turns`, Default 6)
- harten **Wall-Clock** (`--timeout-s`, Default 600)
- Prozess-Hard-Kill kurz hinter dem Wall-Clock

Reißt eines der Limits, endet der Lauf mit

```text
inconclusive — did not converge within <N> turns / <T>s
```

und Exit-Code **2**. „Kein Ergebnis“ ist **nicht** „sicher“ und wird auch nicht als
`not-reproduced` gemeldet.

### Voraussetzungen

```bash
# einmalig / bei Bedarf — der Model-Server ist mlx-serve, nicht Ollama.
# Er muss installiert sein und auf 127.0.0.1:11434 lauschen; wo er liegt, ist
# maschinenspezifisch. Start wahlweise als launchd-Agent oder im Vordergrund:
mlx-serve serve --host 127.0.0.1 --port 11434 &   # oder: als launchd-Agent geladen, dann läuft er von selbst
curl -s http://127.0.0.1:11434/api/tags    # muss jk-coder listen

# Modell: jk-coder, MLX-4-bit-quantisiert (in der Modell-Datei unter
# quantization_config.bits = 4 nachlesbar). Ollama wird nicht mehr installiert oder
# gepullt; mlx-serve bedient die Ollama-Routen /api/tags und /v1/chat/completions auf
# Port 11434, deshalb funktionieren Modell-Erkennung
# (security/studio/lab-model.mjs) und Provider-Konfiguration unverändert.

colima start                 # docker-CLI spricht danach den colima-Socket
docker pull node:22-bookworm-slim
```

Das gestagte Sandbox-Workdir liegt unter `$HOME/.cache/security-lab/` (nicht unter
`/tmp`): colima mountet standardmäßig nur das Home-Verzeichnis; Bind-Mounts aus
`/tmp` oder `/private/tmp` erscheinen im Container leer.

### Aufruf

```bash
node security/lab/run.mjs \
  --finding security/lab/fixtures/finding-proto-pollution.json \
  --code-dir security/eval/corpus/vuln/006-proto-pollution/after \
  --out /tmp/lab-report

# Gegenprobe fail-closed (muss inconclusive liefern):
node security/lab/run.mjs \
  --finding security/lab/fixtures/finding-proto-pollution.json \
  --code-dir security/eval/corpus/vuln/006-proto-pollution/after \
  --max-turns 1 \
  --timeout-s 2 \
  --out /tmp/lab-report-cap
```

Exit-Codes: `0` = conclusively `reproduced` oder `not-reproduced`, `2` = `inconclusive`,
`3` = Setup-Fehler (Config, fehlendes Image, Modell nicht erreichbar).

Provider-Eintrag in `redteam/config.json` (kein neuer Transport-Typ):

```json
"ollama": {
  "type": "openai",
  "baseUrl": "http://localhost:11434/v1",
  "apiKeyEnv": "OLLAMA_API_KEY"
}
```

`run.mjs` setzt `OLLAMA_API_KEY=ollama`, wenn die Variable fehlt (Ollama ignoriert den
Auth-Header).

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
Dasselbe Muster funktioniert mit einer OpenAI-Codex-CLI auf einem Codex-Abo:
`npm i -g @openai/codex && codex` (einmalig einloggen). Modellspec: `codex-cli:<model>`.

Modelle werden als `provider:model` angegeben (`kimi-cli:kimi-code/k3`). Ein Provider, der nicht
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
   **`static`**, **`scanners`** und **`verify`** als *required* markieren (Check-Run-
   Namen vom Authority-Workflow auf dem PR-Head). `ai-review` erst required setzen,
   nachdem die Falsch-Positiv-Rate über ein paar Wochen beobachtet wurde.
4. **Code-Owner-Reviews erzwingen** für `/.github/` und `/security/` (siehe
   `.github/CODEOWNERS`). Owner-Reviews verhindern, dass ein Merge die Authority aushöhlt.
5. **Environment `security-ai`:** optional Required Reviewers aktivieren, damit Model-
   Keys auf `ai-review` nicht ohne menschliche Freigabe fließen.

**PR-Pfad und Trust-Boundary:** `security-scan.yml` hat **keinen** `pull_request`-Trigger.
Nur `Security PR Trigger` (minimal, ohne Secrets) läuft am PR; die Authority-Jobs laufen
über `workflow_run` und laden ihre YAML **immer vom Default-Branch**. So kann ein PR die
Required-Check-Namen nicht mit eigener Workflow-YAML grün färben.

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
(unbekannte Hosts in Produktionspfaden blockieren; Matching ist case-insensitive und
host-verankert) plus `hostAllowExtra` am Studio-Target, die Lens-Auswahl in `config.json`
und die Blocking-Schwelle in `gate.blockOn`.

Der PR-Pfad läuft ausschließlich über `workflow_run` (kein `pull_request` am
Authority-Workflow). Der Trigger ist minimal und ohne Secrets; die Authority-Jobs laden
YAML und `security/` vom Default-Branch.
