# Messungen des Security-Scans

Fortlaufendes Protokoll. Jeder Eintrag entsteht aus `node security/eval/run.mjs`; die
Rohdaten liegen unter `security/eval/results/<timestamp>/` (nicht eingecheckt).

Zielwerte laut [Implementierungsplan](./implementation-plan.md) §3, Phase 0:

| Metrik | Zielwert |
|---|---|
| Detection Rate | ≥ 50 % |
| **Falsch-Positiv-Rate** | **≤ 5 %** |
| Blockiert aus falschem Grund | 0 |
| p95 Wall-Clock | ≤ 480 s |

---

## 2026-08-08 — Baseline, statisches Gate allein

Korpus: 10 Vuln-Fälle, 7 Negativkontrollen. Kommando:
`node security/eval/run.mjs --no-ai`

| Metrik | Wert | Ziel | |
|---|---|---|---|
| Detection Rate | **10,0 %** (1/10) | ≥ 50 % | verfehlt |
| Falsch-Positiv-Rate | **14,3 %** (1/7) | ≤ 5 % | verfehlt |
| Blockiert aus falschem Grund | 0 | 0 | erreicht |
| p95 Wall-Clock | 0,8 s | ≤ 480 s | erreicht |

Die AI-Stufe lief **nicht** — kein Modell-Provider erreichbar. Gemessen ist damit
ausschließlich `security/gate/static-checks.sh`.

### Was erkannt wurde

| Fall | Ergebnis |
|---|---|
| `vuln-010-workflow-injection` | **TP** — CI-Änderung löst die Review-Pflicht aus |
| alle übrigen 9 | **FN** |

### Was das aussagt

Die neun übersehenen Fälle sind kein Defekt, sondern die Bauart: Ein Muster-Scanner kann
weder „Fallback auf `Math.random()`" noch „Verifikation liefert `true`, wenn kein Key
gesetzt ist" noch „Balance-Check ohne Transaktion" erkennen. Dafür braucht es Datenfluss-
analyse (Phase 1, CodeQL/Semgrep) und semantisches Review (Phase 2/3).

Die Baseline erfüllt damit ihren Zweck: Sie zeigt, welchen Anteil das Gate **ohne** die
geplanten Stufen abdeckt — ein Zehntel — und liefert die Zahl, gegen die jede spätere Phase
gemessen wird.

### Gefundener Defekt: Falsch-Positiv `benign-002-legit-child-process`

Blockiert von *„dynamic execution / shell-out introduced"*. Der Fall ist:

```ts
import { execFileSync } from 'child_process';
execFileSync('npx', ['tsc', '--project', 'tsconfig.json'], { stdio: 'inherit' });
```

`execFileSync` mit fester Argumentliste und ohne Shell ist genau die *sichere* Form. Die
Regel matcht aber pauschal auf `child_process`. Bewusst **nicht** sofort gefixt, damit die
Baseline unverfälscht bleibt — festgehalten als erste Aufgabe für Phase 1: Die Regel gehört
nach Semgrep und muss zwischen `execFileSync(cmd, [args])` und `exec`/`execSync` mit
String-Interpolation unterscheiden.

---

## 2026-08-08 — Phase 1: Scanner-Stufe

Korpus unverändert. Kommando: `node security/eval/run.mjs --no-ai`
Aktiv: statisches Gate + Semgrep (eigene Regeln) + OSV-Scanner + Gitleaks über SARIF.

| Metrik | Vorher | **Jetzt** | Ziel | |
|---|---|---|---|---|
| Detection Rate | 10,0 % (1/10) | **60,0 %** (6/10) | ≥ 50 % | **erreicht** |
| Falsch-Positiv-Rate | 14,3 % (1/7) | **0,0 %** (0/7) | ≤ 5 % | **erreicht** |
| Blockiert aus falschem Grund | 0 | 0 | 0 | erreicht |
| p95 Wall-Clock | 0,8 s | 2,7 s | ≤ 480 s | erreicht |

### Was die Scanner-Stufe zusätzlich fand

| Fall | Regel |
|---|---|
| `001-prng-fallback` | `weak-random-in-security-context` |
| `003-verify-skipped-no-key` | `verification-returns-true-when-unconfigured` |
| `005-timing-unsafe-hmac` | `timing-unsafe-mac-comparison` |
| `006-proto-pollution` | `key-copy-without-proto-guard` |
| `007-path-traversal` | `path-join-unsanitised` |
| `010-workflow-injection` | `workflow-command-injection` (vorher schon vom statischen Gate) |

Alle sechs an der korrekten Zeile — keine `BLOCKED_WRONG_REASON`.

### Weiterhin übersehen (4/10)

`002-entropy-truncation`, `004-nonce-reuse`, `008-unbounded-recursion`,
`009-check-then-act-balance`. Alle vier verlangen semantisches Verständnis, das kein
Pattern-Matching liefert: „diese 32 Byte tragen nur 32 Bit Entropie", „dieser Zähler wird bei
Reconnect zurückgesetzt", „diese Prüfung und ihre Verwendung sind durch ein `await`
getrennt". Genau dafür existiert der Lens-Kanal (Stufe 3), reduziert auf `fallback`,
`entropy`, `state`.

### Der Falsch-Positiv aus der Baseline ist behoben

`benign-002-legit-child-process` läuft durch. Ursache war die pauschale
`child_process`-Regel im statischen Gate. Semgrep unterscheidet jetzt korrekt zwischen
`execFileSync(cmd, [args])` und `exec` mit String-Interpolation, deshalb hat `static-checks.sh`
diese Klasse abgegeben und behält nur noch `curl | sh` — das einzige Muster ohne legitime
Verwendung.

**Regressionstest bestanden:** Der synthetische bösartige PR (Credential, Postinstall-Hook,
`exec` mit Interpolation, `curl | sh`) wird weiterhin von beiden Stufen geblockt.

### Offen: Phase 2 ist noch nicht gemessen

Die Triage-Stufe läuft technisch (mit echtem Modell verifiziert: der PRNG-Fallback wurde
korrekt als `true_positive`/`critical` eingestuft, mit korrekt hergeleitetem Angriffspfad),
aber ihre **Wirkung auf die Falsch-Positiv-Rate ist ungemessen** — bei 0 % FP nach Phase 1
gibt es an diesem Korpus nichts zu filtern.

Das Abnahmekriterium für Phase 2 lautet deshalb: **kein Korpus-Bug darf als
`false_positive` verworfen werden.** Zu prüfen, sobald ein Provider konfiguriert ist:

```bash
node security/eval/run.mjs            # mit AI-Stufe
# und für jeden TP-Fall in security-report/triaged.json prüfen, dass verdict != false_positive
```

---

## 2026-08-09 — Phase 4: Beweisstufe

Kommando: `node security/prove/run-probes.mjs`

**5 von 5 Probes bestätigen ihren Fall.** Jeder Probe läuft in einem eigenen Kindprozess mit
Timeout, gegen eine Kopie des Falls, ohne Repository-Token.

| Fall | Beweis |
|---|---|
| `002-entropy-truncation` | `deriveSeed()` liefert zweimal dieselben 32 Byte — Suchraum ist die 4-Byte-Geräte-ID, ~2³² statt 2²⁵⁶ |
| `004-nonce-reuse` | Nonce `000000000000000000000000` vor **und** nach Reconnect ausgegeben |
| `006-proto-pollution` | Nach `mergeConfig({}, hostile)` meldet ein frisches, unbeteiligtes Objekt `polluted === "yes"` |
| `008-unbounded-recursion` | 50.000 Verschachtelungen → `RangeError: Maximum call stack size exceeded` |
| `009-check-then-act-balance` | Zwei gleichzeitige Abhebungen von je 60 gegen Guthaben 100 gelingen beide; Endstand **−20** |

### Diese Zahlen zählen NICHT zur Detection Rate

Ein Probe, der neben der Lösung liegt, beweist nichts über das, was der Gate von sich aus
findet. Die Probes validieren den **Korpus**: Sie belegen, dass jede Ground Truth einen
echten Defekt beschreibt und nicht nur eine Code-Meinung. Vier der fünf sind genau die Fälle,
die die Scanner-Stufe übersieht — damit ist belegt, dass diese vier FN echte Bugs sind und
nicht falsch etikettierte Fixtures.

In Produktion schreibt das Modell den Probe (`prompts/04-repro.md`), und er läuft in einer
Sandbox ohne Token und ohne Netz — nie im Job, der Checkout und Token hält.

### Nebenbefund

Ein Fixture importierte `./device` ohne Erweiterung — für Node ESM nicht auflösbar. Erst der
Probe hat das aufgedeckt; die Scanner-Stufe hatte den Fall nie geladen, nur gelesen. Genau
dafür ist eine ausführende Stufe da.

### Nächste Messung

Phase 3 mit Provider: trägt der Lens-Kanal bei den vier FN, die die Werkzeuge strukturell
nicht erreichen? Die Probes liefern dafür jetzt die unabhängige Bestätigung, dass dort
wirklich etwas zu finden ist.

Zur Laufzeit: p95 schwankte zwischen Läufen deutlich (2,6 s bis 16,6 s) — Maschinenlast, nicht
Pipeline-Änderung. Beide Werte liegen weit unter dem Ziel von 480 s.

---

## 2026-08-09 — Erster echter CI-Lauf (PR #1)

Der Lauf, den die lokale Umgebung nicht liefern konnte: GitHub-Runner mit vollem Netzzugang.

| Job | Ergebnis | Dauer |
|---|---|---|
| `codeql` | **success** | 45 s Analyse |
| `scanners` | **success** | Semgrep + Gitleaks → SARIF → Code Scanning |
| `static` | **failure** | drei Blocks, siehe unten |
| `ai-review` | **skipped** | wegen `needs: static` |

### Was damit erstmals belegt ist

- **CodeQL läuft.** `javascript-typescript` mit `security-extended`, init + analyze grün.
  Lokal war das nicht testbar (Bundle-Download geblockt).
- **Der SARIF-Pfad funktioniert.** Zwei Berichte (`semgrep_oss`, `gitleaks`) ins
  GitHub Code Scanning hochgeladen, danach Normalisierung und Triage ohne Fehler.
- **OSV wird korrekt übersprungen** — das Repo hat seit dem Umbau kein Lockfile mehr.
  Der Scanner meldet das explizit, statt einen leeren Bericht als sauber auszugeben.
- Scanner-Installation kostet ~2 min pro Lauf (pip semgrep + zwei `go install`).

### Drei Blocks — zwei davon Falsch-Positive

Das Gate hat **seinen eigenen Pull Request blockiert**, zweimal an eigenem Material:

| Block | Bewertung |
|---|---|
| CI-Konfiguration geändert | by design — aber siehe unten |
| „adds an install/postinstall script" | **FP**: die Semgrep-Regel *zitiert* `"postinstall"`, um es zu erkennen |
| „download piped into a shell" | **FP**: ein Korpus-Fixture enthält absichtlich `curl \| sh` als Köder |

Beide sind dieselbe Klasse: **ein Prüfer, der auf seine eigenen Regeldefinitionen und
Testdaten anschlägt.** Der Ausschluss galt bereits für `*.md`, aber nicht für
`security/scanners/semgrep/rules/`, `security/eval/corpus/` und `security/redteam/prompts/`
— jetzt behoben, zusammen mit Check 3, der noch alle Dateien statt nur Code las.

**Warum die lokale Messung das nicht finden konnte:** `run.mjs` fährt Korpus-Fälle durch das
Gate, jeder in einem eigenen Wegwerf-Repo. Das Gate wurde **nie gegen den Diff dieses
Repositories selbst** gefahren. Genau dort lagen beide Fehler. Der Selbsttest
`security/gate/static-checks.sh master` gehört ab jetzt zur Routine — er läuft jetzt grün.

### Zwei Designfehler, die der Lauf aufdeckte

**CI-Änderung als harter Block ist eine Sackgasse.** Als Required Check könnte kein Fix am
Gate jemals mergen — jede Änderung an `.github/workflows/` färbt den Check rot. Herabgestuft
auf `note`. Die gefährlichen Formen bleiben präzise geblockt: `pull_request_target` mit
Head-Checkout im statischen Gate, Command-Injection über die Semgrep-Regel. Die Detection
Rate bleibt dadurch bei 60 % — `vuln-010` wird ohnehin von Semgrep an der richtigen Zeile
gefunden, nicht nur von der Pauschalregel.

**`ai-review: needs: static` hat die AI-Stufe stillgelegt.** Static ging rot, also lief die
Stufe gar nicht — ausgerechnet die, die zum Inhalt etwas hätte sagen können, wurde von einem
unabhängigen Urteil zum Schweigen gebracht. `needs` entfernt; jede Stufe berichtet für sich.

### Korpus-Messung nach den Korrekturen

Unverändert: **Detection 60,0 % (6/10), Falsch-Positive 0,0 % (0/7)**, p95 2,8 s.
Zusätzlich neu grün: das Gate gegen den eigenen Diff.


---

## 2026-08-09 — PR #2: die Korrekturen halten, und ein toter Check kommt ans Licht

Alle sieben Checks grün: `static`, `scanners`, `codeql`, `ai-review` plus die drei
Code-Scanning-Analysen (Semgrep OSS, Gitleaks, CodeQL). Beide Korrekturen aus PR #1
bestätigt — `static` läuft durch, und `ai-review` wird nicht mehr stillgelegt.

### Was der Log offenlegte, obwohl der Job grün war

```
Scanners not contributing:
  semgrep: error — exit 2
  osv: skipped — no lockfile
7 raw -> 7 deduped -> 0 in diff scope -> 0 blocking
```

Semgrep meldete `error`, hatte aber **sieben Findings geliefert**. Die Ursache lokal
reproduziert:

> `Rule parse error in rule crypto-fallback-in-catch: Invalid pattern for JavaScript`

**Eine der zwölf Regeln hat nie kompiliert und ist nie gelaufen** — ausgerechnet die für die
COLDCARD-Klasse. Der Regelsatz gab deshalb durchgehend Exit 2 zurück, während die übrigen
Regeln normal Ergebnisse produzierten. Zwei Gründe, warum das monatelang hätte unentdeckt
bleiben können:

1. `catch(...)` ist keine gültige JavaScript-Pattern-Syntax. Semgrep verwirft die Regel und
   scannt weiter.
2. Mein Exit-Code-Handling war **in beide Richtungen falsch**: erst galt 2 als Erfolg (versteckt
   die kaputte Regel), dann als Fehler (versteckt sieben gültige Findings).

Behoben: Die Regel ist als `Math.random()` **innerhalb** eines `catch` formuliert — auch
robuster, denn `...` erreicht keine Ausdrücke, die in einer Schleife im Catch-Block liegen;
selbst eine kompilierende Fassung der alten Form hätte den Korpus-Fall verfehlt. Der
Orchestrator urteilt jetzt nach dem **Bericht**, nicht nach dem Exit-Code, und meldet einen
Regel-Parse-Fehler als eigenen Status `degraded` — laut, aber nicht fatal.

### Zweiter Fund: Semgrep hing 98 Sekunden im Netzwerk

Ein Korpus-Fall brauchte 1 m 40 s bei 1,9 s CPU — Semgrep wartete auf seinen
Versionscheck gegen `semgrep.dev`. Mit `--disable-version-check`: **3 s**. In Orchestrator und
beiden Hooks ergänzt. Ein Scanner in einem blockierenden Gate darf nicht auf einen fremden
Server warten.

### Messung nach den Korrekturen

| Metrik | Wert | Ziel | |
|---|---|---|---|
| Detection Rate | 60,0 % (6/10) | ≥ 50 % | erreicht |
| Falsch-Positiv-Rate | 0,0 % (0/7) | ≤ 5 % | erreicht |
| Blockiert aus falschem Grund | 0 | 0 | erreicht |
| p95 Wall-Clock | 2,6 s | ≤ 480 s | erreicht |

Unverändert — die reparierte Regel trifft denselben Fall (`001-prng-fallback`), den
`weak-random-in-security-context` schon fand. Der Gewinn ist keine höhere Zahl, sondern
**eine Regel, die tatsächlich existiert**: Semgrep meldet jetzt 8 statt 7 Findings über das
Repo, und der Regelsatz kompiliert fehlerfrei.

Selbsttest gegen den eigenen Diff: grün. Probes: 5/5.


---

## 2026-08-09 — Gate-Härtung (Review des Gates gegen sich selbst)

Zwölf Befunde aus einem Review des Gates an eigenem Code (Parser-Fragilität, Exit-Pfade,
Diff-Scope, Sentinel-Stripping, Workflow-Permissions, Versions-Pins, Testlücken). Die
Korpus-Metriken bleiben unverändert; gemessen wurde die Regressionssuite und der
unveränderte Scanner-Korpus.

Kommando Korpus: `node security/eval/run.mjs --no-ai`  
Kommando Suite: `bash security/gate/gate.test.sh`  
Kommando Probes: `node security/prove/run-probes.mjs`

| Metrik | Wert | Ziel | |
|---|---|---|---|
| Detection Rate | 60,0 % (6/10) | ≥ 50 % | erreicht |
| Falsch-Positiv-Rate | 0,0 % (0/7) | ≤ 5 % | erreicht |
| Blockiert aus falschem Grund | 0 | 0 | erreicht |
| p95 Wall-Clock | 1,3 s | ≤ 480 s | erreicht |

### Suite

Ausgeliefert hat die Runde **19/19** Fälle in `security/gate/gate.test.sh` (lokal, bash/node).
Der Zwischenstand von 16 Fällen, der hier ursprünglich stand, war die Zahl zum Zeitpunkt des
Parser-Fixes; die drei Fälle für den Scanner-Ausfall kamen im selben Pull Request danach.

Setzt man `security/scanners/normalize.mjs` auf den Stand vor beiden Fixes zurück, fallen
**2 von 19** Fällen: der Positionsfall `--no-gate` zuerst und der Fall, dass ein Scanner im
Status `error` den Schritt scheitern lassen muss. Beide Fixes liegen in derselben Datei,
deshalb trifft ein Rückbau sie zusammen. Die übrigen siebzehn bleiben grün — der Workflow
setzt `--no-gate` ans Ende, und die anderen Fälle prüfen andere Pfade.

### Was sich nicht geändert hat

Detection und Falsch-Positiv-Rate sind dieselben wie nach PR #2. Die Härtung adressiert
Fragilität und Beweisbarkeit, nicht die Erkennungsrate am Korpus.

### Ausdrücklich offen (nicht in diesem Lauf belegt)

- **F1-Reset (Fork- vs. Branch-PR):** nie in einem echten GitHub-Actions-Lauf gegen einen
  Fork-PR und einen Branch-PR im selben Repo geprüft. Lokal nur Code-Pfad gelesen.
- **Versions-Pins:** SHA-Pins der Actions per API belegt, aber nie auf einem GitHub-Runner
  installiert und ausgeführt. Ob die gepinnten Ref/SHA-Paare auf dem Runner auflösen, ist
  ungemessen.

Kein Eintrag hier behauptet, dass diese beiden Punkte grün sind.

Probes: 5/5. Semgrep über das Repo ohne Korpus: Exit 0, 0 Parse-Fehler (lokal mit
Semgrep 1.136.0).


---

## 2026-08-10 — Schwellen erzwingen und in CI messen

Bis hierher waren die Korpus-Kennzahlen von nichts abgesichert: `eval/run.mjs` schrieb
Detection ≥ 50 % und Falsch-Positive ≤ 5 % in den Report, beendete aber immer mit Exit 0
(auch bei 0 % Detection, etwa wenn Semgrep fehlte). Kein CI-Job fuhr Suite, Probes oder
Korpus-Messung.

**Was jetzt gilt**

- `security/eval/run.mjs` erzwingt die dokumentierten Schwellen (50 % / 5 %) als Exit-Code;
  Flags `--min-detection` / `--max-fp` überschreiben sie. Leerer oder einseitiger Korpus
  (keine Vuln- oder keine Benign-Fälle) ist ein Fehler, kein vacuous pass. p95 bleibt ohne
  Schwelle (Maschinenlast, nicht Regression).
- CI-Job `verify` in `.github/workflows/security-scan.yml` fährt der Reihe nach
  `gate.test.sh`, `run-probes.mjs`, `eval/run.mjs --no-ai`. **Kein** Base-Revision-Reset:
  der Job prüft die PR-Änderung, nicht die Base gegen sich selbst. Authority bleiben
  `static` und `scanners`.
- Installiert wird nur Semgrep `1.172.0` (wie im `scanners`-Job).

Kommando: `node security/eval/run.mjs --no-ai`  
Suite: `bash security/gate/gate.test.sh`  
Probes: `node security/prove/run-probes.mjs`

| Metrik | Wert | Schwelle | |
|---|---|---|---|
| Detection Rate | 60,0 % (6/10) | ≥ 50 % | **erzwungen** |
| Falsch-Positiv-Rate | 0,0 % (0/7) | ≤ 5 % | **erzwungen** |
| Blockiert aus falschem Grund | 0 | 0 | erreicht |
| p95 Wall-Clock | 1,3 s | (nicht erzwungen) | informativ |

### Ausdrücklich weiterhin ungemessen

- **Modellstufen (Triage / Lens):** kein Provider in diesem Lauf; Wirkung auf Detection und
  FP-Rate bleibt unbelegt.
- **Korpuszahlen mit `osv-scanner` / `gitleaks`:** die 60 %/0 % sind mit Semgrep allein
  gemessen. Beide Tools bewusst nicht im `verify`-Job; ihre Aufnahme erfordert eine neu
  gemessene Baseline, sonst ist unklar, welche Änderung die Zahl bewegt hat.

### Erster CI-Lauf des `verify`-Jobs (PR #3, Branch `fix/enforce-and-measure`)

Der Job hat im ersten Lauf, in dem er existiert, einen Defekt gefunden, den vier vorherige
grüne Jobs (`static`, `scanners`, `codeql`, `ai-review`) nicht sehen konnten.

- **Suite:** 23/23 grün (unter Node 20).
- **Probes:** rot. Wörtlich aus dem Job-Log, Schritt `Probes`:
  `TypeError: Unknown file extension ".ts" for /tmp/probe-…/src/seed.ts`
  (u. a. `vuln-002-entropy-truncation`, `vuln-004-nonce-reuse`).
- **Ursache:** `security/prove/exec-probe.mjs` lädt Korpus-Fixtures per dynamischem
  `import()`; der Korpus enthält `.ts`-Dateien. Der Job stand auf `node-version: '20'`,
  und Node 20 kann TypeScript-Typen nicht strippen. Gegenprobe lokal (v22.22.3): mit
  Type-Stripping laufen die Probes 5/5; ohne (z. B. `NODE_OPTIONS=--no-experimental-strip-types`)
  derselbe `ERR_UNKNOWN_FILE_EXTENSION` / `Unknown file extension ".ts"`.
- **Folge:** Schritt „Corpus thresholds“ wurde nicht mehr erreicht.
- **Korrektur:** `verify` auf Node 22; README/`engines` nennen den Unterschied Gate vs.
  Beweisstufe statt „Node ≥ 20“ für alles.

---

## 2026-08-15 — Erste echte KI-gestützte Messung (Codex/Claude, nicht `--no-ai`)

Kommando: `node security/eval/run.mjs` (voller Korpus, 10 Vuln + 7 Negativkontrollen, kein
`--skip-ai`).

| Metrik | Wert | Ziel | |
|---|---|---|---|
| Detection Rate | **90,0 %** (9/10) | ≥ 50 % | erreicht |
| Falsch-Positiv-Rate | **0,0 %** (0/7) | ≤ 5 % | erreicht |
| Blockiert aus falschem Grund | 0 | 0 | erreicht |
| p95 Wall-Clock | 143,3 s | ≤ 480 s | erreicht |

Rohdaten: `security/eval/results/2026-08-15T06-03-10-956Z/` (nicht eingecheckt).

Der erste Versuch dieser Messung ergab identisch 60,0 % / 0,0 % bei 12,6 s p95 — exakt die
alte statisch-nur-Baseline vom 2026-08-08, obwohl `--no-ai` nicht gesetzt war. Ursache: der
KI-Hunt-Provider (`security/eval/run.mjs`) hatte **nie** `SECURITY_CLAUDE_WRAPPER` oder das
PATH-Fragment für `codex`/`kimi` gesetzt — die separate `check-pr.mjs`-Umgebung
(`stageEnv()`) wurde dafür bereits gehärtet (PR #21), aber `eval/run.mjs` ist ein eigener
Einstiegspunkt und hatte diese Verdrahtung nie geerbt. `ai.log` zeigte für jeden Fall
denselben Fehler wie unten unter „Kimi-CLI-Defekt" — die KI-Stufe lief in jedem einzelnen
bisherigen Aufruf dieses Skripts still auf null Ergebnisse. Fix: neue `aiStageEnv()` in
`security/eval/run.mjs`, spiegelt `stageEnv()`. Landete zusammen mit dem Merge-Base-Fix in
PR #22 (Amoxidx/security-scan).

**Damit ist dies die erste Messung, die die Zielwerte je mit echter KI-Beteiligung erreicht
hat — seit Projektstart lief hier faktisch immer nur das statische Gate**, ohne dass das an
den gemeldeten Zahlen sichtbar war.

---

## 2026-08-15 — Echter Produktions-Korpus (217 reale Scans, `auto-pr-check`-LaunchAgent)

Kein `eval/run.mjs`-Lauf — Auswertung der realen `check-pr.mjs`-Ergebnisse, die der
LaunchAgent auf macpro über zwei Tage für tatsächlich geöffnete PRs in DFXswiss/,
RealUnitCH/ und zk-coins/ gesammelt hat (`~/.cache/security-scan/auto-pr-check/runs/`,
217 Verzeichnisse zum Auswertungszeitpunkt). Das ist der synthetische Korpus oben nicht:
17 echte Zielrepos, reale Diffs, reale Autoren, kein kuratiertes Vuln/Benign-Set.

| Ergebnis | Anzahl | Anteil |
|---|---|---|
| PASS | 81 | 37,3 % |
| BLOCK — echte Inhalts-Findings (static + AI) | 39 | 18,0 % |
| BLOCK — als „no merge base" fehlklassifiziert (Tooling-Defekt, s. u.) | 60 | 27,6 % |
| Crash — falsches Target zugeordnet | 17 | 7,8 % |
| Crash — PR-Head-Fetch non-fast-forward | 9 | 4,1 % |
| Degraded (KI-Stufe lief nicht) | 1 | 0,5 % |

**Drei reale Infrastrukturdefekte gefunden und behoben, die zusammen 40,3 % aller 217
Läufe (86 von 217) verfälscht hatten — nicht nur „nicht gelaufen", sondern in 60 Fällen als
scheinbar legitimer Sicherheits-Block gemeldet:**

1. **Shallow-Clone-Merge-Base (PR #22).** `git fetch --depth 50` auf beiden Seiten eines
   Drei-Punkt-Diffs verliert den Merge-Base, sobald der Base-Branch seit dem PR-Fork mehr als
   50 Commits gewandert ist. Das äußerte sich **nicht** als Crash, sondern als
   `Static security gate: BLOCKED — git diff failed against base ref … no merge base` — ein
   Tooling-Fehler, der wie ein Sicherheitsfund aussah. 60 der 99 als „static-only BLOCK"
   gezählten Läufe waren tatsächlich das (siehe Detailtabelle unten), nicht 47 „harte Crashes"
   wie in einer ersten, gröberen Zählung vermutet — das statische Gate fängt einen
   `git`-Fehler ab und meldet ihn als Blocker, statt die Pipeline abzubrechen. Fix:
   `fetchBaseFully()` nutzt `--unshallow`.
2. **Falsches `defaultTarget` (PR #23).** Jedes org-entdeckte Repo außerhalb der 18 benannten
   Targets fiel auf das Self-Scan-Target zurück (`repo: Amoxidx/security-scan`,
   `defaultBase: master`) — 17 Läufe (7,8 %) klonten das falsche Repo gegen den falschen
   Base-Branch-Namen und crashten vor jedem Check. Fix: `defaultTarget: "generic"`.
3. **PR-Head-Fetch ohne Force-Prefix (PR #24).** Der persistente lokale Checkout behält
   `refs/security-scan/pr-<n>` über Scans hinweg; nach einem Rebase/Force-Push auf GitHub
   verweigerte `git fetch` die Non-Fast-Forward-Aktualisierung — 9 Läufe (4,1 %). Fix:
   `+`-Force-Prefix auf der PR-Head-Refspec.

### Die 39 echten Inhalts-Blocks im Detail

| Grund | Läufe | Einordnung |
|---|---|---|
| „New outbound endpoints" — reines Platzhalter-/Testdomain-Muster (`*.example`, `*.test`, `scripts.sil.org`) | 18 | **Falsch-Positiv** — keine dieser Domains ist ein realer Netzwerkaufruf |
| „New outbound endpoints" — mindestens ein echter neuer Host (`dilisense.com`, `opencollective.com`, interne `dfx.swiss`-/`zkcoins`-Subdomains, Doku-/Social-Links) | 17 | Regelkonform „neu, nicht auf der Allowlist" — in keinem der Fälle ein tatsächlich bösartiger oder überraschender Host; Reibung, kein Fund |
| Lockfile-/Manifest-Inkonsistenz | 6 (aus 3 Läufen, 2 Findings/Lauf) | nicht einzeln geprüft |
| KI-Hunt mit „N blocking" > 0 | 5 | s. u. |

**Kein einziger der 217 realen Läufe hat einen tatsächlich bösartigen oder
Angreifer-kontrollierten Host gefangen.** Die „New outbound endpoints"-Regel produzierte in
mindestens 51 % der Fälle (18 von 35), in denen sie überhaupt auslöste, ein reines
Platzhalter-Muster als Block-Grund.

### Die 5 echten KI-Blocks: 5 von 5 unverifiziert

Von 217 realen Scans haben genau 5 einen KI-Fund mit `blocking > 0` erzeugt. **Alle 5 sind
`NOT verified — no usable verifier verdict`** — die adversariale Verifikation, die laut
zitierter Literatur (DARPA AIxCC, Buttercup) die 92 %→6 % FP-Reduktion liefert, hat in der
gesamten beobachteten Produktionslaufzeit **kein einziges Mal** tatsächlich stattgefunden.

**Ursache: Kimi-CLI-Defekt.** `hunt[fallback]` und `hunt[entropy]` (2 von 3 Hunt-Lenses) und
ein Drittel der Verify-Modelle sind auf `kimi-cli:kimi-k3` konfiguriert. Jeder einzelne
Aufruf in allen 217 Läufen scheiterte identisch:
`kimi exited 1: unknown command 'kimi-k3'. See 'kimi --help'.` — vermutlich eine
CLI-Versions-Inkompatibilität zwischen der installierten `kimi`-Version und dem konfigurierten
Modell-Flag, kombiniert mit der bereits bekannten inaktiven Kimi-Mitgliedschaft. **Effekt:
die „3 unabhängige Lenses + adversariale Verifikation"-Architektur lief in 100 % der
beobachteten Produktionsfälle faktisch als Ein-Lens-System (nur `claude-cli`), dessen Funde
nie gegengeprüft wurden, sondern per Fail-open-Policy ungeprüft durchgereicht wurden.** Nicht
behoben — Kimi-Mitgliedschaft ist ein externer Blocker außerhalb dieses Repos.

Stichprobe der 5 Funde (nicht einzeln verifiziert, aber inhaltlich plausibel):
`DFXswiss/api#4992` (SSH-Bootstrap überschreibt `authorized_keys` bei jedem Push blind),
`DFXswiss/api#4966` (UPDATE-Guard nach Payout-Read, doppelte Auszahlung möglich),
`DFXswiss/services#1330` (Broadcast-Tx-Hash wird bei Fehler verworfen, User soll manuell
erneut senden). Keiner dieser Funde wurde von JK oder einem menschlichen Reviewer bestätigt
oder verworfen — sie liegen als „nicht verifiziert" im jeweiligen Report.

### Modellverfügbarkeit real gemessen

Über die 217 Läufe: **0 erfolgreiche Kimi-Aufrufe, 0 erfolgreiche Codex-Aufrufe** (Codex war
in älteren Läufen „not on PATH" — vor PR #21 gepullt; ein Live-Test nach allen vier Fixes
am 2026-08-15 zeigt Codex jetzt erreichbar, aber mangels weiterer Läufe seit dem Fix noch
nicht in einer echten Produktionsmessung bestätigt). **100 % der 36 erfolgreichen KI-Aufrufe
kamen von `claude-cli`.**

### Nebenfund: eigener Fix erzeugt eine neue, unverifizierte KI-Meldung

Ein Live-Testlauf von `check-pr.mjs` gegen den eigenen PR #24 (nach dessen Merge) fand einen
plausiblen, nicht reproduzierten Fund gegen die eigene neue Zeile: ein gleichzeitiger Scan
derselben PR-Nummer könnte über das gemeinsame Force-Fetch-Ziel den verifizierten Commit
gegen einen anderen austauschen (TOCTOU zwischen `fetchPrHead()` und `git worktree add`).
Real, aber praktisch nicht erreichbar: `auto-pr-check.sh` verarbeitet PRs sequentiell
(`while`-Schleife, keine Parallelisierung) — nur ein manueller, zeitgleicher Zweitlauf
könnte das Fenster treffen. Nicht als eigener Fix verfolgt (Fallzahl trägt nicht); hier
dokumentiert als Beleg für die Fundqualität: plausibel, korrekt lokalisiert, aber unverifiziert
und von geringer praktischer Reichweite — das Muster, das sich durch alle 5 echten Blocks
zieht.

---

## Vorlage für weitere Einträge

```
## JJJJ-MM-TT — <Phase / was geändert wurde>

Kommando: `...`

| Metrik | Wert | Ziel | |
|---|---|---|---|
| Detection Rate | | ≥ 50 % | |
| Falsch-Positiv-Rate | | ≤ 5 % | |
| Blockiert aus falschem Grund | | 0 | |
| p95 Wall-Clock | | ≤ 480 s | |

Was sich gegenüber der Vormessung geändert hat:
Neue Falsch-Positive und ihre Ursache:
```
