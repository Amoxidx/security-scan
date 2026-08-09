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
