# Evaluations-Korpus (Phase 0)

Misst, was das Security-Scan tatsächlich findet — und was es fälschlich blockiert.

```bash
node security/eval/run.mjs --no-ai          # statisches Gate allein, ~1 s
node security/eval/run.mjs                  # inklusive AI-Stufe (braucht Provider)
node security/eval/run.mjs --only prng      # einzelner Fall
node security/eval/run.mjs --keep           # Arbeitsverzeichnisse behalten
```

Ergebnisse landen in `security/eval/results/<timestamp>/` (nicht eingecheckt), die
Zusammenfassung wandert nach [`docs/security/measurements.md`](../../docs/security/measurements.md).

> `--no-ai` benutzen, wenn eine Coding-Agent-CLI im PATH liegt. Sonst feuert die Harness pro
> Fall echte Agent-Calls, und ein Durchlauf dauert Stunden statt Sekunden.

## Aufbau eines Falls

```
corpus/vuln/001-prng-fallback/
├── meta.json          Klasse, CWE, Severity, Ground Truth (Datei + Zeilenbereich)
├── before/            der Zustand vor dem PR
└── after/             der Zustand nach dem PR — hier steckt der Bug
```

Der Runner baut daraus ein Wegwerf-Git-Repo: `before/` als Basis-Commit, `after/` als
PR-Commit. Das Gate sieht also **exakt die Form, die es in echt sieht** — ein Diff gegen
einen Base-Ref, nicht eine isolierte Datei.

## Bewertung

| Ergebnis | Bedeutung |
|---|---|
| `TP` | Vuln-Fall erkannt, **an der richtigen Stelle** (Datei + Zeile ±5) |
| `FN` | Vuln-Fall übersehen |
| `BLOCKED_WRONG_REASON` | blockiert, aber nicht wegen des echten Bugs — zählt **nicht** als Treffer |
| `FP` | Negativkontrolle blockiert |
| `TN` | Negativkontrolle durchgelassen |

`BLOCKED_WRONG_REASON` existiert, weil ein Gate, das aus dem falschen Grund rot wird, keine
Erkennung ist, sondern Zufall. Ohne diese Kategorie sieht jede Pipeline besser aus, als sie
ist.

## Abdeckung

**Vuln-Fälle (10)**

| Klasse | Fälle |
|---|---|
| Stille Degradation (COLDCARD-Muster) | PRNG-Fallback, Entropie-Kürzung, übersprungene Verifikation |
| Krypto | Nonce-Wiederverwendung, timing-unsichere HMAC-Prüfung |
| Parser | Prototype Pollution, Path Traversal, unbegrenzte Rekursion |
| State | Check-then-Act auf einem Kontostand |
| Supply Chain | Workflow-Injection über den PR-Titel |

**Negativkontrollen (7)** — jede zielt auf eine konkrete Prüfung, die falsch anschlagen kann:

| Fall | Ködert |
|---|---|
| `ui-jitter-random` | `Math.random()` ohne Sicherheitsbezug |
| `legit-child-process` | `execFileSync` mit fester Argumentliste |
| `catch-with-rethrow` | `try/catch` um Krypto, das korrekt weiterwirft |
| `test-vector-key` | veröffentlichter BIP-32-Testvektor in einer Testdatei |
| `dependency-bump` | Manifest **und** Lockfile gemeinsam geändert |
| `rename-key-function` | Umbenennung, viele Zeilen mit `key` im Namen |
| `docs-mention-eval` | Doku, die `eval`, `child_process`, `curl \| sh` benennt |

Die Negativkontrollen sind der wichtigere Teil. Die Falsch-Positiv-Rate entscheidet, ob das
Gate benutzt oder durchgewunken wird — und kein öffentlicher Benchmark misst sie.

## Korpus erweitern

Neuen Ordner unter `corpus/vuln/` oder `corpus/benign/` anlegen, `meta.json` schreiben,
`before/` und `after/` füllen. Der Runner findet ihn automatisch.

Zwei Regeln:
- **Ground Truth exakt.** Datei und Zeilenbereich müssen den Defekt bezeichnen, nicht die
  Datei „irgendwo".
- **Jede Negativkontrolle zielt auf eine benannte Prüfung.** `targets_check` in `meta.json`
  ausfüllen — sonst weiß später niemand, warum der Fall existiert.

Der Korpus ist bewusst klein gehalten und selbst geschrieben: reproduzierbar, lizenzfrei und
mit exakt kontrollierter Ground Truth. Für belastbare Zahlen sollte er auf 20+ Vuln-Fälle
wachsen, idealerweise ergänzt um echte, historische Fixes aus euren eigenen Repos — die
treffen euer Bedrohungsmodell besser als jeder generische Korpus.

> Der Code unter `corpus/` ist **absichtlich verwundbar**. Er ist vom Linting ausgenommen und
> wird nie gebaut oder ausgeliefert.

## Probes (Stufe 4)

Fälle können eine `probe.mjs` mitbringen — ausführbaren Code, der den Defekt *vorführt*
statt ihn zu behaupten:

```bash
node security/prove/run-probes.mjs
node security/prove/run-probes.mjs --only nonce
```

```js
export const describes = 'kurze Beschreibung dessen, was vorgeführt wird';
export default async function probe({ dir, importFrom }) {
  const mod = await importFrom('src/channel.ts');
  return { present: true, evidence: 'was beobachtet wurde' };
}
```

Jeder Probe läuft in einem eigenen Kindprozess gegen eine **Kopie** des Falls — sie dürfen
abstürzen, den Stack sprengen und Zustand verändern, ohne den Runner oder den Korpus zu
beschädigen.

**Probe-Ergebnisse gehen nicht in die Detection Rate ein.** Ein Probe, der neben der Lösung
liegt, misst nichts über die Erkennungsleistung des Gates. Er validiert den Korpus: dass die
Ground Truth einen echten Defekt beschreibt.
