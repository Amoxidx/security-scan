# Welches Setup findet wirklich Schwachstellen?

**Stand: 2026-08-08** · Recherche zu Harness, Modell, Test-Tools, Graphs und Hooks — und was
davon für unser PR-Gate taugt.

Die Kurzfassung vorweg: **Die belegte Wirksamkeit liegt nicht beim Modell, sondern bei der
Architektur.** Der Ansatz „starkes LLM liest Code und findet Bugs" ist der am schlechtesten
belegte im ganzen Feld. Die Systeme mit den besten gemessenen Ergebnissen benutzen LLMs
*schmal* — als Triage- und Übersetzungsschicht auf dem Output deterministischer Werkzeuge.

---

## 1. Die beste Evidenzquelle: DARPA AIxCC

Zwei Jahre Wettbewerb, sieben vollautomatische *Cyber Reasoning Systems* (CRS), gegen echte
Open-Source-Codebasen, mit einheitlichem Scoring für Finden **und** Beweisen **und** Patchen.
**Alle sieben Systeme sind unter OSI-Lizenz veröffentlicht.** Das ist die einzige rigorose,
nachvollziehbare Vergleichsmessung, die es zu diesem Problem gibt.

Der Sprung zwischen den beiden Runden ist die aussagekräftigste Zahl:

| | DEF CON 32 (2024) | DEF CON 33 (2025) |
|---|---|---|
| Synthetische Schwachstellen gefunden | 37 % | **86 %** |
| Gepatcht | 25 % | — |

### Die Sieger und ihre Bauweise

**1. Team Atlanta — ATLANTIS** ($4 Mio., Georgia Tech / KAIST / POSTECH / Samsung Research)
- **43 von 70 Schwachstellen (61 %)**, 31 korrekte Patches, darunter **4 echte 0-Days** in
  SQLite3 und Apache Commons Compress
- Kafka-basierte Microservices auf Kubernetes/Azure, Controller-Worker-Struktur
- **Ensemble-Philosophie:** mehrere unabhängige Bug-Finder-Module, die über *Seed-Sharing*
  zusammenarbeiten; acht Patch-Agents mit unterschiedlichen Reparaturstrategien
- `HarnessBuilder` erzeugt pro Ziel mehrere instrumentierte Builds: libFuzzer, LibAFL,
  AFL++, directed fuzzing, Coverage, Artefakt-Extraktion
- Kombiniert symbolische Ausführung, gerichtetes Fuzzing und statische Analyse — LLMs sind
  tief integriert, aber nicht der Sucher

**2. Trail of Bits — Buttercup** ($3 Mio.) — *für uns das interessantere System*
- **28 Schwachstellen über 20 CWEs, 90 % Genauigkeit, bei 181 USD pro Punkt**
- **Ausschließlich Nicht-Reasoning-Modelle**
- Explizite Designphilosophie: deterministische Workflows, die das Problem in klar
  definierte Teilaufgaben zerlegen — **LLMs nur dort, wo klassische Werkzeuge nicht
  weiterkommen**
- libFuzzer und Jazzer, angereichert mit LLM-generierten Testfällen; tree-sitter plus
  Code-Query-System für die statische Seite; Multi-Agent nur beim Patchen
- Open Source, refaktoriert und für Einzelnutzer lauffähig

**3. Theori** ($1,5 Mio.)

### Was daraus folgt

Buttercup erreichte mit **billigen Modellen und mehr Engineering** 90 % Genauigkeit zu
181 USD/Punkt. Das ist der stärkste verfügbare Beleg dafür, dass die Modellwahl zweitrangig
ist. Wer die Architektur falsch baut, holt das mit keinem Frontier-Modell auf.

---

## 2. Die harte Einschränkung: AIxCC lässt sich nicht 1:1 übertragen

AIxCC lief auf **C/C++ und Java mit Sanitizern**. Ein Crash unter AddressSanitizer ist ein
*Beweis* — maschinell, unbestechlich, ohne Diskussion. Genau dieses Signal trägt das ganze
System: Der Fuzzer erzeugt es, das LLM muss es nur noch einordnen und patchen.

**In JavaScript/TypeScript gibt es dieses Signal nicht.** Kein Speicherfehler, kein
Sanitizer-Abort, keine automatische Ground Truth. Deshalb ist der CRS-Ansatz für unseren
Stack nicht direkt verwendbar. Was in JS/TS die Rolle des Beweises übernehmen kann:

- **Taint-Analyse** (CodeQL) — belegt einen Pfad von Quelle zu Senke
- **Property-based Tests** (fast-check) — belegt eine verletzte Invariante
- **Differential Testing** — zwei Implementierungen, ein Input, unterschiedliches Ergebnis
- **Coverage-guided Fuzzing für Parser** (jazzer.js) — belegt eine unbehandelte Eingabe

Ohne eine dieser Stufen bleibt jedes Finding eine Behauptung.

---

## 3. Modelle: die Benchmarks sind ernüchternd

| Benchmark | Was gemessen wird | Bestes Ergebnis |
|---|---|---|
| **SecVulEval** | 25.440 C/C++-Funktionen, 5.867 CVEs, Statement-Level | **23,8 % F1** |
| **SEC-bench** | 200 verifizierte Instanzen, PoC-Generierung + Patch | **≤18 % PoC**, 34 % Patch |
| **SEC-bench Pro** | V8 / SpiderMonkey / Firefox / Linux, 344 Instanzen | beste Konfiguration **33/103** (V8) |
| **CVE-Bench** (AXE) | End-to-End-Exploit | 30 % |

SEC-bench Pro ist für uns besonders relevant, weil es auf **JavaScript-Engines** (V8,
SpiderMonkey) basiert — dort liegt die beste Konfiguration bei rund einem Drittel, und der
Open-Weight-Baseline (Kimi-K2.6) bei 12/103.

Zwei weitere Befunde aus der Literatur:

- **Agentische Frameworks schlagen einfaches Prompting deutlich — aber nur bei starken
  Modellen.** Bei schwächeren Backbones sind die Gewinne gering oder inkonsistent. Die
  Arbeitsteilung „billiges Modell scannt, starkes Modell triagiert" ist damit nicht nur
  eine Kostenentscheidung, sondern eine Qualitätsentscheidung.
- **Kein Benchmark berichtet Falsch-Positiv-Raten** — genau die Metrik, die über die
  Praxistauglichkeit entscheidet. Das ist die größte Lücke im Feld und der Grund, warum
  Benchmark-Ranglisten für unsere Frage nur begrenzt taugen.

**Empfehlung:** Modelldiversität und Rollentrennung schlagen Modellwahl. Ein starkes Modell
für Verify/Triage, ein billiges für Bulk-Scan. Genau das hatte auch das Bitcoin Red Team
(Kimi K3 scannt, andere Modelle dokumentieren).

---

## 4. Der größte belegte Hebel: LLM als Filter, nicht als Finder

Das ist der am besten belegte Einsatz von LLMs in diesem Feld, und er ist deutlich stärker
belegt als LLM-als-Sucher:

| Studie | Ausgangslage | Ergebnis |
|---|---|---|
| Vergleichsstudie LLM-FP-Filter | CodeQL-Alerts | **93,3 %** der Falsch-Positiven korrekt erkannt |
| dieselbe, OWASP Benchmark | FP-Rate > 92 % | auf **6 %** gesenkt |
| QASecClaw (Multi-Agent) | 560 Falsch-Positive | auf **64** (−88,6 %) |
| SAST-Genius / Semgrep-Triage | 225 Falsch-Positive | auf **20** (~11× Signal-Rausch-Verhältnis), −91 % Triage-Zeit |

Restfehler konzentrieren sich auf schwierige CWE-Familien — Kryptografie und Policy.

**Konsequenz für unsere Architektur:** Wir haben aktuell *LLM sucht → LLM verifiziert*. Die
Evidenz spricht für *Tools suchen → LLM filtert → LLM verifiziert*. Das ist keine kleine
Umstellung, sondern eine Umkehrung der Suchrichtung.

---

## 5. Test-Tools für JS/TS

Kein Werkzeug deckt alles ab; Standardpraxis ist **Semgrep plus ein tieferes Tool**.

| Ebene | Werkzeug | Warum |
|---|---|---|
| Sofort, IDE + pre-commit | `eslint-plugin-security`, `eslint-plugin-no-unsanitized` | Null Latenz, erste Verteidigungslinie |
| Breit, schnell | **Semgrep** | Open Source, eigene Regeln schreibbar, sekundenschnell |
| Tief, interprozedural | **CodeQL** | Beste Taint-Analyse für JS/TS, gratis für öffentliche Repos, läuft als GitHub Action |
| Node-spezifisch | NodeJSScan | Express/Hapi-Muster, die generische Tools verfehlen |
| Abhängigkeiten | **OSV-Scanner** (Google OSV.dev) oder Trivy | Lockfile-genau; Trivy deckt zusätzlich Container/IaC/Secrets ab |
| Supply Chain | Socket, Snyk | Verhaltensanalyse neuer Paketversionen |
| Parser-Härtung | `jazzer.js`, `fast-check` | Erzeugt den Beweis, den JS sonst nicht hat |

JS ist wegen dynamischer Typisierung und Callback-Stil für Datenflussanalyse schwerer als
typisierte Sprachen — der Grund, warum Layering hier nicht optional ist.

---

## 6. Graphs: das Kontextproblem lösen

Das eigentliche Problem beim LLM-Review großer Codebasen ist nicht die Modellqualität,
sondern der Kontext: Token-Limits verhindern das Laden ganzer Repos, Embeddings erfassen
keine interprozeduralen Datenflüsse, und Snippet-basiertes Arbeiten übersieht genau die Bugs,
die sich über mehrere Funktionen und Dateien erstrecken.

**Code Property Graphs (CPG)** sind die belegte Antwort. Ein CPG vereint AST,
Control-Flow-Graph und Program-Dependence-Graph in einer Struktur.

- **LLMxCPG** (USENIX Security '25): CPG-basierte Slice-Konstruktion über Joerns
  `reachableByFlows` reduziert die Codemenge um **67,8–90,9 %** und erhält dabei den
  schwachstellenrelevanten Kontext — Schleifen, Deklarationen, Initialisierungen.
- **Codebadger** (2026): Open-Source-**MCP-Server**, der Joerns CPG-Engine an LLMs anbindet
  — Program Slicing, Taint Tracking, Datenflussanalyse, semantische Navigation. Damit kann
  ein Agent gezielt durch eine große Codebasis navigieren, statt Dateien vollständig zu
  lesen.

**Für uns:** Ein CPG- oder CodeQL-basierter Retrieval-Layer ist der Weg von „Review des
Diffs" zu „Review des Diffs *und* aller Aufrufer, die ihn erreichen". Ohne das findet unser
Gate strukturell nur lokale Bugs.

---

## 7. Hooks: drei Ebenen, nicht eine

| Ebene | Wann | Werkzeug | Laufzeit |
|---|---|---|---|
| Agent-Hook | während des Schreibens | Claude Code `PreToolUse` | ms |
| Commit-Hook | vor dem Commit | pre-commit / husky | Sekunden |
| CI-Gate | vor dem Merge | GitHub Actions Required Check | Minuten |

**`PreToolUse` ist der einzige Hook, der blockieren kann.** Claude Code bietet 21+
Lifecycle-Events und vier Handler-Typen: `command` (Shell), `prompt` (einmaliger
LLM-Aufruf), `agent` (Subagent mit Tool-Zugriff) und HTTP.

Das in der Praxis bewährte Muster: ein `PreToolUse`-Hook auf `git commit`, der den Commit
blockiert, bis ein **adversarialer Subagent** das Working-Tree-Diff geprüft und ein
`Verdict: CLEAN`-Artefakt erzeugt hat, das **an genau dieses Diff gebunden** ist. Der Gate
ist mechanisch — der Agent kann nicht committen —, aber der Prompt muss gegen „Review-Theater"
kalibriert sein: ein konkreter Defekt mit `file:line`, nicht „könnte sauberer sein".

Semgrep als `PreToolUse`-Hook fängt eine feste Liste von Klassen ab — Command Injection,
XSS, unsichere Deserialisierung, GitHub-Actions-Workflow-Injection, `eval`/`new Function` —
**bevor** die Edit-Operation abgeschlossen ist.

---

## 8. Fertige Systeme, falls man nicht selbst bauen will

| System | Status | Einordnung |
|---|---|---|
| **Buttercup** (Trail of Bits) | Open Source, lauffähig | Beste Referenzarchitektur, dokumentierte Kosten |
| **ATLANTIS** (Team Atlanta) | Open Source | Maximale Abdeckung, aber k8s/Kafka/Azure — schwerer Betrieb |
| **Codex Security** (ehem. Aardvark, OpenAI) | Research Preview seit 03/2026 | In Codex integriert, ChatGPT Enterprise/Business/Edu |
| **CodeMender** (Google DeepMind) | begrenzt | Findet *und* patcht, validiert Patches; bis 4,5 Mio. Zeilen |

---

## 9. Empfehlung für unser Setup

Die aktuelle Harness (`security/redteam/`) ist als *LLM-sucht*-Pipeline gebaut. Die Evidenz
sagt: das ist die schwächste Variante. Konkreter Umbau, in Reihenfolge des Nutzens:

1. **Suchrichtung umkehren.** Semgrep + CodeQL + OSV-Scanner erzeugen die Kandidaten; die
   LLM-Stufe wird zum Triage-Filter auf deren Output. Das ist der Schritt mit dem
   belegtesten Nutzen (FP-Rate 92 % → 6 %) und dem geringsten Aufwand — CodeQL läuft für
   dieses Repo kostenlos als Action.
2. **Unsere Lens-Suche als *zweiten* Kanal behalten, nicht als ersten.** Sie deckt genau die
   Klasse ab, für die es keine SAST-Regel gibt: stille Degradation einer Sicherheitsgarantie
   — der COLDCARD-Fall. Kein Semgrep-Pattern findet „Fallback auf schwächeren PRNG".
3. **Beweisstufe nachrüsten.** Für JS/TS: `fast-check`-Property-Tests für Parser und
   Wert-Arithmetik. Ohne Beweisstufe bleibt es bei „Kandidaten", und die Zahlen des Bitcoin
   Red Teams (21,4 % reproduziert) zeigen, wohin das führt.
4. **Graph-Retrieval ergänzen.** CodeQL-Datenbank oder Joern/Codebadger als MCP-Server,
   damit die LLM-Stufe die Aufrufer des Diffs sieht statt nur das Diff.
5. **Modellrollen trennen.** Billig scannen, stark triagieren. Buttercups 90 % bei
   181 USD/Punkt mit Nicht-Reasoning-Modellen ist der Beleg, dass das reicht.
6. **Erst dann messen** — Korpus bekannter Bugs, Detection Rate *und* Falsch-Positiv-Rate.
   Vorher lässt sich über „zuverlässig" nichts sagen.

Realistische Erwartung: Ein solches Setup liefert **belastbar gefilterte Kandidaten**, keine
zuverlässige Vollabdeckung. Das beste gemessene Gesamtsystem der Welt fand 61 % der
Schwachstellen in einem Wettbewerb mit maschineller Ground Truth. Wer mehr verspricht,
misst nicht.

---

## Quellen

**AIxCC**
- [DARPA — AI Cyber Challenge Results](https://www.darpa.mil/news/2025/aixcc-results)
- [AIxCC — Final Competition Winners](https://aicyberchallenge.com/finals-winners-announcement/)
- [SoK: DARPA's AI Cyber Challenge — Competition Design, Architectures, and Lessons Learned](https://arxiv.org/html/2602.07666v2)
- [OpenSSF — Impact and Legacy of AIxCC](https://openssf.org/blog/2026/05/12/hack-to-the-future-the-impact-and-legacy-of-the-darpa-aixcc-challenge/)
- [Trail of Bits — Buttercup wins 2nd place](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/) · [Buttercup Projektseite](https://trailofbits.com/buttercup/)
- [Team Atlanta — ATLANTIS](https://team-atlanta.github.io/blog/post-afc/) · [ATLANTIS Paper](https://arxiv.org/pdf/2509.14589)

**Benchmarks**
- [SEC-bench Pro](https://sec-bench.github.io/) · [Paper](https://arxiv.org/abs/2605.26548) · [Repo](https://github.com/SEC-bench/SEC-bench)
- [Are Frontier LLMs Ready for Cybersecurity? Dual-Mode Vulnerability Benchmarks](https://arxiv.org/pdf/2605.23243)
- [Seclens — Role-specific Evaluation of LLMs for Vulnerability Detection](https://arxiv.org/pdf/2604.01637)

**Falsch-Positiv-Triage**
- [Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering](https://arxiv.org/abs/2601.22952)
- [QASecClaw — Multi-Agent LLM for False Positive Reduction in SAST](https://arxiv.org/html/2605.01885v1)
- [LLM-Driven SAST-Genius](https://arxiv.org/pdf/2509.15433)

**Graphs**
- [LLMxCPG (USENIX Security '25)](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays) · [Paper](https://arxiv.org/pdf/2507.16585)
- [Bridging Code Property Graphs and Language Models for Program Analysis (2026)](https://dl.acm.org/doi/10.1145/3786165.3788441)
- [Joern](https://joern.io/impact/)

**Tools & Hooks**
- [Best SAST Tools for JavaScript & TypeScript (2026)](https://appsecsanta.com/sast-tools/sast-tools-for-javascript)
- [Claude Code Hooks — Production Patterns](https://www.pixelmojo.io/blogs/claude-code-hooks-production-quality-ci-cd-patterns)
- [The Pre-Commit Review Gate](https://imti.co/pre-commit-review-gate/)
- [Checkmarx — CodeMender, Aardvark and the Rise of Agentic AppSec](https://checkmarx.com/blog/codemender-aardvark-and-the-rise-of-agentic-appsec/)
- [OpenAI — Introducing Aardvark](https://openai.com/index/introducing-aardvark/)
