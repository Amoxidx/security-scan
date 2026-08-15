# Do/Don't-Verdikt — lohnt sich der Security-Scan?

**Stand: 2026-08-15.** Grundlage: [`setup-evaluation.md`](./setup-evaluation.md) (Architektur-
Recherche, DARPA AIxCC/Buttercup, unabhängig geprüfte Zitate), der neue Eintrag in
[`measurements.md`](./measurements.md) vom 2026-08-15 (erste echte KI-Messung + Auswertung von
217 realen Produktions-Scans), und vier in diesem Zug gefundene und behobene Infrastrukturdefekte
(Amoxidx/security-scan PR #21–#24).

## Verdikt

**DO — mit einer harten Auflage: die Verifikationsstufe muss zuerst repariert werden, bevor
weitere KI-Findings als Entscheidungsgrundlage zählen.**

Das statische Gate + die Scanner-Stufe (Semgrep/Gitleaks/OSV) tragen sich bereits selbst: sie
sind deterministisch, günstig (keine KI-Kosten), und liefern 87 % aller echten Blocks im realen
Korpus (34 von 39, s. u.). Die KI-Hunt-Stufe liefert ein reales, plausibles Zusatzsignal (5
Funde in 217 Läufen, inhaltlich nicht trivial), aber **jeder einzelne davon lief nie durch die
Verifikation, die den Kern der Architekturwette ausmacht** — nicht weil das Design falsch ist,
sondern weil ein einzelner externer CLI-Defekt (Kimi) die Hälfte der Lens-Diversität und ein
Drittel der Verify-Modelle lahmlegt, in 100 % der beobachteten Fälle.

## Wie belastbar ist das Verdikt

| Frage | Belegquelle | Stärke |
|---|---|---|
| Erreicht das System seine eigenen Zielwerte? | Eval-Korpus, echte KI (2026-08-15) | Stark — einmalig, sauber gemessen, aber n=17 |
| Wie verhält es sich auf echtem Code? | 217 reale Scans, 2 Tage, 17 Repos | Stark — größte verfügbare Stichprobe, aber Beobachtungszeitraum kurz |
| Ist die Architektur richtig gewählt? | DARPA AIxCC (unabhängig verifizierte Zitate) + eigene 217-Läufe-Verteilung | Stark für die Grundthese, schwach für Übertragbarkeit (AIxCC lief auf C/C++, nicht TS/JS) |
| Was kostet der Betrieb? | Reale `usage.json` aus 87 Läufen | Mittel — Abo-Kosten, keine Grenzkosten-Wahrheit |
| Funktioniert die lokale Ollama-Reproduktion? | 5 reale Lab-Läufe | Schwach als Stichprobe (n=5), aber 0/5 ist ein klares Signal in eine Richtung |

---

## 1. Phase D — Ressourcen und Kosten (reale Daten, kein Benchmark)

Aus 87 realen `usage.json`-Dateien (von 217 Läufen — die übrigen 130 hatten keinen einzigen
erfolgreichen KI-Aufruf, s. Phase C):

| Metrik | Wert |
|---|---|
| Erfolgreiche KI-Aufrufe gesamt | 36 |
| … davon `claude-cli` | 36 (100 %) |
| … davon `codex-cli` | 0 (in älteren Läufen „not on PATH", s. Phase C) |
| … davon `kimi-cli` | 0 (CLI-Defekt, s. Phase C) |
| Notional-Kosten gesamt (Opus-5-Äquivalent) | 42,50 USD |
| Ø Output-Tokens/Aufruf | 7.950 |
| p95 Wall-Clock (voller Eval-Lauf) | 143,3 s |
| Vollständiger Pipeline-Lauf mit Lab-Reproduktion (real) | ~288 s (01:10:09–01:15:06, `DFXswiss-api-pr4992`) |

**Die 42,50 USD sind keine Grenzkosten.** Jeder Aufruf trägt `"billed": false` — es ist
Abo-Nutzung (Claude-Subscription), die JK ohnehin für andere Arbeit bezahlt; der Betrag ist der
Marktpreis-Äquivalenzwert, den man zahlen würde, käme man ohne Abo. Reale Zusatzkosten durch den
Scan-Betrieb: **de facto 0 USD**, solange die Abo-Kapazität nicht ausgeschöpft wird (dazu liegen
keine Messwerte vor — nicht geprüft, ob 36 Aufrufe/2 Tage gegen ein Abo-Limit läuft).

**Ollama/lokale Reproduktion (die „Lab"-Stufe):** lief in den 217 realen Scans genau **5 Mal**
(nur wenn ein blockierender KI-Fund vorliegt) — und **reproduzierte in 0 von 5 Fällen** etwas
(`0 reproduced / 1 run` bzw. `/ 2 run` in jedem der fünf Reports). Bei n=5 ist das keine
belastbare Rate, aber es deckt sich mit der bereits vor dieser Messung dokumentierten Beobachtung
(„qwen3-coder-next konvergiert nicht") und mit externer Evidenz: ein TrustedSec-Benchmark zu
lokalen Modellen (aus der Phase-A-Recherche dieses Vorgangs) fand, dass lokale Modelle
Einzelschritt-Exploits brauchbar handhaben, aber bei mehrschrittiger agentischer Reproduktion
kollabieren — exakt das Muster, das hier real beobachtet wird. **Optimierungsempfehlung für die
Lab-Stufe: nicht das Modell tunen, sondern den Scope reduzieren** (z. B. nur bei „high/critical"
UND „state"-Lens auslösen, statt bei jedem blockierenden Fund) — bei 0 % realer Trefferquote ist
jede zusätzliche Ollama-Rechenzeit dort Verschwendung, nicht Investition.

## 2. Phase E — „Tools-first" vs. „LLM-first": was die eigenen Daten zeigen

Der Implementierungsplan (`implementation-plan.md`) und die Architektur-Recherche
(`setup-evaluation.md` §7) sagen bereits vor Projektstart: „tools find, LLM filters" ist die
best-belegte Bauweise (DARPA AIxCC: Buttercup 90 % Genauigkeit bei 181 USD/Punkt mit
Nicht-Reasoning-Modellen; die am schlechtesten belegte Bauweise ist „starkes LLM sucht selbst").
Diese Session hat keinen dedizierten Gegentest gebaut (per Nutzerentscheidung — Recherche statt
Benchmark), aber die 217 realen Scans sind ein ungeplantes, aber echtes Naturexperiment für genau
diese Frage:

| Layer | Beitrag zu den 39 echten Content-Blocks | Anteil |
|---|---|---|
| Statisches Gate + Scanner (deterministisch, „tools find") | 34 | 87 % |
| KI-Hunt (`blocking > 0`) | 5 | 13 % |
| … davon adversarial verifiziert | 0 | 0 % |

Das bestätigt die Architekturwahl in der Größenordnung, in der sie im Projekt bereits gebaut ist:
das deterministische Gate trägt die Hauptlast und tut das zuverlässig; die KI-Schicht liefert ein
echtes, aber kleines Zusatzsignal, dessen Wert aktuell **nicht realisiert** wird, weil die
Verifikationsstufe (der Teil, der laut Literatur die False-Positive-Rate senken soll) durch den
Kimi-Defekt faktisch abgeschaltet ist. Ein separater „reiner Tools-first"-Gegentest (KI-Schicht
komplett aus) würde aktuell fast dasselbe Ergebnis liefern wie die vollständige Pipeline — mit
dem Unterschied, dass die 5 echten KI-Funde (darunter der SSH-Bootstrap- und der
Payout-Race-Fund, beide plausibel und nicht trivial) verloren gingen. **Empfehlung: keine
Neuarchitektur — die bestehende Tools-first-mit-KI-Overlay-Bauweise ist richtig gewählt; die
Investition gehört in die Reparatur der Verify-Kette, nicht in ein neues Grundgerüst.**

## 3. Was in dieser Auswertung offen bleibt

- Der Kimi-CLI-Defekt (`unknown command 'kimi-k3'`) selbst ist **nicht behoben** — externer
  Blocker (inaktive Kimi-Mitgliedschaft, s. Memory). Bis er behoben ist, liefert die
  Verify-Stufe strukturell keine Verifikation, egal wie gut der Rest der Pipeline läuft.
- Codex-Erreichbarkeit nach dem PATH-Fix (PR #21) ist nur durch **einen** Live-Test bestätigt,
  nicht durch eine neue Vollmessung über mehrere reale PRs.
- Die 5 echten KI-Funde wurden inhaltlich plausibel eingeschätzt, aber **keiner wurde von einem
  Menschen bestätigt oder widerlegt** — die hier genannte „Fundqualität" ist meine Einschätzung,
  keine geprüfte Tatsache.
- Kein dedizierter Tools-first-Gegentest wurde gebaut (Nutzerentscheidung); die Phase-E-Aussage
  stützt sich auf einen Beobachtungs-, nicht auf einen kontrollierten Vergleich.
- 130 von 217 realen Läufen hatten null erfolgreiche KI-Aufrufe (PASS-Fälle mit sauberem
  statischem Gate lösen die Hunt-Stufe evtl. gar nicht aus, oder sie scheiterte still) — die
  genaue Ursache je Fall wurde nicht einzeln geprüft, nur die Kimi-Ursache für die
  blockierenden Fälle.
