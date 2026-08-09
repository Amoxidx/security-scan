# Stage 2 — Triage: is this scanner finding real?

A static analyser flagged the code below. Static analysis over-reports by construction: it
sees patterns, not reachability. Your job is to decide whether this particular finding
describes a real problem **in this codebase**.

FINDING:
{{FINDING}}

CODE:
{{CODE}}

CONTEXT:
{{CONTEXT}}

## The three verdicts

**`true_positive`** — The pattern is real, the code is reachable from something an attacker
influences, and the consequence the rule describes actually follows here.

**`false_positive`** — You can name the specific reason it does not apply. Not "seems fine",
not "well-tested code" — a reason anchored to a line you read. Valid reasons include: the
input is validated upstream, the flagged call is unreachable or test-only, the language or
library already provides the missing property, the value is a published constant rather than
a secret, the flagged construct is the safe variant of the pattern.

**`needs_human`** — Anything else. You lack the context, the reachability is unclear, or the
severity depends on a business rule you cannot see.

## Default

**`needs_human`.** A finding you dismiss disappears; nobody reads it again. A finding you
escalate costs someone two minutes. Those errors are not symmetrical, so when the evidence
does not decide, escalate.

Never answer `false_positive` because a finding is *low severity* or *unlikely to be
exploited*. Those are triage-priority questions, not truth questions. Downgrade the severity
instead and keep the verdict honest. Downgrading severity changes urgency and priority only;
it does not hide the finding from the gate. A `needs_human` or `true_positive` verdict still
surfaces the finding regardless of the severity label you assign.

## Specific traps

- **The safe variant of a dangerous pattern.** `execFileSync(cmd, [args])` without a shell,
  `timingSafeEqual`, a path run through `basename` and then containment-checked. If the code
  is the *fixed* form of the flagged pattern, that is a `false_positive` — say which form.
- **Test fixtures and published vectors.** Key material in a test file that matches a
  published specification vector is not a leaked secret.
- **Non-security use of a security-flavoured primitive.** `Math.random()` for an animation
  delay is correct. `Math.random()` for anything a user must not predict is not.
- **Deleted or moved code.** A finding on a line the diff removed is not a finding.

## Output

```json
{
  "verdict": "true_positive|false_positive|needs_human",
  "reason": "<anchored to file:line — what you read that decided it>",
  "severity": "critical|high|medium|low",
  "reachable_from": "<the entry point, when true_positive; null otherwise>",
  "what_would_change_my_mind": "<the observation that would flip this verdict>"
}
```
