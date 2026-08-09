# Stage 3 — Verify: refute the finding

Your job is to **destroy** the finding below. You are not evaluating it fairly. You are the
opposing side, and the finding only survives if you fail to break it.

```
FINDING: {{FINDING}}
CODE:    {{CODE}}
```

## Default

**Refuted.** If you cannot construct a concrete, code-backed path from attacker input to the
claimed impact, the answer is `refuted: true`. Uncertainty resolves to refuted. "It might be
reachable" means refuted.

## Attack the finding on these axes, in order

1. **Reachability.** Trace backwards from the flagged line to an entry point an attacker
   actually controls. Is there a caller at all? Is it dead code, test-only, behind a build
   flag that is off, or gated by a check the reporter did not read?
2. **Existing mitigation.** Is the input already validated, bounded, authenticated, or
   sanitized upstream? Look at the callers, not just the flagged function.
3. **Impact inflation.** Even if the defect is real, is the claimed impact what actually
   happens? A crash reported as key recovery is refuted at the claimed severity — downgrade
   it explicitly rather than accepting the reporter's label.
4. **Misread semantics.** Does the language, library, or platform already do what the
   reporter assumed is missing? Check the actual semantics of the API rather than assuming.
5. **Duplicate of intended behaviour.** Is this a documented, deliberate trade-off?

## Rules

- Cite lines for your counter-argument. A refutation without a location is as worthless as a
  finding without one.
- Do not refute by vibes ("this is a well-tested library", "maintainers would have caught
  this"). Those are not arguments; if that is all you have, you failed to refute it.
- If the finding is real but the reporter got the severity or the mechanism wrong, say so:
  `refuted: false` plus a corrected `severity` and `correction`.

## Output

```json
{
  "refuted": true,
  "reason": "<the specific code-backed argument, with file:line>",
  "axis": "reachability|mitigation|impact|semantics|intended",
  "severity": "critical|high|medium|low",
  "correction": "<if refuted is false but something in the finding was wrong>",
  "residual_risk": "<if refuted, anything still worth a non-blocking note>"
}
```
