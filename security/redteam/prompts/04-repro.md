# Stage 4 — Reproduce: build a proof that runs

Prose is not proof. Produce a script that executes inside a checkout of this repository and
**exits 0 when the bug is present, non-zero when it is not**.

```
FINDING: {{FINDING}}
REPO:    {{REPO_CONTEXT}}
```

This stage is the reason the pipeline is trustworthy. In the Bitcoin Red Team's own sprint,
4,962 findings reduced to 21.4% reproduced. Everything that does not survive this stage is
an opinion.

## Requirements

- Self-contained. Use only what the repository already installs, or the standard library.
  If you need a dependency the repo does not have, the finding is not reproducible here —
  say so.
- Deterministic. No reliance on timing, network, or wall-clock unless the bug *is* a timing
  bug, in which case run enough iterations to make the signal unambiguous and state the
  statistical threshold you are using.
- Assertive. The script must *test the claim*, not merely print state. Assert the property
  that should hold, and let it fail.
- Non-destructive. Read-only against the repo. No network calls to third parties. No writes
  outside a temp directory.
- Fast. Under 60 seconds.

## If you cannot reproduce it

Say so. `reproducible: false` with an honest `blocker` is a correct and valuable answer.
Do not write a script that asserts something trivially true in order to return a green
result — a fabricated proof is worse than no proof, because it launders an unverified claim
into a confirmed one.

## Output

```json
{
  "reproducible": true,
  "language": "bash|python|node",
  "script": "<the complete script, ready to write to a file and execute>",
  "run_command": "<exact command, relative to repo root>",
  "expected_output": "<what appears when the bug is present>",
  "blocker": "<only when reproducible is false: what stopped you>"
}
```
