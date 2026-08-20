# Stage 1 — Recon: find the load-bearing code

You are mapping a codebase to decide where expensive review time is worth spending. You are
**not** looking for bugs yet. Do not report bugs in this stage.

The question you are answering for every candidate file is not "is this code correct" but:

> **If this file quietly lied, what would break, and who would lose what?**

## Procedure

1. Identify the trust boundaries: where does data or control cross from untrusted to
   trusted? (network, user input, file formats, IPC, external processes, dependencies)
2. Identify the security-critical primitives: anything touching randomness, keys, seeds,
   signatures, nonces, authentication, authorization, balance or amount arithmetic,
   serialization of value-bearing structures.
3. Identify the fallback and error paths around those primitives. A `try/except` or an
   `if not available:` branch around a security primitive is a first-class target, not an
   edge case.
4. Rank by blast radius, not by complexity. Twenty lines that pick an entropy source
   outrank two thousand lines of UI.

## Output

```json
{
  "repo_summary": "<3 sentences: what this code does and what it protects>",
  "trust_boundaries": [
    {"description": "...", "entry_points": ["file:line"]}
  ],
  "targets": [
    {
      "file": "path/to/file",
      "lines": "120-180",
      "why": "<what security guarantee this code carries>",
      "blast_radius": "critical|high|medium|low",
      "worst_case": "<what an attacker gains if this misbehaves>",
      "suggested_lenses": ["entropy", "parser", "state", "fallback", "supply-chain", "access-control"]
    }
  ]
}
```

Return at most 40 targets. Fewer, better-justified targets beat a long list.
