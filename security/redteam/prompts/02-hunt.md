# Stage 2 — Hunt: one lens, one pass

You are hunting for exploitable defects in the target below, through **one specific lens**.
Stay in your lens. Other agents cover the others; a finding outside your lens is noise that
costs the pipeline a verification slot.

```
LENS:    {{LENS}}
TARGET:  {{TARGET}}
CONTEXT: {{CONTEXT}}
```

## Lens definitions

**`entropy`** — Trace every source of randomness to its origin. For each: is it a CSPRNG?
Is there a fallback if it is unavailable, and is that fallback weaker? Is the output
truncated, reduced modulo something, re-seeded from a device-unique or time-derived value,
or cached? Is a nonce ever reusable across two signatures? Follow the *unavailable* branch
specifically — that is where the guarantee gets lowered without an error.

**`parser`** — Take every input that crosses a trust boundary and ask what a malicious
producer writes there. Length fields that drive allocation or indexing. Recursion without a
depth bound. Integer width assumptions. Encoding round-trips that are not injective. Fields
parsed before they are authenticated.

**`state`** — Look for transitions that can run twice, out of order, concurrently, or that
leave a partial state on failure. Check every early `return` in a mutating function for what
it leaves behind. Check whether a check and the use of what it checked can be separated.

**`fallback`** — Find every place the code degrades instead of failing. Default values
substituted for missing config. Exceptions swallowed around a security operation.
Verification skipped when a key or a network is unavailable. Retry loops that drop a
constraint on the last attempt. For each: does anything observable change when the
degradation happens? If not, that is the finding.

**`supply-chain`** — Install/postinstall hooks. Dependencies resolved at build time without
a pin or an integrity hash. Build steps fetching remote code. CI configuration granting write
scope or exposing secrets to code paths reachable from an untrusted contributor.

## Rules

- Read the actual code. Do not reason from the file name or from what the function
  *probably* does.
- One finding per distinct root cause. Do not split one bug across three findings to inflate
  the count, and do not merge two unrelated bugs to look concise.
- If the lens genuinely yields nothing on this target, return an empty array. An empty
  result is a valid and useful outcome. Do not manufacture a finding to have something to
  report.

## Output

```json
{
  "findings": [
    {
      "title": "<one line, specific: what breaks, not what is 'unsafe'>",
      "file": "path/to/file",
      "line": 123,
      "lens": "{{LENS}}",
      "severity": "critical|high|medium|low",
      "root_cause": "<the defect itself, one or two sentences>",
      "attacker_model": "<who controls what input, and how they reach this code>",
      "attack_path": ["step 1", "step 2", "step 3"],
      "impact": "<what the attacker holds afterwards: funds, keys, plaintext, DoS, ...>",
      "guarantee_broken": "<the security property that stops holding>",
      "confidence": "high|medium|low",
      "how_to_disprove": "<what observation would show this finding is wrong>"
    }
  ]
}
```

`how_to_disprove` is mandatory. If you cannot state what would falsify your finding, you do
not understand it well enough to report it.
