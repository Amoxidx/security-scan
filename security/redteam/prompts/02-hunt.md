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

**`access-control`** — For every operation that acts on a resource or performs a privileged
action, find the authorization check that must gate it and ask whether it actually governs
*this* operation on *this* object. Trace from the entry to the sink and name the missing or
misplaced gate. Is the owner/permission check present on the path that still performs the
action, or was it removed (a comment that it “moved to the router / gateway / caller” is not
evidence)? Is the check applied to the object being acted on, or to a different one the
caller legitimately owns? Is an async check (`isAdmin`, `hasAccess`, `assertOwner`)
**awaited** before its boolean is used, or is the Promise itself treated as truthy? Can a
replay/nonce/idempotency guard be bypassed because the token is checked but never consumed?
Can a request reach an internal target because an allowlist runs on the raw input string
instead of the parsed URL/host? The bug is the gap between the check and what it is supposed
to protect. Do not report a check that still gates the object being acted on (even if logging
around it changed), and do not report an unawaited call whose return value is not used as a
gate (fire-and-forget audit or metrics is not authorization).

**`business-logic`** — Domain invariants the type checker will not enforce: money, quantities,
credits, and ordered workflows. Trace every signed amount, price, quantity, discount, and
limit from the entry to the mutation. Report in the JSON schema only; do not ask follow-up
questions. (1) Sign/range of an amount: if `transfer` / `withdraw` still does
`balances[from] -= amount` / `balances[to] += amount` (or equivalent) and the `amount > 0`
reject is gone from **that function**, that is the finding — a negative amount inverts the
flow (sender credited, recipient debited). Do not wait for a caller in the hunk; the entry
is the function. (2) Overflow of a total: is `price * quantity` (or any money arithmetic)
narrowed to a 32-bit lane (`| 0`, `>>> 0`, `Math.imul`, packed int) or otherwise wrapped so
a huge quantity yields a tiny invoice? (3) Reusable credit: is a coupon/voucher/gift-code
checked for validity but never marked consumed, so the same code applies twice? Follow the
helper — `used.add` in `claim()` still counts. (4) Skipped mandatory step: for every path
that can reach `fulfillOrder` / ship / credit-out, is `capturePayment` (or the equivalent
settlement) actually invoked, or does a special case (`source === 'internal'`, gift, prepaid,
admin) jump the step? (5) Missing upper bound: if a `dailyLimit` / `maxAmount` / `maxQty`
field or config exists, is it still compared on the path that mutates, or was the comparison
removed (a comment that it “moved to the product layer / gateway / caller” is not evidence)?
Do not report a refactor that still rejects `amount <= 0` on the entry (`transfer`) **and**
whose `debit`/`credit` helpers re-check sign and coverage (`bal < amount` on a
`balances[from] ?? 0` read, credit via `balances[to] ?? 0`) — those helpers are internals of
a still-safe transfer, not a new unguarded mint, even without `private`/`#`. Missing-key
reads that use `?? 0` are not NaN corruption. Do not report a total that range-checks or uses BigInt/wide arithmetic before
any narrowing, a coupon whose consume still runs on the apply path and that still rejects
`off <= 0` and `off > order.total`, a workflow that still captures payment on every path
that can fulfill, or a limit that is still compared before the debit. Do not report authorization (wrong object, missing owner) or TOCTOU/races — those
are other lenses. An unused `used` set or leftover `dailyLimit` field is a clue the check
was removed, not that it still holds.

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
