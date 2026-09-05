# 02 — Architecture

## The shape of the file, top to bottom

```
RULES (data)  →  evaluate_rule() (pure)  →  Finding (data)
                                                   │
DISCLOSURE_HEADERS (data) → find_disclosures() (pure) → DisclosureFinding (data)
                                                   │
                                                   ▼
                          audit() (impure — does I/O) → AuditReport (data)
                                                   │
                                                   ▼
                          render_report() (impure — prints) / to_dict() (pure)
```

Everything above the `audit()` function is a **pure function**: given the
same input dict of headers, it always returns the same output, with no
network access, no printing, no shared mutable state. Everything below the
line either does network I/O (`audit()`) or terminal output
(`render_report()`).

## Why split it this way — "functional core, imperative shell"

This is a named pattern (sometimes shortened FCIS): push all your decision
logic into small pure functions, and shrink the parts of your program that
touch the outside world (network, disk, terminal) down to the thinnest
possible layer around that core.

The practical payoff is in the test suite: `evaluate_rule()` and
`find_disclosures()` are tested with plain Python dicts — no live server,
no mocked network, no `pytest` fixtures beyond the data itself. Only the
handful of tests that specifically exercise `audit()` need
`httpx.MockTransport` at all. If the grading logic instead lived inside a
function that also made the HTTP request, *every* test would need network
mocking, and a bug in HTTP handling could hide a bug in grading logic (or
vice versa) inside the same test failure.

## Dataclasses as value objects

`HeaderRule`, `Finding`, `DisclosureFinding`, and `AuditReport` are all
declared with `@dataclass(frozen=True, slots=True)`:

- **`frozen=True`** makes instances immutable after construction — you
  cannot accidentally mutate a `Finding` after the fact and have that
  silently change a report that was already handed to the renderer. This
  matches the project's broader habit of treating data as something you
  build once and pass around, not something you edit in place.
- **`slots=True`** tells Python not to give each instance a `__dict__` —
  it can only ever have the fields declared on the class. This catches a
  typo like `finding.satus` (missing `t`) at the moment it's accessed,
  instead of silently creating a new attribute that nothing reads.

## The rubric is data, not a chain of `if` statements

`RULES` is a plain list of `HeaderRule` objects. `evaluate_rule()` doesn't
know or care which specific header it's looking at — it just applies the
same three checks (present? matches `must_match`? contains anything in
`must_not_contain`?) to whatever rule it's handed. Adding an eighth header
to the rubric means adding one more `HeaderRule(...)` entry to the list —
zero changes to any function. See
[04-CHALLENGES.md](04-CHALLENGES.md) for a worked example of exactly that.

## Why the disclosure penalty is a separate code path

`find_disclosures()` and `DISCLOSURE_HEADERS` are deliberately not folded
into `RULES`. A `HeaderRule` describes "does this header have a *correct*
value" — but a disclosure header (`Server`, `X-Powered-By`) has no correct
value to check against; the finding is really "does this header exist at
all, with a version number in it." Trying to force that into the
`HeaderRule` shape (which expects `must_match`/`must_not_contain` against a
*desired* value) would mean bending the model to fit an unrelated kind of
check. Two small, single-purpose code paths stayed easier to read and test
than one code path handling two different questions.

## `score` and `grade` are computed properties, not stored fields

`AuditReport` stores `findings` and `disclosures` — the raw evidence — and
computes `rubric_score`, `disclosure_penalty`, `score`, and `grade` as
`@property` methods derived from that evidence every time they're read.
The alternative — computing the score once and storing it as a plain field
— would open a door for the stored number to drift out of sync with the
`findings` list if either were ever changed after construction (they can't
be here, since the dataclass is frozen, but the property approach makes
that guarantee obvious by construction rather than by convention).

## Next

[03-IMPLEMENTATION.md](03-IMPLEMENTATION.md) walks the actual functions in
file order, including exactly how the test suite fakes a live HTTP response
without a network connection.
