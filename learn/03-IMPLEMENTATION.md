# 03 — Implementation Walkthrough

Read this alongside `secheader_audit.py` open in another window — it's
organized to match the file's actual top-to-bottom order.

## `Severity` / `Status` — `Literal` instead of `Enum`

```python
Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]
```

Both are small, closed sets of strings that will never need methods of
their own (an `Enum` shines when you want to attach behavior to each
member). A `Literal` gets the same "only these exact values are valid"
type-checking benefit from mypy with less ceremony — writing
`severity: Severity = "hihg"` (typo) is a type error the moment you save
the file, before you ever run the code.

## `HeaderRule` — the shape of one rubric entry

Two optional fields do the actual grading work:

- `must_match: str | None` — a regex the header's *value* must satisfy to
  count as `ok`. Used for HSTS (`max-age` must be a positive integer) and
  `X-Content-Type-Options` (must literally say `nosniff`).
- `must_not_contain: tuple[str, ...]` — substrings that, if found
  (case-insensitively) in the value, downgrade an otherwise-present header
  to `weak`. Used for CSP's `unsafe-inline`/`unsafe-eval` and
  `X-Frame-Options`'s deprecated `ALLOW-FROM`.

A rule can use neither (bare presence is enough — `Cross-Origin-Opener-Policy`,
`Referrer-Policy`, `Permissions-Policy` all work this way), either, or
conceptually both, though none of the seven built-in rules currently need
both at once.

## `evaluate_rule()` — the one function every grading decision runs through

```python
def evaluate_rule(rule: HeaderRule, headers: dict[str, str]) -> Finding:
```

Three steps, in order, and it returns as soon as one applies:

1. **Look up the header, case-insensitively.** HTTP header names are not
   case-sensitive per the HTTP spec — a server can send `strict-transport-security`
   in all lowercase and it means exactly the same thing as
   `Strict-Transport-Security`. `_find_header()` walks the dict comparing
   lowercased keys rather than assuming any particular casing.
2. **Not found → `missing`.** Nothing further to check.
3. **Found → check `must_match`, then `must_not_contain`.** If a
   `must_match` pattern is set and the value doesn't satisfy it, that's
   `weak`. Otherwise, if any `must_not_contain` substring appears, that's
   also `weak`. If the header cleared both checks (or had neither to
   clear), it's `ok`.

This function takes a plain `dict[str, str]`, not an `httpx.Response` —
that's what lets the test suite call it directly with hand-written
dictionaries and no network involved at all.

## `find_disclosures()` — same shape, different question

Walks `DISCLOSURE_HEADERS` (`Server`, `X-Powered-By`, etc.), and for each
one present, checks whether its value contains something that looks like a
version number (`_VERSION_PATTERN = re.compile(r"\d+\.\d+")` — one or more
digits, a literal dot, one or more digits). `Server: nginx` doesn't match
that pattern and is ignored; `Server: nginx/1.18.0` does, and becomes a
`DisclosureFinding`.

## `AuditReport` — properties, not stored numbers

```python
@property
def rubric_score(self) -> int: ...
@property
def disclosure_penalty(self) -> int: ...
@property
def score(self) -> int:
    return max(0, self.rubric_score - self.disclosure_penalty)
```

`rubric_score` sums `SEVERITY_POINTS` for every `ok` finding at full value
and every `weak` finding at half value, divides by the maximum possible
total, and converts to a 0–100 percentage. `disclosure_penalty` is
`len(disclosures) * 5`, capped at 15 via `min()`. `score` is the rubric
score minus the penalty, floored at zero with `max(0, ...)` so a chatty
server with a low rubric score can't be pushed into a negative number.

## `audit()` — the only function that touches the network

```python
def audit(url: str, *, timeout: float = 10.0) -> AuditReport:
```

Three things happen here, in order:

1. **Validate the scheme.** `if not url.startswith(("http://", "https://"))`
   raises `ValueError` immediately, before any network call — the CLI
   catches this and prints a clean message instead of a raw traceback.
2. **Make the request.** `httpx.get(..., follow_redirects=True, ...)` — the
   redirect-following matters because grading `http://example.com` when it
   immediately 301s to `https://example.com` would grade the wrong
   response; `response.url` after the call reflects wherever the browser
   would have actually ended up.
3. **Wire the pure functions together.** `dict(response.headers)` converts
   httpx's own `Headers` object into the plain dict every pure function
   above expects, then both `evaluate_rule()` (once per rule) and
   `find_disclosures()` run against it to build the `AuditReport`.

## How the test suite fakes a live HTTP response

```python
def _mock_client_response(headers: dict[str, str], status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, request=request)
    return httpx.Client(transport=httpx.MockTransport(handler))
```

`httpx.MockTransport` replaces the actual network transport layer inside an
`httpx.Client` with a plain Python function (`handler`) that inspects the
outgoing `request` and constructs whatever `Response` the test wants —
no socket is ever opened. `monkeypatch.setattr(httpx, "get", fake_get)`
then substitutes the module-level `httpx.get()` that `audit()` calls with a
`fake_get` that routes through that mocked client. The whole round trip —
building a request, running it through `audit()`, getting back an
`AuditReport` — happens entirely in memory, which is why all 18 tests run
in well under a second and never depend on which network you happen to be
on.

One real bug got caught this way during development: an earlier version of
`fake_get` declared a `headers=None` keyword parameter (to accept the
User-Agent header `audit()` passes) with the *same name* as the outer
variable holding the intended mock response headers — the parameter shadowed
the outer variable, so the mock silently returned an empty response. The
fix was renaming the outer variable to `response_headers`. It's left as a
comment in `test_secheader_audit.py` because it's a realistic mistake, not
a hypothetical one — a "did the test actually test what I think it tested"
double-check when a mocked test passes trivially is worth doing at any
level of experience.

## `render_report()` — turning data into a terminal report

Purely presentational: builds a `rich.Table` (one row per finding, colored
by status), prints a plain-HTTP warning if the final URL wasn't upgraded to
HTTPS, prints the disclosure block if any were found, and wraps the grade
in a color-coded `rich.Panel`. None of this function's logic feeds back
into `AuditReport` — it only reads from it, which is what keeps grading
testable independently of what the terminal output looks like.

## `main()` — the CLI shell

Parses arguments, calls `audit()`, and converts any `ValueError` or
`httpx.RequestError` into a clean printed message and exit code `2`
instead of letting a raw traceback reach the user. Otherwise it either
prints JSON (`--json`) or calls `render_report()`, then maps the final
grade to the exit code documented in the [README](../README.md#exit-codes).
