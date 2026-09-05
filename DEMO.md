# Demo

Real output from real runs — nothing below is fabricated or hand-edited except
for stripping terminal color codes so it renders in plain Markdown.

## `github.com` — a mostly-hardened site with one real gap

```
$ python secheader_audit.py https://github.com

                        https://github.com  (HTTP 200)
┌────────────────────────────┬─────────┬──────────┬───────────────────────────┐
│ Header                     │ Status  │ Severity │ Note                      │
├────────────────────────────┼─────────┼──────────┼───────────────────────────┤
│ Strict-Transport-Security  │ ok      │ high     │ present and correctly     │
│                            │         │          │ configured                │
│ Content-Security-Policy    │ weak    │ high     │ present but contains      │
│                            │         │          │ `unsafe-inline`, which    │
│                            │         │          │ undermines the header's   │
│                            │         │          │ purpose                   │
│ X-Content-Type-Options     │ ok      │ medium   │ present and correctly     │
│                            │         │          │ configured                │
│ X-Frame-Options            │ ok      │ medium   │ present and correctly     │
│                            │         │          │ configured                │
│ Cross-Origin-Opener-Policy │ missing │ medium   │ Cross-Origin-Opener-Policy│
│                            │         │          │ was not sent              │
│ Referrer-Policy            │ ok      │ low      │ present and correctly     │
│                            │         │          │ configured                │
│ Permissions-Policy         │ missing │ low      │ Permissions-Policy was    │
│                            │         │          │ not sent                  │
└────────────────────────────┴─────────┴──────────┴───────────────────────────┘
┌────────────────────────────────── Result ───────────────────────────────────┐
│ Grade: D                                                                    │
│ Score: 69 / 100  (rubric 69 − disclosure 0)                                 │
└─────────────────────────────────────────────────────────────────────────────┘

Recommendations:
  • Content-Security-Policy — Content-Security-Policy: default-src 'self'; script-src 'self'
  • Cross-Origin-Opener-Policy — Cross-Origin-Opener-Policy: same-origin
  • Permissions-Policy — Permissions-Policy: camera=(), microphone=(), geolocation=()

$ echo $?
1
```

This one is worth pausing on: GitHub is a well-resourced, security-conscious
company, and this scanner still catches a real, current gap — their CSP
allows `unsafe-inline`, which is a genuinely common trade-off (some legacy
inline widget needs it) but is exactly the kind of "technically present,
not actually doing its job" case a naive presence-only checker would miss
and mark `ok`. That's the entire reason `must_not_contain` exists.

## `example.com` — no security headers at all

```
$ python secheader_audit.py https://example.com

                        https://example.com  (HTTP 200)
┌────────────────────────────┬─────────┬──────────┬───────────────────────────┐
│ Header                     │ Status  │ Severity │ Note                      │
├────────────────────────────┼─────────┼──────────┼───────────────────────────┤
│ Strict-Transport-Security  │ missing │ high     │ Strict-Transport-Security │
│                            │         │          │ was not sent              │
│ Content-Security-Policy    │ missing │ high     │ Content-Security-Policy   │
│                            │         │          │ was not sent              │
│ X-Content-Type-Options     │ missing │ medium   │ X-Content-Type-Options    │
│                            │         │          │ was not sent              │
│ X-Frame-Options            │ missing │ medium   │ X-Frame-Options was not   │
│                            │         │          │ sent                      │
│ Cross-Origin-Opener-Policy │ missing │ medium   │ Cross-Origin-Opener-Policy│
│                            │         │          │ was not sent              │
│ Referrer-Policy            │ missing │ low      │ Referrer-Policy was not   │
│                            │         │          │ sent                      │
│ Permissions-Policy         │ missing │ low      │ Permissions-Policy was    │
│                            │         │          │ not sent                  │
└────────────────────────────┴─────────┴──────────┴───────────────────────────┘
┌────────────────────────────────── Result ───────────────────────────────────┐
│ Grade: F                                                                    │
│ Score: 0 / 100  (rubric 0 − disclosure 0)                                   │
└─────────────────────────────────────────────────────────────────────────────┘

Recommendations:
  • Strict-Transport-Security — Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  • Content-Security-Policy — Content-Security-Policy: default-src 'self'; script-src 'self'
  • X-Content-Type-Options — X-Content-Type-Options: nosniff
  • X-Frame-Options — X-Frame-Options: DENY
  • Cross-Origin-Opener-Policy — Cross-Origin-Opener-Policy: same-origin
  • Referrer-Policy — Referrer-Policy: strict-origin-when-cross-origin
  • Permissions-Policy — Permissions-Policy: camera=(), microphone=(), geolocation=()

$ echo $?
2
```

`example.com` is IANA's reserved documentation domain — it deliberately ships
a bare-minimum response, which makes it a reliable, always-available F-grade
test case.

## `--json` output, for CI

```
$ python secheader_audit.py https://example.com --json
{
  "requested_url": "https://example.com",
  "final_url": "https://example.com",
  "status_code": 200,
  "score": 0,
  "rubric_score": 0,
  "disclosure_penalty": 0,
  "grade": "F",
  "findings": [ ... one object per rule ... ],
  "disclosures": []
}
```

## Information disclosure, illustrated

No live site in this demo happened to leak a versioned `Server` header at
capture time, so here is the same code path exercised directly (this is
exactly what `test_versioned_server_header_is_a_disclosure` in the test
suite asserts):

```python
>>> from secheader_audit import find_disclosures
>>> find_disclosures({"Server": "Apache/2.4.41"})
[DisclosureFinding(header='Server', value='Apache/2.4.41')]
>>> find_disclosures({"Server": "nginx"})  # bare name, no version — not penalized
[]
```

If a scanned site's `Server` or `X-Powered-By` header includes a version
number, the CLI output gains an "Information disclosure" block right above
the grade panel, and the score drops by 5 points per leaked header (capped
at 15 total) — see the [Concepts](learn/01-CONCEPTS.md) module for why that's
graded separately from the seven-header rubric.
