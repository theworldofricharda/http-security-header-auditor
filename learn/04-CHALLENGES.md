# 04 — Challenges

Twelve ways to extend this project, roughly ordered easiest to hardest.
Each one is a real, scoped exercise — not busywork — and several are
exactly the kind of gap between a foundations tool and a production one.

## 1. Add an eighth rubric header

Add `Cache-Control` as a `medium`-severity rule requiring `no-store` for
URLs that look like they serve sensitive data. Because `RULES` is just a
list and `evaluate_rule()` is generic, this is a one-entry change — do it
first to confirm you understand the data-driven design in
[02-ARCHITECTURE.md](02-ARCHITECTURE.md) before attempting anything harder.

## 2. Parse CSP directives properly instead of substring-matching

Right now, a CSP is only checked for the presence of `unsafe-inline` /
`unsafe-eval` anywhere in the string. Write a real parser that splits the
policy into directives (`default-src`, `script-src`, `frame-ancestors`,
...) and sources, and grade `script-src` and `default-src` separately —
a policy with a strict `script-src` but no `default-src` fallback behaves
very differently from one with neither.

## 3. Batch-scan a list of URLs

Add a `--file urls.txt` flag that reads one URL per line, audits each, and
prints a summary table (URL, grade, score) instead of one full report per
URL. This is also a natural place to introduce `asyncio` + `httpx.AsyncClient`
for concurrent requests instead of scanning one at a time.

## 4. Add a `--diff` mode

Store a previous scan's JSON output (`--json > baseline.json`), then add a
mode that re-scans and reports exactly what changed since the baseline —
"Content-Security-Policy went from missing to ok" is a genuinely useful
thing to show in a deploy pipeline.

## 5. Cookie security flags

Extend the tool to also inspect any `Set-Cookie` headers in the response
for the `Secure`, `HttpOnly`, and `SameSite` attributes — a different kind
of header (there can be several, and the interesting information is in
attributes on the value, not the value itself), which will stress-test
whether the current `HeaderRule` shape actually generalizes or needs a
sibling type.

## 6. TLS/certificate checks

Beyond headers: is the certificate expired or expiring soon? What TLS
versions does the server accept? This starts to overlap with what Mozilla
Observatory's deeper scan does, and requires stepping outside `httpx` into
something like Python's `ssl` module directly.

## 7. HTML report output

Add `--html report.html` that renders the same `AuditReport` data as a
static HTML page instead of (or alongside) the terminal table — good
practice at keeping the data model (`AuditReport`) decoupled from any one
rendering target, since you'll be adding a second renderer next to
`render_report()` without touching the grading logic at all.

## 8. A tiny web front end

Wrap `audit()` in a minimal FastAPI or Flask app with one endpoint:
`GET /scan?url=https://example.com` returning the same JSON `to_dict()`
already produces. This is most of the way to the "Real-World Context"
tools mentioned in the README, just without their UI polish.

## 9. Historical tracking

Persist every scan's JSON output (SQLite is enough) keyed by URL and
timestamp, and add a `--history <url>` flag that shows a site's grade over
time. Useful for demonstrating whether a site's security posture is
actually improving after you've filed the recommendations from a scan.

## 10. Rate-limit-aware batch mode

If you built the batch-scan mode in #3, add polite rate limiting (don't
hammer many URLs on the same host back-to-back) and honor `Retry-After` on
a 429 response — this is the difference between a script and a tool other
people can point at a list of real sites without getting blocked.

## 11. A GitHub Action

Package this as a reusable GitHub Action that runs on every push, scans a
site named in a repo secret, and fails the build on grade F — using the
exit-code contract that already exists in `main()`. This is genuinely
useful as a portfolio artifact: it demonstrates the tool solving a real CI
problem, not just running locally.

## 12. Full CSP report-only mode support

Real sites often deploy `Content-Security-Policy-Report-Only` alongside or
instead of the enforcing header, to test a policy without breaking
anything if it's wrong. Add a rule (or a variant flag on the existing one)
that recognizes and separately reports on this header — and decide, with
reasoning written down in your own README update, whether a report-only
policy should count toward the score at all.
