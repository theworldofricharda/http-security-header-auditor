# 00 — Overview

## What you're looking at

`secheader_audit.py` is one Python file. Point it at a URL, it makes one
HTTPS request, reads the response headers, and tells you which of seven
security-relevant headers are missing, weak, or correctly configured — then
converts that into a 0–100 score and an A–F grade.

Nothing here requires prior security experience. It does assume you can
read basic Python (functions, dictionaries, `if`/`for`) — if that's shaky,
work through a short Python primer first and come back; the code comments
explain *why* each design choice was made, not *what* `for` does.

## Prerequisites

- Python 3.11 or newer (`python --version` to check)
- `pip` (comes with Python)
- An internet connection when you actually run a scan (the test suite does
  not need one — see [03-IMPLEMENTATION.md](03-IMPLEMENTATION.md) for how
  that's possible)

## Get it running

```bash
git clone <this-repo>
cd http-security-header-auditor
pip install -e ".[dev]"
python secheader_audit.py https://example.com
```

You should see a colored table, a boxed grade panel, and (for `example.com`,
which ships no security headers at all) a full list of recommendations. If
your terminal doesn't render color or box-drawing characters well, the
output is still fully readable — it just loses the color.

## Run the tests

```bash
pytest -v
```

Eighteen tests should pass in well under a second. If they don't, `pytest -v`
will point at the exact assertion that failed — read the failing assertion's
message, not just its name, it's written to tell you what was expected.

## Common first-run problems

**"ModuleNotFoundError: No module named 'httpx'"**
The install step (`pip install -e ".[dev]"`) didn't run, or ran in a
different Python environment than the one you're now invoking. Check
`which python` / `where python` matches the one you installed into.

**The scanner hangs for a long time before failing**
Some networks block outbound HTTPS to unfamiliar hosts, or the target site
is simply slow. Pass `--timeout 5` to fail fast instead of waiting the
default 10 seconds, and try `https://example.com` first — it's small,
fast, and always available — to confirm the tool itself works before
blaming the target site.

**"Input error: '...' has no scheme"**
You passed `example.com` instead of `https://example.com`. This is
deliberate, not a bug — see the note in the main [README](../README.md#quick-start)
about why the scanner refuses to guess.

## Where to go next

Read [01-CONCEPTS.md](01-CONCEPTS.md) for what each header actually does and
which attack it stops — that context makes the rest of the code make sense
instead of feeling like an arbitrary checklist.
