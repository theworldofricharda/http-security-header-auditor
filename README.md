```
        .-""""""-.
      .'          '.
     /   SECHEADER   \
     |     AUDIT      |
      \              /
       '.          .'
         '-......-'
```

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?style=flat&logo=pytest&logoColor=white)](https://pytest.org)
[![HTTP Client](https://img.shields.io/badge/httpx-0.27+-1f5582?style=flat)](https://www.python-httpx.org/)
[![Tier](https://img.shields.io/badge/Tier-Foundations-00C9A7?style=flat&logo=bookstack&logoColor=white)](#)

> Send one HTTPS request, read what the server actually sent back, and grade its security-header posture A through F — the same weighted-rubric idea behind Mozilla Observatory, built from scratch to understand *why* each header matters, not just to check a box.

*This is the quick-start version — the security theory, the design decisions, and a full code walkthrough live in [`learn/`](#learn).*

**[Sample output & demo runs →](DEMO.md)**

## What It Does

- Sends one polite HTTPS request to the URL you give it and reads the response headers
- Grades seven security-relevant headers against a weighted rubric (high = 25 pts, medium = 12 pts, low = 6 pts)
- Catches headers that are present but broken — `Strict-Transport-Security: max-age=0` (actively disables HSTS), a `Content-Security-Policy` that still allows `unsafe-inline`, `X-Frame-Options: ALLOW-FROM` (deprecated, browsers ignore it) — and grades all three `weak`, never `ok`
- Separately flags **information disclosure** — a `Server` or `X-Powered-By` header that leaks an exact version number — and applies its own capped penalty, distinct from the header rubric
- Follows redirects and grades the final URL, the one a visitor's browser actually lands on
- Prints a colored table plus a grade panel plus a concrete fix for every non-`ok` finding, or emits `--json` for CI pipelines
- Returns exit codes that mean something: `0` for A/B, `1` for C/D, `2` for F or a request error

## The Headers It Grades

| Header | Severity | What it stops |
|---|---|---|
| `Strict-Transport-Security` | high | SSL-stripping downgrades to plain HTTP |
| `Content-Security-Policy` | high | XSS via injected `<script>`/`<style>` sources |
| `X-Content-Type-Options` | medium | MIME-sniffing a file into the wrong content type |
| `X-Frame-Options` | medium | Clickjacking via an invisible embedding iframe |
| `Cross-Origin-Opener-Policy` | medium | Cross-window/tab reference leaks and Spectre-class side channels |
| `Referrer-Policy` | low | Leaking the current URL (and any token in it) via outbound links |
| `Permissions-Policy` | low | Compromised third-party scripts abusing camera/mic/geolocation |

Plus a separate check for **information disclosure**: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and `X-Runtime` headers that reveal an exact software version, each worth a 5-point penalty (capped at 15).

## Quick Start

```bash
python -m venv .venv && . .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
python secheader_audit.py https://example.com
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as an optional command runner: `just test`, `just run -- https://example.com`, `just lint`. Everything also works with plain `python`/`pytest` if you'd rather not install it.

> [!IMPORTANT]
> Always include the `http://` or `https://` scheme. The tool refuses bare hostnames like `example.com` on purpose — guessing the scheme for you is exactly the ambiguity HSTS exists to close.

## Machine-Readable Output

```bash
python secheader_audit.py https://example.com --json
```

Emits the full report — score, grade, every finding, every disclosure — as JSON, so a CI pipeline can gate on `.grade` or `.score` without scraping table output.

## Exit Codes

| Grade | Exit code | Meaning |
|---|---|---|
| A, B | `0` | Green light |
| C, D | `1` | Worth a look, not necessarily a blocker |
| F or request error | `2` | Hard fail |

```bash
python secheader_audit.py https://my-deployed-site.com
if [ $? -gt 1 ]; then exit 1; fi   # fail CI only on F or a network error
```

## Tooling

```bash
just            # list available recipes
just test       # pytest — 18 tests, fully network-mocked, runs in <1s
just run -- <url>
just lint       # ruff
just format     # black
```

## Requirements

- Python 3.11+
- `httpx` and `rich` (installed automatically via `pip install -e .`)
- A live internet connection at *runtime* — the tool makes one real HTTPS request per audit. The test suite mocks the network with `httpx.MockTransport` and runs fully offline.

No compilers, no system libraries. One Python file plus its test suite.

## Learn

Step-by-step material covering the security theory, the design decisions, and a function-by-function code walkthrough.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | What this tool is, prerequisites, first run, common problems |
| [01 - Concepts](learn/01-CONCEPTS.md) | Each header explained with the real attack class it stops |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | The functional-core/imperative-shell split and why grading is a pure function |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Function-by-function walkthrough, plus how the test suite mocks the network |
| [04 - Challenges](learn/04-CHALLENGES.md) | Ways to extend the tool, from "add an eighth header" to "wrap it in a small API" |

## Real-World Context

This is a teaching-scale version of tools that do the same job at production scale:

- **[Mozilla Observatory](https://observatory.mozilla.org/)** — the reference implementation of this idea: same weighted-rubric approach, deeper CSP parsing, cookie and TLS-configuration checks.
- **[securityheaders.com](https://securityheaders.com)** — a simpler, hosted equivalent.

Once the logic in this repo makes sense, those tools stop being a black box.

## License

MIT — see [LICENSE](LICENSE).
