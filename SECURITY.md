# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

Fixes land on `master` and go into the next 1.0.x release.

## Reporting a Vulnerability

Please don't open a public issue for a security bug. Report it privately through GitHub instead:

**[Report a vulnerability](https://github.com/theworldofricharda/http-security-header-auditor/security/advisories/new)**

Only the maintainer can see the report. It helps to include:

- the version (`pip show secheader-audit`) and your Python version
- the URL or the exact response headers that trigger the problem
- the output you got and the output you expected
- a proof of concept, if you have one

## What Counts

This is a tool people use to decide whether a site's headers are safe, so wrong answers matter as much as crashes. In scope:

- **False assurance:** a missing or broken header graded `ok`, or a site getting an A or B it shouldn't
- **Output injection:** a crafted header value that injects terminal escape sequences or `rich` markup into the report, or breaks the `--json` output
- **Crashes or hangs** caused by a malicious server's response
- anything that makes the tool send more than the one request (plus redirects) it's meant to

Out of scope:

- weaknesses in a site you scanned with the tool. Report those to that site's owner.
- bugs in `httpx` or `rich` themselves. Report those upstream, though I'd still like to hear if they affect this tool.

## What to Expect

This project has one maintainer, so these are targets, not guarantees:

- **Acknowledgement** within 7 days
- **An assessment** (confirmed or not, and how serious) within 14 days
- **A fix and a published advisory** for confirmed issues as soon as one is ready. You'll be credited unless you'd rather not be.
