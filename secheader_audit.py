"""
secheader_audit.py — Richard Akinfadeyi, 2026

Audit a live URL's HTTP response headers and grade its security posture A-F.

WHY THIS EXISTS
----------------
A browser trusts whatever a server tells it, unless the server's response
headers say otherwise. A handful of headers control real attack surface:
whether the page can be framed by another site (clickjacking), whether a
downgrade to plain HTTP is possible (SSL stripping), whether the browser
will "helpfully" reinterpret a file's content type (MIME sniffing), and
what an injected <script> tag is actually allowed to do (XSS blast radius).
Most sites get some of these right and forget the rest. This tool sends one
HTTPS request, reads what came back, and turns "some of these right" into a
concrete score you can act on.

SCOPE, ON PURPOSE
------------------
This checks response headers only — it does not crawl the site, does not
attempt to trigger an actual XSS or clickjacking, and does not parse the
full grammar of a Content-Security-Policy (it looks for red-flag tokens
like `unsafe-inline`, not full policy correctness). That's a deliberate
foundations-tier boundary: understand what these seven headers do and how
a scanner reasons about them, then graduate to something like Mozilla
Observatory or securityheaders.com, which do the deeper version of this.

WHAT MAKES THIS SCANNER'S GRADING DIFFERENT FROM "IS THE HEADER PRESENT"
--------------------------------------------------------------------------
Two things this tool checks that a naive "is the header there" scan won't:

1. A header can be present and still be actively harmful. HSTS with
   `max-age=0` is not a missing header — it's a header telling browsers
   to STOP enforcing HTTPS. A CSP containing `unsafe-inline` still blocks
   *some* attacks but defeats the header's main job. Both are graded
   "weak", not "ok".

2. Information disclosure is graded separately from the seven core
   controls. A `Server: Apache/2.4.41` or `X-Powered-By: Express` header
   doesn't stop an attack by itself, but it hands a would-be attacker a
   version number to go look up known CVEs for — so it costs points as
   its own penalty line, distinct from the header rubric.

WHAT THIS FILE EXPOSES
------------------------
  HeaderRule           — one rubric entry (name, severity, matcher, advice)
  Finding              — the graded result of one rule against one response
  DisclosureFinding    — a leaked version-revealing header, penalized separately
  AuditReport          — the full result: findings, disclosures, score, grade
  evaluate_rule()       — pure function: one rule + headers -> one Finding
  find_disclosures()    — pure function: headers -> list[DisclosureFinding]
  audit()               — does the actual HTTP request, wires the above together
  main()                — CLI entry point, returns a shell exit code
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Literal

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# =============================================================================
# Small fixed vocabularies, expressed as Literal types rather than Enums —
# a Literal is enough for a closed set of strings and mypy still catches a
# typo like "hihg" at type-check time.
# =============================================================================

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]

# Point value awarded per severity tier when a rule is fully satisfied.
# Chosen so that missing every "high" header alone drags a site into the
# F range even if every other header is perfect.
SEVERITY_POINTS: dict[Severity, int] = {"high": 25, "medium": 12, "low": 6}

# Flat penalty subtracted from the final score per distinct information-
# disclosure header found, capped so a single chatty server can't sink an
# otherwise well-configured site below a fair score.
DISCLOSURE_PENALTY_PER_HEADER = 5
DISCLOSURE_PENALTY_CAP = 15


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """
    One entry in the grading rubric.

    `must_not_contain` and `must_match` are both optional and independent:
    a rule can require a value to match a pattern (e.g. HSTS's max-age),
    forbid a substring (e.g. CSP's `unsafe-inline`), both, or neither (in
    which case bare presence is enough to pass).
    """

    header: str
    severity: Severity
    why_it_matters: str
    fix: str
    must_match: str | None = None
    must_not_contain: tuple[str, ...] = ()


# The rubric is the single source of truth for what gets checked. Extending
# the scanner is: add a row here. evaluate_rule() below treats every row
# identically, so no branching logic needs to change.
RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        why_it_matters=(
            "Without it, a user's very first visit (and every visit after "
            "a cleared cache) can be silently downgraded to plain HTTP by "
            "anyone on the network path — the classic SSL-stripping attack."
        ),
        fix="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        # HSTS with max-age=0 actively tells the browser to forget HSTS —
        # so the value must contain a *positive* integer, not just digits.
        must_match=r"max-age\s*=\s*[1-9]\d*",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        why_it_matters=(
            "The strongest available control against injected-script "
            "attacks — it defines which script/style/frame sources the "
            "browser will honor at all."
        ),
        fix="Content-Security-Policy: default-src 'self'; script-src 'self'",
        # A CSP that allows unsafe-inline or unsafe-eval still blocks
        # cross-origin script loads, but it no longer blocks the single
        # most common XSS payload shape — so we grade it as weak, not ok.
        must_not_contain=("unsafe-inline", "unsafe-eval"),
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        why_it_matters=(
            "Stops the browser from guessing a file's type from its "
            "content and running it as something the server never "
            "intended (e.g. a user-uploaded .txt rendered as HTML)."
        ),
        fix="X-Content-Type-Options: nosniff",
        must_match="nosniff",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        why_it_matters=(
            "Blocks the page from being embedded in another site's "
            "invisible iframe — the mechanism behind clickjacking."
        ),
        fix="X-Frame-Options: DENY",
        # ALLOW-FROM is deprecated and unsupported by modern browsers —
        # a site relying on it believes it is protected when it is not.
        must_not_contain=("allow-from",),
    ),
    HeaderRule(
        header="Cross-Origin-Opener-Policy",
        severity="medium",
        why_it_matters=(
            "Isolates the page's browsing context from cross-origin "
            "popups/tabs it opens, closing the Spectre-style side-channel "
            "and reference-leak class of attacks between windows."
        ),
        fix="Cross-Origin-Opener-Policy: same-origin",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        why_it_matters=(
            "Without it, the full URL a user was just on — including any "
            "token or session id living in the query string — can leak "
            "to every site linked from that page via the Referer header."
        ),
        fix="Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        why_it_matters=(
            "Without it, a compromised third-party script embedded on the "
            "page inherits access to camera/microphone/geolocation APIs "
            "the page itself never uses."
        ),
        fix="Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
]

# Headers that exist purely to advertise server/framework software and
# version — useful to an operator, also useful to an attacker building a
# target-specific exploit shortlist. Graded as a separate penalty, not
# folded into the rubric above, because "leaks a version number" is a
# different kind of risk than "missing a browser-enforced control".
DISCLOSURE_HEADERS: tuple[str, ...] = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
)

# A bare framework name ("Server: nginx") is normal and low-risk; a name
# plus a version number ("Server: nginx/1.18.0") is what actually narrows
# down which CVEs apply. Only the latter is penalized.
_VERSION_PATTERN = re.compile(r"\d+\.\d+")


@dataclass(frozen=True, slots=True)
class Finding:
    """The graded outcome of one HeaderRule against one response."""

    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class DisclosureFinding:
    """One header that revealed server/framework version information."""

    header: str
    value: str


@dataclass(frozen=True, slots=True)
class AuditReport:
    """
    The complete result of auditing one URL.

    `score` and `grade` are computed properties rather than stored fields —
    they are always derived from `findings` and `disclosures`, so there is
    no way for a caller to construct a report where the number and the
    letter disagree with the underlying evidence.
    """

    requested_url: str
    final_url: str
    status_code: int
    findings: list[Finding]
    disclosures: list[DisclosureFinding]

    @property
    def rubric_score(self) -> int:
        """0-100 score from the seven-header rubric, before any penalty."""
        total_possible = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        if total_possible == 0:
            return 0
        earned = 0.0
        for finding in self.findings:
            points = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += points
            elif finding.status == "weak":
                earned += points / 2
            # "missing" contributes nothing.
        return round((earned / total_possible) * 100)

    @property
    def disclosure_penalty(self) -> int:
        """Points deducted for leaked version headers, capped."""
        raw = len(self.disclosures) * DISCLOSURE_PENALTY_PER_HEADER
        return min(raw, DISCLOSURE_PENALTY_CAP)

    @property
    def score(self) -> int:
        """Final 0-100 score: rubric score minus the disclosure penalty."""
        return max(0, self.rubric_score - self.disclosure_penalty)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def to_dict(self) -> dict:
        """JSON-serializable view, for --json / CI consumption."""
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "score": self.score,
            "rubric_score": self.rubric_score,
            "disclosure_penalty": self.disclosure_penalty,
            "grade": self.grade,
            "findings": [
                {
                    "header": f.rule.header,
                    "severity": f.rule.severity,
                    "status": f.status,
                    "actual_value": f.actual_value,
                    "note": f.note,
                }
                for f in self.findings
            ],
            "disclosures": [asdict(d) for d in self.disclosures],
        }


# =============================================================================
# Pure logic — no network, no printing. This is the part the test suite
# exercises directly, by handing it plain dicts instead of live responses.
# =============================================================================


def _find_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive lookup — HTTP header names are not case-sensitive."""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def evaluate_rule(rule: HeaderRule, headers: dict[str, str]) -> Finding:
    """Grade one rule against one response's headers."""
    value = _find_header(headers, rule.header)

    if value is None:
        return Finding(rule, "missing", None, f"`{rule.header}` was not sent")

    if rule.must_match is not None and not re.search(
        rule.must_match, value, re.IGNORECASE
    ):
        return Finding(
            rule,
            "weak",
            value,
            f"present but does not satisfy `{rule.must_match}` (got `{value}`)",
        )

    lowered = value.lower()
    for banned in rule.must_not_contain:
        if banned in lowered:
            return Finding(
                rule,
                "weak",
                value,
                f"present but contains `{banned}`, which undermines the header's purpose",
            )

    return Finding(rule, "ok", value, "present and correctly configured")


def find_disclosures(headers: dict[str, str]) -> list[DisclosureFinding]:
    """Return every disclosure header that reveals a specific version number."""
    disclosures: list[DisclosureFinding] = []
    for name in DISCLOSURE_HEADERS:
        value = _find_header(headers, name)
        if value and _VERSION_PATTERN.search(value):
            disclosures.append(DisclosureFinding(header=name, value=value))
    return disclosures


# =============================================================================
# I/O boundary — the only function in this file that touches the network.
# =============================================================================

DEFAULT_USER_AGENT = "secheader-audit/1.0 (+https://github.com/theworldofricharda)"


def audit(url: str, *, timeout: float = 10.0) -> AuditReport:
    """
    Fetch `url` once and grade the response's security headers.

    A bare hostname (`example.com`, no scheme) is rejected rather than
    guessed at — silently choosing http:// for the user is exactly the
    kind of ambiguity HSTS exists to close, so this tool won't reproduce
    it in its own input handling.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"'{url}' has no scheme — pass a full URL like https://{url}"
        )

    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": DEFAULT_USER_AGENT},
    )
    headers = dict(response.headers)

    return AuditReport(
        requested_url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=[evaluate_rule(rule, headers) for rule in RULES],
        disclosures=find_disclosures(headers),
    )


# =============================================================================
# Rendering — kept separate from AuditReport so the data model never has
# to know it will eventually be printed to a terminal.
# =============================================================================

_STATUS_COLOR: dict[Status, str] = {"ok": "green", "weak": "yellow", "missing": "red"}
_GRADE_COLOR: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def render_report(report: AuditReport, console: Console) -> None:
    table = Table(
        title=f"{report.final_url}  (HTTP {report.status_code})",
        title_style="bold cyan",
    )
    table.add_column("Header", style="bold white", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Note", style="dim")
    for finding in report.findings:
        color = _STATUS_COLOR[finding.status]
        table.add_row(
            finding.rule.header,
            f"[{color}]{finding.status}[/{color}]",
            finding.rule.severity,
            finding.note,
        )
    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] final response was served over plain HTTP — "
            "browsers ignore Strict-Transport-Security entirely in that case, "
            "so any HSTS grade above does not reflect real protection."
        )

    if report.disclosures:
        console.print("\n[bold]Information disclosure:[/bold]")
        for d in report.disclosures:
            console.print(f"  • [yellow]{d.header}[/yellow]: {d.value}")
        console.print(
            f"  Penalty applied: -{report.disclosure_penalty} points "
            f"(capped at -{DISCLOSURE_PENALTY_CAP})"
        )

    color = _GRADE_COLOR[report.grade]
    console.print(
        Panel(
            f"[bold {color}]Grade: {report.grade}[/bold {color}]\n"
            f"Score: {report.score} / 100  "
            f"(rubric {report.rubric_score} − disclosure {report.disclosure_penalty})",
            title="Result",
            border_style=color,
        )
    )

    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for f in actionable:
            console.print(f"  • [yellow]{f.rule.header}[/yellow] — {f.rule.fix}")


# =============================================================================
# CLI
# =============================================================================


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secheader-audit",
        description="Audit a URL's HTTP security headers and grade the result A-F.",
    )
    parser.add_argument("url", help="Full URL to audit (must include http:// or https://)")
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON instead of a table"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    console = Console()

    try:
        report = audit(args.url, timeout=args.timeout)
    except ValueError as exc:
        console.print(f"[red]Input error:[/red] {exc}")
        return 2
    except httpx.RequestError as exc:
        console.print(f"[red]Request failed:[/red] {type(exc).__name__}: {exc}")
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render_report(report, console)

    if report.grade in ("A", "B"):
        return 0
    if report.grade in ("C", "D"):
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
