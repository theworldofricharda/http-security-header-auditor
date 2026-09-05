"""
test_secheader_audit.py

The pure functions (evaluate_rule, find_disclosures, AuditReport's
properties) are tested directly with plain dicts — no network involved.
audit() itself is tested with httpx.MockTransport, which intercepts the
request inside httpx before it ever reaches a socket, so the whole suite
runs offline and in well under a second.
"""

from __future__ import annotations

import httpx
import pytest

from secheader_audit import (
    RULES,
    AuditReport,
    DisclosureFinding,
    Finding,
    audit,
    evaluate_rule,
    find_disclosures,
)

STRICT_TRANSPORT_RULE = next(r for r in RULES if r.header == "Strict-Transport-Security")
CSP_RULE = next(r for r in RULES if r.header == "Content-Security-Policy")
FRAME_RULE = next(r for r in RULES if r.header == "X-Frame-Options")
NOSNIFF_RULE = next(r for r in RULES if r.header == "X-Content-Type-Options")


# --- evaluate_rule: missing / ok / weak, per rule shape --------------------


def test_missing_header_is_graded_missing():
    finding = evaluate_rule(STRICT_TRANSPORT_RULE, {})
    assert finding.status == "missing"
    assert finding.actual_value is None


def test_header_lookup_is_case_insensitive():
    # Real servers send mixed-case header names; RFC 7230 says it must
    # not matter, so the scanner must not care either.
    finding = evaluate_rule(NOSNIFF_RULE, {"x-CONTENT-type-OPTIONS": "nosniff"})
    assert finding.status == "ok"


def test_must_match_rule_accepts_matching_value():
    finding = evaluate_rule(
        STRICT_TRANSPORT_RULE, {"Strict-Transport-Security": "max-age=31536000"}
    )
    assert finding.status == "ok"


def test_hsts_max_age_zero_is_weak_not_ok():
    # This is the whole point of using a regex instead of bare presence:
    # max-age=0 actively disables HSTS, so it must never grade as "ok".
    finding = evaluate_rule(
        STRICT_TRANSPORT_RULE, {"Strict-Transport-Security": "max-age=0"}
    )
    assert finding.status == "weak"


def test_csp_present_without_unsafe_tokens_is_ok():
    finding = evaluate_rule(
        CSP_RULE, {"Content-Security-Policy": "default-src 'self'"}
    )
    assert finding.status == "ok"


def test_csp_with_unsafe_inline_is_weak():
    finding = evaluate_rule(
        CSP_RULE,
        {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"},
    )
    assert finding.status == "weak"
    assert "unsafe-inline" in finding.note


def test_frame_options_allow_from_is_weak():
    # ALLOW-FROM is deprecated and browsers ignore it — a site relying on
    # it is not actually protected, so bare presence must not pass.
    finding = evaluate_rule(
        FRAME_RULE, {"X-Frame-Options": "ALLOW-FROM https://example.com"}
    )
    assert finding.status == "weak"


def test_frame_options_deny_is_ok():
    finding = evaluate_rule(FRAME_RULE, {"X-Frame-Options": "DENY"})
    assert finding.status == "ok"


# --- find_disclosures -------------------------------------------------------


def test_bare_server_name_is_not_a_disclosure():
    # "nginx" with no version number is normal ops hygiene, not a leak.
    assert find_disclosures({"Server": "nginx"}) == []


def test_versioned_server_header_is_a_disclosure():
    disclosures = find_disclosures({"Server": "Apache/2.4.41"})
    assert disclosures == [DisclosureFinding(header="Server", value="Apache/2.4.41")]


def test_multiple_disclosure_headers_are_all_reported():
    disclosures = find_disclosures(
        {"Server": "nginx/1.18.0", "X-Powered-By": "Express/4.17.1"}
    )
    assert {d.header for d in disclosures} == {"Server", "X-Powered-By"}


# --- AuditReport scoring -----------------------------------------------------


def _report(findings: list[Finding], disclosures: list[DisclosureFinding] | None = None) -> AuditReport:
    return AuditReport(
        requested_url="https://example.test",
        final_url="https://example.test",
        status_code=200,
        findings=findings,
        disclosures=disclosures or [],
    )


def test_all_ok_scores_100_and_grades_a():
    findings = [evaluate_rule(r, {r.header: "1"}) for r in RULES]
    # Force every rule to "ok" using values that satisfy each constraint.
    values = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    findings = [evaluate_rule(r, values) for r in RULES]
    report = _report(findings)
    assert report.score == 100
    assert report.grade == "A"


def test_everything_missing_scores_zero_and_grades_f():
    findings = [evaluate_rule(r, {}) for r in RULES]
    report = _report(findings)
    assert report.score == 0
    assert report.grade == "F"


def test_disclosure_penalty_reduces_score_but_is_capped():
    findings = [evaluate_rule(r, {}) for r in RULES]
    many_disclosures = [
        DisclosureFinding(header=h, value="v/1.0") for h in ("Server", "X-Powered-By", "X-Runtime")
    ]
    report = _report(findings, many_disclosures)
    # 3 headers * 5 points = 15, which sits exactly at the cap.
    assert report.disclosure_penalty == 15
    assert report.score == 0  # already 0 from missing headers; can't go negative


def test_score_never_goes_below_zero_with_penalty_on_top_of_low_rubric():
    only_low_ok = [
        evaluate_rule(r, {"Referrer-Policy": "strict-origin-when-cross-origin"} if r.header == "Referrer-Policy" else {})
        for r in RULES
    ]
    report = _report(
        only_low_ok,
        [DisclosureFinding(header="Server", value="nginx/1.0"), DisclosureFinding(header="X-Powered-By", value="PHP/8.0")],
    )
    assert report.score >= 0


# --- audit(): network boundary, mocked with httpx.MockTransport ------------


def _mock_client_response(headers: dict[str, str], status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, request=request)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_audit_rejects_bare_hostname_without_scheme():
    with pytest.raises(ValueError, match="no scheme"):
        audit("example.com")


def test_audit_builds_a_full_report_from_mocked_response(monkeypatch):
    response_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "Server": "nginx/1.18.0",
    }

    # NB: this function's `headers` kwarg is audit()'s request headers (the
    # User-Agent), not the mocked *response* headers — keep the two apart,
    # a same-name shadow here previously made the mock silently empty.
    def fake_get(url, *, timeout, follow_redirects, headers=None):
        client = _mock_client_response(response_headers)
        return client.get(url)

    monkeypatch.setattr(httpx, "get", fake_get)

    report = audit("https://example.test")
    assert report.status_code == 200
    assert report.final_url == "https://example.test"
    assert len(report.findings) == len(RULES)
    assert report.disclosures == [DisclosureFinding(header="Server", value="nginx/1.18.0")]


def test_to_dict_is_json_shaped(monkeypatch):
    def fake_get(url, *, timeout, follow_redirects, headers=None):
        client = _mock_client_response({})
        return client.get(url)

    monkeypatch.setattr(httpx, "get", fake_get)
    report = audit("https://example.test")
    payload = report.to_dict()
    assert payload["grade"] == "F"
    assert payload["score"] == 0
    assert len(payload["findings"]) == len(RULES)
