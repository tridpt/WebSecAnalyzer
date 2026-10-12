"""HTML resource findings use only fetched markup and keep URL secrets out of reports."""

from __future__ import annotations

from conftest import FakeResponse

from websec.evidence import evidence_bundle, snapshot_response
from websec.findings import Severity, Verification
from websec.html_resources import check_html_resources
from websec.scanner import ScanReport


def _response(html: str, *, headers: dict[str, str] | None = None, url: str = "https://owned.test/"):
    response = FakeResponse(headers=headers, text=html)
    response.url = url
    response.status_code = 200
    return response


def test_mixed_resources_form_and_external_script_have_redacted_evidence():
    response = _response("""
      <script src="http://cdn.test/app.js?token=PRIVATE_SCRIPT"></script>
      <link rel="stylesheet" href="http://cdn.test/site.css">
      <img src="http://cdn.test/photo.png?key=PRIVATE_IMAGE">
      <form action="http://owned.test/submit?session=PRIVATE_FORM"></form>
      <script src="https://cdn.test/vendor.js?key=PRIVATE_SRI"></script>
    """)
    result = check_html_resources(response)
    checks = {finding.check: finding for finding in result.findings}
    assert set(checks) == {
        "mixed-content-active", "mixed-content-passive",
        "insecure-form-action", "external-script-no-sri",
    }
    assert checks["mixed-content-active"].severity == Severity.MEDIUM
    assert checks["external-script-no-sri"].severity == Severity.LOW
    assert all(finding.verification == Verification.OBSERVED for finding in checks.values())
    text = " ".join(finding.evidence for finding in result.findings)
    assert "token=[REDACTED]" in text
    assert "PRIVATE_" not in text

    page = ScanReport(
        response.url, response.url, 200, results=[result],
        observations=[snapshot_response(response, purpose="page")],
    )
    report = ScanReport(response.url, response.url, 200, pages=[page])
    bundle = evidence_bundle(report)
    assert all(item["response_ids"] == ["r1"] for item in bundle["surfaces"][1]["findings"])


def test_same_origin_https_integrity_and_csp_upgrade_are_not_flagged():
    response = _response("""
      <script src="/app.js"></script>
      <script src="//cdn.test/vendor.js" integrity="sha384-example" crossorigin="anonymous"></script>
      <link rel="stylesheet" href="http://cdn.test/old.css">
      <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
      <img src="http://cdn.test/old.png">
    """, headers={"Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests"})
    result = check_html_resources(response)
    assert [finding.check for finding in result.findings] == ["html-resources-ok"]


def test_base_href_changes_effective_script_origin_and_meta_only_applies_forward():
    response = _response("""
      <script src="http://cdn.test/before.js"></script>
      <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
      <script src="http://cdn.test/after.js"></script>
      <base href="https://cdn.test/assets/">
      <script src="vendor.js"></script>
    """)
    checks = {finding.check: finding for finding in check_html_resources(response).findings}
    assert "before.js" in checks["mixed-content-active"].evidence
    assert "after.js" not in checks["mixed-content-active"].evidence
    assert "https://cdn.test/assets/vendor.js" in checks["external-script-no-sri"].evidence


def test_http_page_does_not_claim_mixed_content_or_sri_result():
    result = check_html_resources(_response(
        '<script src="https://cdn.test/app.js"></script>', url="http://owned.test/",
    ))
    assert [finding.check for finding in result.findings] == ["html-resources-https-only"]


def test_malformed_resource_port_is_ignored_without_failing_page():
    result = check_html_resources(_response(
        '<script src="https://cdn.test:invalid/app.js"></script>'
        '<script src="https://cdn.test/good.js"></script>',
    ))
    assert [finding.check for finding in result.findings] == ["external-script-no-sri"]
    assert "good.js" in result.findings[0].evidence
