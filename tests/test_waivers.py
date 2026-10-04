"""Verification labels and exact, expiring exception lifecycle."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import app as web_app

from websec import storage
from websec.findings import CheckResult, Severity, Verification
from websec.report import to_dict
from websec.scanner import ScanReport
from websec.waivers import Waiver, finding_refs, load_waivers, waiver_payload


def _report() -> ScanReport:
    direct = CheckResult(category="HTTP Security Headers")
    direct.add("x-content-type-options", "Thiếu nosniff", Severity.MEDIUM, "Header không có.")
    inferred = CheckResult(category="API Access")
    inferred.add("api-auth-missing", "API trả 2xx", Severity.HIGH, "Cần xác minh dữ liệu.")
    unknown = CheckResult(category="TLS/SSL Configuration", error="Không kết nối được.")
    page = ScanReport(
        "https://owned.test/", "https://owned.test/", 200,
        results=[direct, inferred, unknown],
    )
    return ScanReport("https://owned.test/", "https://owned.test/", 200, pages=[page])


def test_verification_is_serialized_and_legacy_reports_are_inferred():
    report = _report()
    findings = report.pages[0].results
    assert findings[0].findings[0].verification == Verification.OBSERVED
    assert findings[1].findings[0].verification == Verification.SUSPECTED
    data = to_dict(report)
    assert data["pages"][0]["categories"][2]["verification"] == "inconclusive"
    assert data["pages"][0]["categories"][1]["findings"][0]["verification"] == "suspected"
    restored = ScanReport.from_dict(data)
    assert restored.pages[0].results[1].findings[0].verification == Verification.SUSPECTED
    del data["pages"][0]["categories"][1]["findings"][0]["verification"]
    legacy = ScanReport.from_dict(data)
    assert legacy.pages[0].results[1].findings[0].verification == Verification.SUSPECTED


def test_waiver_storage_web_form_export_and_revocation(tmp_path, monkeypatch):
    db = tmp_path / "history.db"
    report = _report()
    report_id = storage.save_report(report, db)
    get_report = storage.get_report
    list_waivers = storage.list_waivers
    save_waiver = storage.save_waiver
    delete_waiver = storage.delete_waiver
    monkeypatch.setattr(web_app.storage, "get_report", lambda scan_id: get_report(scan_id, db))
    monkeypatch.setattr(web_app.storage, "list_waivers", lambda: list_waivers(db))
    monkeypatch.setattr(web_app.storage, "save_waiver", lambda item: save_waiver(item, db))
    monkeypatch.setattr(web_app.storage, "delete_waiver", lambda key: delete_waiver(key, db))
    monkeypatch.setattr(web_app.storage, "score_trend", lambda url: [])
    monkeypatch.setattr(web_app.storage, "previous_scan_id", lambda url, scan_id: None)

    client = web_app.app.test_client()
    page = client.get(f"/scan/{report_id}")
    assert page.status_code == 200
    assert "Có bằng chứng" in page.get_data(as_text=True)
    assert "Nghi ngờ" in page.get_data(as_text=True)
    assert "Không kết luận được" in page.get_data(as_text=True)
    with client.session_transaction() as user_session:
        token = user_session["csrf_token"]
    ref = next(item for item in finding_refs(report) if item.finding.check == "api-auth-missing")
    expiry = (datetime.now(timezone.utc).date() + timedelta(days=2)).isoformat()
    url = f"/scan/{report_id}/waiver"
    form = {
        "csrf_token": token, "fingerprint": ref.fingerprint,
        "reason": "Đã kiểm tra thủ công với tài khoản thử nghiệm", "expires_on": expiry,
    }
    assert client.post(url, data={**form, "csrf_token": "bad"}).status_code == 400
    assert client.post(url, data={**form, "fingerprint": "f" * 64}).status_code == 400
    assert client.post(url, data={**form, "reason": " "}).status_code == 400
    assert client.post(url, data={**form, "expires_on": "2020-01-01"}).status_code == 400
    assert client.post(url, data=form).status_code == 302
    saved = list_waivers(db)
    assert len(saved) == 1 and saved[0].active
    assert saved[0].fingerprint == ref.fingerprint
    assert "Ngoại lệ còn hiệu lực" in client.get(f"/scan/{report_id}").get_data(as_text=True)
    offline = client.get(f"/scan/{report_id}/export").get_data(as_text=True)
    assert "Ngoại lệ còn hiệu lực" in offline and "Lưu ngoại lệ" not in offline
    exported_report = client.get(f"/scan/{report_id}/json").json
    assert exported_report["exceptions"][0]["reason"] == form["reason"]
    assert exported_report["pages"][0]["categories"][1]["findings"][0]["severity"] == "HIGH"
    exported_waivers = client.get("/waivers/json").json
    assert exported_waivers["format"] == "websec-waivers-v1"
    assert len(exported_waivers["exceptions"]) == 1
    assert client.post(f"/waivers/{ref.fingerprint}/delete", data={"csrf_token": token}).status_code == 302
    assert list_waivers(db) == []


def test_waiver_file_validation_and_expiry(tmp_path):
    report = _report()
    ref = next(item for item in finding_refs(report) if item.finding.check == "api-auth-missing")
    expiry = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
    waiver = Waiver.from_finding(ref, "Đã được chấp nhận tạm thời", expiry)
    file = tmp_path / "waivers.json"
    file.write_text(json.dumps(waiver_payload([waiver])), encoding="utf-8")
    assert load_waivers(file)[ref.fingerprint].active
    expired = replace(waiver, expires_on="2020-01-01")
    file.write_text(json.dumps(waiver_payload([expired])), encoding="utf-8")
    assert not load_waivers(file)[ref.fingerprint].active
    invalid = replace(waiver, fingerprint="f" * 64)
    file.write_text(json.dumps(waiver_payload([invalid])), encoding="utf-8")
    from websec.targets import InvalidTarget
    import pytest
    with pytest.raises(InvalidTarget):
        load_waivers(file)
