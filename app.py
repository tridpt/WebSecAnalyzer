"""Flask web UI for WebSecAnalyzer.

Run:
    python app.py                 # default http://127.0.0.1:8000
    python app.py --port 8080     # pick a port
    set PORT=9000 && python app.py  # or via env var (Windows cmd)

Local-only tool. It still enforces the ownership confirmation: the scan form
has a checkbox you must tick to confirm you own / are authorized to test the
target. Only scan sites you are allowed to test.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, session, url_for

from websec import storage
from websec.api import (
    parse_api_credential, parse_api_targets, parse_comparison_fields,
    validate_openapi_path,
)
from websec.api_preview import preview_openapi
from websec.browser_cors import validate_browser_options
from websec.compare import compare_reports
from websec.control import ScanControl, ScanStopped
from websec.crawler import MAX_PAGES
from websec.evidence import evidence_bundle
from websec.lockfiles import MAX_LOCK_BYTES, parse_lockfile
from websec.report import render_json
from websec.scanner import scan
from websec.targets import InvalidTarget
from websec.waivers import Waiver, finding_refs, fingerprint, waiver_payload

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.config["MAX_CONTENT_LENGTH"] = MAX_LOCK_BYTES + 100_000
app.add_template_global(fingerprint, "finding_key")

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
_jobs_lock = threading.Lock()


@dataclass
class ScanJob:
    owner: str
    control: ScanControl
    status: str = "running"
    report_id: int | None = None
    error: str = ""


_jobs: dict[str, ScanJob] = {}


def _score_class(score: int) -> str:
    if score >= 85:
        return "good"
    if score >= 60:
        return "ok"
    if score >= 40:
        return "warn"
    return "bad"


def _csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _owner_token() -> str:
    if "job_owner" not in session:
        session["job_owner"] = secrets.token_urlsafe(24)
    return session["job_owner"]


def _valid_csrf() -> bool:
    return secrets.compare_digest(
        request.form.get("csrf_token") or "", session.get("csrf_token", "")
    )


def _run_job(job: ScanJob, options: dict) -> None:
    try:
        report = scan(**options, control=job.control)
        job.control.check()
        report_id = storage.save_report(report)
        with _jobs_lock:
            job.report_id = report_id
            job.status = "done"
    except ScanStopped as exc:
        with _jobs_lock:
            job.status = "cancelled" if job.control.cancelled.is_set() else "timed_out"
            job.error = str(exc)
    except (InvalidTarget, requests.RequestException) as exc:
        with _jobs_lock:
            job.status = "error"
            job.error = str(exc)
    except Exception:
        logging.exception("Scan job failed")
        with _jobs_lock:
            job.status = "error"
            job.error = "Lần quét gặp lỗi không mong đợi. Xem log máy chủ để biết chi tiết."


def _owned_job(job_id: str) -> ScanJob:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None or job.owner != session.get("job_owner"):
        abort(404)
    return job


@app.route("/", methods=["GET", "POST"])
def index():
    context: dict = {"score_class": _score_class, "csrf_token": _csrf_token()}

    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        owns = request.form.get("owns") == "on"
        use_osv = request.form.get("no_osv") != "on"
        try:
            max_pages = int(request.form.get("max_pages", "20"))
        except ValueError:
            max_pages = 0
        try:
            max_seconds = int(request.form.get("max_seconds", "120"))
        except ValueError:
            max_seconds = 0

        if not _valid_csrf():
            context["error"] = (
                "Phiên biểu mẫu đã hết hạn. Hãy nhập lại URL và thử quét lần nữa."
            )
            return render_template("index.html", **context), 400
        if not url:
            context["error"] = "Vui lòng nhập địa chỉ website."
        elif not owns:
            context["error"] = "Vui lòng xác nhận bạn có quyền kiểm tra website này."
        elif not 1 <= max_pages <= MAX_PAGES:
            context["error"] = f"Số trang cần quét phải từ 1 đến {MAX_PAGES}."
        elif not 1 <= max_seconds <= 600:
            context["error"] = "Thời gian quét tối đa phải từ 1 đến 600 giây."
        else:
            try:
                openapi_path = (request.form.get("openapi_path") or "").strip() or None
                api_paths = (request.form.get("api_paths") or "").splitlines()
                validate_openapi_path(openapi_path)
                selected_api = parse_api_targets(api_paths)
                api_credential = parse_api_credential(
                    request.form.get("api_auth_mode"),
                    request.form.get("api_auth_secret"),
                )
                browser_cors = request.form.get("browser_cors") == "on"
                js_discovery = request.form.get("js_discovery") == "on"
                browser_cookie_attributes = (
                    request.form.get("browser_cookie_attributes") or ""
                ).strip() or None
                validate_browser_options(
                    browser_cors, api_credential, browser_cookie_attributes,
                )
                api_second_credential = parse_api_credential(
                    request.form.get("api_second_auth_mode"),
                    request.form.get("api_second_auth_secret"),
                )
                api_compare_fields = (
                    request.form.get("api_compare_fields") or ""
                ).splitlines()
                selected_fields = parse_comparison_fields(
                    api_compare_fields, selected_api
                )
                if api_credential and not selected_api:
                    raise InvalidTarget("Hãy chọn ít nhất một endpoint GET trước khi nhập phiên thử nghiệm.")
                if bool(selected_fields) != bool(api_second_credential) or (
                    api_second_credential and not api_credential
                ):
                    raise InvalidTarget(
                        "So sánh hai tài khoản cần cả hai phiên và ít nhất một trường JSON đã chọn."
                    )
                if api_second_credential == api_credential and api_second_credential:
                    raise InvalidTarget("Hai phiên thử nghiệm phải khác nhau.")
                lockfile = None
                upload = request.files.get("lockfile")
                if upload and upload.filename:
                    filename = upload.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                    contents = upload.read(MAX_LOCK_BYTES + 1)
                    parse_lockfile(filename, contents)
                    lockfile = (filename, contents)
                with _jobs_lock:
                    if sum(job.status == "running" for job in _jobs.values()) >= 2:
                        raise InvalidTarget("Đang có 2 lượt quét. Hãy đợi hoặc hủy một lượt quét.")
                    job_id = secrets.token_urlsafe(16)
                    job = ScanJob(owner=_owner_token(), control=ScanControl(max_seconds))
                    _jobs[job_id] = job
                    # Keep a small bounded in-memory history of job statuses.
                    for old_id in list(_jobs)[:-30]:
                        if _jobs[old_id].status != "running":
                            del _jobs[old_id]
                options = {
                    "url": url, "use_osv": use_osv,
                    "allow_private": os.environ.get("ALLOW_PRIVATE_TARGETS") == "1",
                    "max_pages": max_pages, "max_seconds": max_seconds,
                    "lockfile": lockfile,
                    "openapi_path": openapi_path, "api_paths": api_paths,
                    "api_credential": api_credential,
                    "api_second_credential": api_second_credential,
                    "api_compare_fields": api_compare_fields,
                    "browser_cors": browser_cors,
                    "browser_cookie_attributes": browser_cookie_attributes,
                    "js_discovery": js_discovery,
                }
                threading.Thread(target=_run_job, args=(job, options), daemon=True).start()
                return redirect(url_for("view_job", job_id=job_id))
            except InvalidTarget as exc:
                context["error"] = str(exc)

    return render_template("index.html", **context)


@app.route("/openapi/preview", methods=["POST"])
def preview_api_routes():
    if not _valid_csrf():
        abort(400)
    if request.form.get("owns") != "on":
        return jsonify({"error": "Xác nhận quyền kiểm tra trước khi đọc OpenAPI."}), 400
    try:
        result = preview_openapi(
            request.form.get("url") or "",
            request.form.get("openapi_path") or "",
            allow_private=os.environ.get("ALLOW_PRIVATE_TARGETS") == "1",
        )
    except InvalidTarget as exc:
        return jsonify({"error": str(exc)}), 400
    except ScanStopped:
        return jsonify({"error": "Đọc OpenAPI đã hết thời gian cho phép."}), 504
    except requests.RequestException:
        return jsonify({"error": "Không kết nối được tới tài liệu OpenAPI."}), 502
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/job/<job_id>")
def view_job(job_id: str):
    job = _owned_job(job_id)
    if job.status == "done":
        return redirect(url_for("view_scan", scan_id=job.report_id))
    return render_template("job.html", job=job, job_id=job_id, csrf_token=_csrf_token())


@app.route("/job/<job_id>/status")
def job_status(job_id: str):
    job = _owned_job(job_id)
    with _jobs_lock:
        status, error, report_id = job.status, job.error, job.report_id
    return jsonify({
        "status": status, "error": error,
        "report_url": url_for("view_scan", scan_id=report_id) if report_id else None,
    })


@app.route("/job/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id: str):
    if not _valid_csrf():
        abort(400)
    job = _owned_job(job_id)
    with _jobs_lock:
        if job.status == "running":
            job.control.cancelled.set()
    return redirect(url_for("view_job", job_id=job_id))


@app.route("/history")
def history():
    return render_template(
        "history.html",
        entries=storage.list_history(),
        score_class=_score_class,
    )


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id: int):
    report = storage.get_report(scan_id)
    if report is None:
        abort(404)
    return render_template(
        "view.html",
        report=report,
        scan_id=scan_id,
        waivers_by_id={item.fingerprint: item for item in storage.list_waivers()},
        can_manage_waivers=True,
        csrf_token=_csrf_token(),
        today_utc=datetime.now(timezone.utc).date().isoformat(),
        trend=storage.score_trend(report.url),
        previous_id=storage.previous_scan_id(report.url, scan_id),
        score_class=_score_class,
    )


@app.route("/scan/<int:scan_id>/export")
def export_scan(scan_id: int):
    report = storage.get_report(scan_id)
    if report is None:
        abort(404)
    html = render_template(
        "export.html",
        report=report,
        scan_id=scan_id,
        waivers_by_id={item.fingerprint: item for item in storage.list_waivers()},
        can_manage_waivers=False,
        score_class=_score_class,
    )
    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f"attachment; filename=websec-report-{scan_id}.html"
        },
    )


@app.route("/scan/<int:scan_id>/json")
def export_json(scan_id: int):
    report = storage.get_report(scan_id)
    if report is None:
        abort(404)
    finding_ids = {ref.fingerprint for ref in finding_refs(report)}
    waivers = [item for item in storage.list_waivers() if item.fingerprint in finding_ids]
    payload = json.loads(render_json(report))
    payload["exceptions"] = [
        {**waiver_payload([item])["exceptions"][0], "active": item.active}
        for item in waivers
    ]
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=websec-report-{scan_id}.json"},
    )


@app.route("/scan/<int:scan_id>/evidence.json")
def export_evidence(scan_id: int):
    report = storage.get_report(scan_id)
    if report is None:
        abort(404)
    return Response(
        json.dumps(evidence_bundle(report), ensure_ascii=False, indent=2) + "\n",
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=websec-evidence-{scan_id}.json",
            "Cache-Control": "no-store",
        },
    )


@app.route("/scan/<int:scan_id>/waiver", methods=["POST"])
def save_scan_waiver(scan_id: int):
    if not _valid_csrf():
        abort(400)
    report = storage.get_report(scan_id)
    if report is None:
        abort(404)
    selected = request.form.get("fingerprint", "")
    ref = next((item for item in finding_refs(report) if item.fingerprint == selected), None)
    if ref is None:
        abort(400, "Phát hiện không thuộc báo cáo này.")
    try:
        waiver = Waiver.from_finding(
            ref, request.form.get("reason", ""), request.form.get("expires_on", ""),
        )
        storage.save_waiver(waiver)
    except InvalidTarget as exc:
        abort(400, str(exc))
    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/waivers")
def view_waivers():
    return render_template(
        "waivers.html", waivers=storage.list_waivers(), csrf_token=_csrf_token(),
    )


@app.route("/waivers/<fingerprint>/delete", methods=["POST"])
def remove_waiver(fingerprint: str):
    if not _valid_csrf():
        abort(400)
    storage.delete_waiver(fingerprint)
    return redirect(url_for("view_waivers"))


@app.route("/waivers/json")
def export_waivers():
    return Response(
        json.dumps(waiver_payload(storage.list_waivers()), ensure_ascii=False, indent=2) + "\n",
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=websec-exceptions.json"},
    )


@app.route("/compare")
def compare_scans():
    try:
        old_id = int(request.args["old"])
        new_id = int(request.args["new"])
    except (KeyError, ValueError):
        abort(400)
    old = storage.get_report(old_id)
    new = storage.get_report(new_id)
    if old is None or new is None:
        abort(404)
    if old.url != new.url:
        abort(400, "Chỉ so sánh hai lần quét cùng URL đầu vào.")
    return render_template(
        "compare.html", comparison=compare_reports(old, new),
        old_id=old_id, new_id=new_id, score_class=_score_class,
    )


def _parse_args() -> int:
    parser = argparse.ArgumentParser(description="WebSecAnalyzer web UI")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8000")),
        help="Port to listen on (default: $PORT or 8000)",
    )
    args = parser.parse_args()
    return args.port


if __name__ == "__main__":
    port = _parse_args()
    print(f"WebSecAnalyzer UI: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
