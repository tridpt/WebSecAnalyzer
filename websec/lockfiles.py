"""Exact npm versions from owner-supplied lockfiles, with bounded OSV lookups."""

from __future__ import annotations

import json
import re

import requests
import yaml

from .control import ScanControl
from .findings import CheckResult, Severity
from .targets import InvalidTarget

MAX_LOCK_BYTES = 2_000_000
MAX_PACKAGES = 200
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def _add_package(found: set[tuple[str, str]], name: str, version: object) -> None:
    if name and isinstance(version, str) and _VERSION.fullmatch(version):
        found.add((name, version))


def parse_lockfile(filename: str, contents: bytes) -> list[tuple[str, str]]:
    if filename not in {"package-lock.json", "pnpm-lock.yaml"}:
        raise InvalidTarget("Chỉ nhận package-lock.json hoặc pnpm-lock.yaml.")
    if len(contents) > MAX_LOCK_BYTES:
        raise InvalidTarget("Lockfile vượt giới hạn 2 MB.")
    try:
        text = contents.decode("utf-8-sig")
        data = json.loads(text) if filename.endswith(".json") else yaml.safe_load(text)
    except (UnicodeError, ValueError, yaml.YAMLError) as exc:
        raise InvalidTarget("Không đọc được lockfile hợp lệ.") from exc
    if not isinstance(data, dict):
        raise InvalidTarget("Lockfile không có cấu trúc hợp lệ.")
    found: set[tuple[str, str]] = set()
    if filename == "package-lock.json":
        packages = data.get("packages")
        if isinstance(packages, dict):
            for path, meta in packages.items():
                if not isinstance(path, str) or not isinstance(meta, dict) or "node_modules/" not in path:
                    continue
                name = path.rsplit("node_modules/", 1)[-1]
                _add_package(found, name, meta.get("version"))
        else:
            def walk(deps: object) -> None:
                if not isinstance(deps, dict):
                    return
                for name, meta in deps.items():
                    if isinstance(meta, dict):
                        _add_package(found, name, meta.get("version"))
                        walk(meta.get("dependencies"))
            walk(data.get("dependencies"))
    else:
        for section in ("packages", "snapshots"):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for key in entries:
                if not isinstance(key, str):
                    continue
                # pnpm v6: /@scope/name@1.2.3; v9: @scope/name@1.2.3
                clean = key.lstrip("/").split("(", 1)[0]
                name, sep, version = clean.rpartition("@")
                if not sep or not _VERSION.fullmatch(version):
                    # Older pnpm lockfiles use /name/1.2.3.
                    name, sep, version = clean.rpartition("/")
                if sep:
                    _add_package(found, name, version)
    if not found:
        raise InvalidTarget("Không tìm thấy phiên bản npm chính xác trong lockfile.")
    return sorted(found)


def check_lockfile(
    filename: str, packages: list[tuple[str, str]], *,
    use_osv: bool, control: ScanControl | None = None,
) -> CheckResult:
    result = CheckResult(category="npm Lockfile / OSV")
    selected = packages[:MAX_PACKAGES]
    if len(packages) > MAX_PACKAGES:
        result.add("lockfile-limit", "Giới hạn số gói tra cứu", Severity.INFO,
                   f"Lockfile có {len(packages)} cặp gói/phiên bản; đã tra {MAX_PACKAGES} cặp đầu tiên.")
    if not use_osv:
        result.add("lockfile-osv-disabled", "Đã đọc phiên bản từ lockfile", Severity.INFO,
                   f"Tìm thấy {len(packages)} cặp gói/phiên bản; tra cứu OSV đang tắt.",
                   evidence=f"{filename}: {len(packages)} phiên bản chính xác")
        return result
    checked = 0
    failed = 0
    for start in range(0, len(selected), 50):
        if control:
            control.check()
        batch = selected[start:start + 50]
        payload = {"queries": [
            {"version": version, "package": {"name": name, "ecosystem": "npm"}}
            for name, version in batch
        ]}
        try:
            response = requests.post(
                _OSV_BATCH, json=payload,
                timeout=control.timeout(8.0) if control else 8.0,
            )
            response.raise_for_status()
            entries = response.json().get("results")
            if not isinstance(entries, list) or len(entries) != len(batch):
                raise ValueError("OSV batch response không hợp lệ")
        except (requests.RequestException, ValueError):
            if control:
                control.check()
            failed += len(batch)
            continue
        if control:
            control.check()
        checked += len(batch)
        for (name, version), entry in zip(batch, entries):
            vulns = entry.get("vulns") if isinstance(entry, dict) else None
            for vuln in vulns if isinstance(vulns, list) else []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id", "UNKNOWN"))[:100]
                result.add(
                    f"npm:{name}@{version}:{vuln_id}",
                    f"{name} {version}: {vuln_id}", Severity.HIGH,
                    f"OSV ghi nhận lỗ hổng {vuln_id} cho đúng phiên bản trong lockfile.",
                    f"Nâng cấp {name} lên bản đã vá; xem https://osv.dev/vulnerability/{vuln_id}",
                    evidence=f"{filename}: {name}@{version}; OSV: {vuln_id}",
                )
    if failed:
        result.add("lockfile-osv-unavailable", "Một số gói chưa tra được OSV", Severity.INFO,
                   f"OSV không phản hồi cho {failed} gói; không kết luận các gói này an toàn.")
    result.add("lockfile-summary", "Đã tra phiên bản chính xác từ lockfile", Severity.INFO,
               f"OSV đã trả lời cho {checked}/{len(selected)} cặp gói/phiên bản.",
               evidence=f"{filename}: {len(packages)} cặp gói/phiên bản")
    return result
