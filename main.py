"""WebSecAnalyzer CLI.

Passive web security analyzer. ONLY run this against websites you own or have
explicit written permission to test. It performs no attacks - it reads HTTP
headers, cookies, the TLS certificate, and script tags, then scores them.

Usage:
    python main.py https://your-site.example
    python main.py your-site.example --json
    python main.py https://your-site.example --no-color
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests

from websec.report import render_json, render_text
from websec.scanner import scan
from websec.targets import InvalidTarget
from websec.control import ScanStopped
from websec.lockfiles import MAX_LOCK_BYTES
from websec.ci import load_baseline
from websec.compare import new_high_issues
from websec.scope import missing_baseline_scope
from websec.waivers import active_waiver_for, load_waivers
from websec.api import parse_api_credential


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="Passive web security analyzer (test your own sites only).",
    )
    parser.add_argument("url", help="URL or hostname to analyze")
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors"
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--no-osv",
        action="store_true",
        help="Skip live OSV.dev CVE lookup (use offline heuristics only)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=20,
        help="Maximum same-origin HTML pages to inspect (1-30; default 20)",
    )
    parser.add_argument(
        "--max-seconds", type=int, default=120,
        help="Maximum total scan time in seconds (1-600; default 120)",
    )
    parser.add_argument(
        "--lockfile", type=Path,
        help="Local package-lock.json or pnpm-lock.yaml for exact npm OSV lookup",
    )
    parser.add_argument(
        "--openapi-path", metavar="/openapi.json",
        help="Read same-origin OpenAPI metadata; discovered routes are listed, not called",
    )
    parser.add_argument(
        "--api-url", action="append", default=[], metavar="/api/health",
        help="Probe a selected GET endpoint without cookies or reading its body (max 10)",
    )
    parser.add_argument(
        "--api-private-url", action="append", default=[], metavar="/api/account",
        help="Like --api-url, but flag HTTP 2xx without authentication as high risk",
    )
    credential_group = parser.add_mutually_exclusive_group()
    credential_group.add_argument(
        "--auth-cookie-env", metavar="NAME",
        help="Read a test-account Cookie value from an environment variable",
    )
    credential_group.add_argument(
        "--auth-bearer-env", metavar="NAME",
        help="Read a test-account Bearer token from an environment variable",
    )
    second_credential_group = parser.add_mutually_exclusive_group()
    second_credential_group.add_argument(
        "--auth-second-cookie-env", metavar="NAME",
        help="Read account B's Cookie value from an environment variable",
    )
    second_credential_group.add_argument(
        "--auth-second-bearer-env", metavar="NAME",
        help="Read account B's Bearer token from an environment variable",
    )
    parser.add_argument(
        "--api-compare-field", action="append", default=[], metavar="'/api/account /user/id'",
        help="Compare one private GET endpoint's JSON Pointer between accounts A and B",
    )
    parser.add_argument(
        "--browser-cors", action="store_true",
        help="Verify selected private API CORS in an isolated local browser",
    )
    parser.add_argument(
        "--browser-cookie-attributes", metavar="'SameSite=None; Secure; Path=/'",
        help="Actual attributes of the single test Cookie used by --browser-cors",
    )
    parser.add_argument(
        "--fail-on-new-high", type=Path, metavar="BASELINE.json",
        help="Exit 3 for new high findings or baseline URLs/APIs not rechecked",
    )
    parser.add_argument(
        "--waivers", type=Path, metavar="EXCEPTIONS.json",
        help="Time-limited exceptions exported by the local UI (requires --fail-on-new-high)",
    )
    parser.add_argument(
        "--yes-i-own-this",
        action="store_true",
        help="Confirm you own or are authorized to test the target",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow localhost/private targets that you own (local testing only)",
    )
    args = parser.parse_args(argv)

    if not args.yes_i_own_this:
        print(
            "Refusing to scan: pass --yes-i-own-this to confirm you own or are\n"
            "authorized to test this site. Scanning sites without permission\n"
            "may be illegal.",
            file=sys.stderr,
        )
        return 2
    if args.waivers and not args.fail_on_new_high:
        print("--waivers requires --fail-on-new-high.", file=sys.stderr)
        return 2

    try:
        baseline = load_baseline(args.fail_on_new_high) if args.fail_on_new_high else None
        waivers = load_waivers(args.waivers) if args.waivers else {}
        credential = None
        second_credential = None
        env_name = args.auth_cookie_env or args.auth_bearer_env
        if env_name:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
                raise InvalidTarget("Tên biến môi trường của phiên thử nghiệm không hợp lệ.")
            credential = parse_api_credential(
                "cookie" if args.auth_cookie_env else "bearer",
                os.environ.get(env_name),
            )
        second_env_name = args.auth_second_cookie_env or args.auth_second_bearer_env
        if second_env_name:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", second_env_name):
                raise InvalidTarget("Tên biến môi trường của tài khoản B không hợp lệ.")
            second_credential = parse_api_credential(
                "cookie" if args.auth_second_cookie_env else "bearer",
                os.environ.get(second_env_name),
            )
        lockfile = None
        if args.lockfile:
            if args.lockfile.name not in {"package-lock.json", "pnpm-lock.yaml"}:
                raise InvalidTarget("Chỉ nhận package-lock.json hoặc pnpm-lock.yaml.")
            with args.lockfile.open("rb") as source:
                contents = source.read(MAX_LOCK_BYTES + 1)
            lockfile = (args.lockfile.name, contents)
        report = scan(
            args.url,
            timeout=args.timeout,
            use_osv=not args.no_osv,
            allow_private=args.allow_private,
            max_pages=args.max_pages,
            max_seconds=args.max_seconds,
            lockfile=lockfile,
            openapi_path=args.openapi_path,
            api_paths=args.api_url + [f"private {path}" for path in args.api_private_url],
            api_credential=credential,
            api_second_credential=second_credential,
            api_compare_fields=args.api_compare_field,
            browser_cors=args.browser_cors,
            browser_cookie_attributes=args.browser_cookie_attributes,
        )
    except (InvalidTarget, ScanStopped) as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Cannot read lockfile: {exc}", file=sys.stderr)
        return 2

    if baseline is not None and baseline.url != report.url:
        print(
            f"Baseline URL does not match scan URL: {baseline.url!r} != {report.url!r}",
            file=sys.stderr,
        )
        return 2

    missing_scope = []
    new_high = []
    unwaived_high = []
    active_exceptions = []
    if baseline is not None:
        missing_scope = missing_baseline_scope(baseline, report)
        new_high = new_high_issues(baseline, report)
        active_exceptions = [
            (issue, active_waiver_for(issue, report.url, waivers))
            for issue in new_high
        ]
        unwaived_high = [issue for issue, waiver in active_exceptions if waiver is None]
    if args.json:
        payload = json.loads(render_json(report))
        if baseline is not None:
            payload["ci_gate"] = {
                "status": "failed" if missing_scope or unwaived_high else "passed",
                "missing_scope": missing_scope,
                "unwaived_new_high": unwaived_high,
                "applied_exceptions": [
                    {
                        "fingerprint": issue["fingerprint"],
                        "url": issue["url"],
                        "title": issue["title"],
                        "reason": waiver.reason,
                        "expires_on": waiver.expires_on,
                    }
                    for issue, waiver in active_exceptions if waiver is not None
                ],
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(report, use_color=not args.no_color))
    if baseline is not None:
        if missing_scope or unwaived_high:
            if missing_scope:
                print(
                    f"CI gate failed: {len(missing_scope)} baseline URL/API surface(s) not rechecked or weakened:",
                    file=sys.stderr,
                )
                for item in missing_scope:
                    print(
                        f"  {item['surface']}: {item['requested_url']} -> {item['final_url']}"
                        + (" (authentication expected)" if item.get("expects_authentication") else ""),
                        file=sys.stderr,
                    )
            if unwaived_high:
                print(f"CI gate failed: {len(unwaived_high)} new high finding(s):", file=sys.stderr)
            for issue in unwaived_high:
                print(f"  {issue['url']} · {issue['title']}", file=sys.stderr)
            return 3
        waived_count = len(new_high) - len(unwaived_high)
        print(
            f"CI gate passed: baseline scope retained; no unexcepted new high findings"
            f" ({waived_count} active exception(s)).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
