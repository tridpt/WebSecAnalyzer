"""Coordinate bounded crawling and passive security checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

from .cookies import check_cookies
from .api import (
    ApiCredential, check_api_access, check_api_auth_comparison,
    check_api_cross_account, check_api_headers, parse_api_credential,
    parse_api_targets, parse_comparison_fields, parse_openapi,
    validate_api_auth_transport, validate_openapi_path,
)
from .crawler import MAX_PAGES, crawl_pages, is_html
from .js_discovery import (
    BrowserDiscoveryUnavailable, JsLinkDiscoverer, MAX_SCRIPT_REQUESTS,
    MAX_SCRIPTS_PER_PAGE,
)
from .evidence import snapshot_response
from .browser_cors import (
    BrowserCorsVerifier, BrowserUnavailable, check_browser_cors,
    validate_browser_options,
)
from .fetch import RequestPacer, fetch, origin
from .findings import CheckResult, Severity, Verification
from .headers import check_headers
from .https_redirect import check_https_redirect
from .libraries import check_libraries
from .lockfiles import check_lockfile, parse_lockfile
from .network import DNSChanged, PinnedDNS, guarded_session
from .policies import (
    AUDIT_ORIGIN, check_cors, check_cors_credentialed, check_cors_preflight,
    check_csp,
)
from .control import ScanControl, ScanStopped
from .targets import InvalidTarget, is_loopback_host, normalize_target
from .tls import check_tls

USER_AGENT = "WebSecAnalyzer/0.2 (passive; owner-authorized use only)"
DEFAULT_MAX_PAGES = 20


@dataclass
class ScanReport:
    """A site report; child entries in pages are individual page reports."""

    url: str
    final_url: str
    status_code: int
    results: list[CheckResult] = field(default_factory=list)
    pages: list[ScanReport] = field(default_factory=list)
    api_endpoints: list[ScanReport] = field(default_factory=list)
    api_routes: list[dict] = field(default_factory=list)
    skipped_urls: int = 0
    max_pages: int = 1
    api_discovered: int = 0
    api_requested: int = 0
    api_selected_paths: list[str] = field(default_factory=list)
    api_skipped: int = 0
    api_skipped_paths: list[str] = field(default_factory=list)
    openapi_status: str = "not_requested"
    api_expect_auth: bool | None = None
    api_auth_status_code: int | None = None
    api_second_auth_status_code: int | None = None
    api_cors_preflight_status_code: int | None = None
    api_cors_credentialed_status_code: int | None = None
    api_cors_browser_outcome: str | None = None
    api_compared_pointers: list[str] = field(default_factory=list)
    api_auth_mode: str = "not_configured"
    api_auth_requested: int = 0
    api_auth_skipped_paths: list[str] = field(default_factory=list)
    api_compare_requested: int = 0
    api_compare_skipped_paths: list[str] = field(default_factory=list)
    api_cors_preflight_skipped_paths: list[str] = field(default_factory=list)
    api_cors_credentialed_skipped_paths: list[str] = field(default_factory=list)
    api_cors_browser_enabled: bool = False
    api_cors_browser_requested: int = 0
    api_cors_browser_skipped_paths: list[str] = field(default_factory=list)
    js_discovery_enabled: bool = False
    js_discovery_status: str = "not_requested"
    js_discovered_urls: int = 0
    js_discovery_error: str | None = None
    observations: list[dict] = field(default_factory=list)

    @property
    def issue_counts(self) -> dict[str, int]:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in self.results:
            for finding in result.findings:
                if finding.severity.name in counts:
                    counts[finding.severity.name] += 1
        for page in self.pages:
            for severity, count in page.issue_counts.items():
                counts[severity] += count
        for endpoint in self.api_endpoints:
            for severity, count in endpoint.issue_counts.items():
                counts[severity] += count
        return counts

    @property
    def checked_categories(self) -> int:
        return sum(result.error is None for result in self.results) + sum(
            page.checked_categories for page in self.pages
        ) + sum(endpoint.checked_categories for endpoint in self.api_endpoints)

    @property
    def total_categories(self) -> int:
        return (len(self.results)
                + sum(page.total_categories for page in self.pages)
                + sum(endpoint.total_categories for endpoint in self.api_endpoints))

    @staticmethod
    def _average_score(results: list[CheckResult]) -> int:
        scored = [result.score for result in results if result.error is None]
        return round(sum(scored) / len(scored)) if scored else 0

    def page_score(self, page: ScanReport) -> int:
        """Include website-wide checks in a page's displayed score."""
        return self._average_score(self.results + page.results)

    @property
    def overall_score(self) -> int:
        checked = self.pages + self.api_endpoints
        if checked:
            # The weakest checked HTML page or API endpoint determines the score.
            return min(self.page_score(page) for page in checked)
        return self._average_score(self.results)

    @classmethod
    def from_dict(cls, data: dict) -> ScanReport:
        """Restore current and legacy reports from stored JSON."""
        report = cls(
            url=data["url"],
            final_url=data["final_url"],
            status_code=data["status_code"],
            skipped_urls=data.get("skipped_urls", 0),
            max_pages=data.get("max_pages", 1),
            api_routes=data.get("api_routes", []),
            api_discovered=data.get("coverage", {}).get("api_routes_discovered", 0),
            api_requested=data.get("coverage", {}).get("api_endpoints_requested", 0),
            api_selected_paths=data.get("coverage", {}).get("api_selected_paths", []),
            api_skipped=data.get("coverage", {}).get("api_endpoints_skipped", 0),
            api_skipped_paths=data.get("coverage", {}).get("api_endpoints_skipped_paths", []),
            openapi_status=data.get("coverage", {}).get("openapi_status", "not_requested"),
            api_expect_auth=data.get("api_expect_auth"),
            api_auth_status_code=data.get("api_auth_status_code"),
            api_second_auth_status_code=data.get("api_second_auth_status_code"),
            api_cors_preflight_status_code=data.get("api_cors_preflight_status_code"),
            api_cors_credentialed_status_code=data.get("api_cors_credentialed_status_code"),
            api_cors_browser_outcome=data.get("api_cors_browser_outcome"),
            api_compared_pointers=data.get("api_compared_pointers", []),
            api_auth_mode=data.get("coverage", {}).get("api_auth_mode", "not_configured"),
            api_auth_requested=data.get("coverage", {}).get("api_authenticated_requested", 0),
            api_auth_skipped_paths=data.get("coverage", {}).get(
                "api_authenticated_skipped_paths", []
            ),
            api_compare_requested=data.get("coverage", {}).get(
                "api_cross_account_requested", 0
            ),
            api_compare_skipped_paths=data.get("coverage", {}).get(
                "api_cross_account_skipped_paths", []
            ),
            api_cors_preflight_skipped_paths=data.get("coverage", {}).get(
                "api_cors_preflight_skipped_paths", []
            ),
            api_cors_credentialed_skipped_paths=data.get("coverage", {}).get(
                "api_cors_credentialed_skipped_paths", []
            ),
            api_cors_browser_enabled=data.get("coverage", {}).get(
                "api_cors_browser_enabled", False
            ),
            api_cors_browser_requested=data.get("coverage", {}).get(
                "api_cors_browser_requested", 0
            ),
            api_cors_browser_skipped_paths=data.get("coverage", {}).get(
                "api_cors_browser_skipped_paths", []
            ),
            js_discovery_enabled=data.get("coverage", {}).get(
                "js_discovery_enabled", False
            ),
            js_discovery_status=data.get("coverage", {}).get(
                "js_discovery_status", "not_requested"
            ),
            js_discovered_urls=data.get("coverage", {}).get(
                "js_discovered_urls", 0
            ),
            js_discovery_error=data.get("coverage", {}).get("js_discovery_error"),
            observations=data.get("observations", []),
        )
        for cat in data.get("categories", []):
            result = CheckResult(category=cat["category"], error=cat.get("error"))
            for finding in cat.get("findings", []):
                result.add(
                    check=finding["check"],
                    title=finding["title"],
                    severity=Severity[finding["severity"]],
                    detail=finding["detail"],
                    recommendation=finding.get("recommendation", ""),
                    evidence=finding.get("evidence", ""),
                    verification=(
                        Verification(finding["verification"])
                        if "verification" in finding else None
                    ),
                )
            report.results.append(result)
        report.pages = [cls.from_dict(page) for page in data.get("pages", [])]
        report.api_endpoints = [
            cls.from_dict(endpoint) for endpoint in data.get("api_endpoints", [])
        ]
        if report.api_expect_auth is None:
            # Reports from earlier releases did not store this flag directly.
            for result in report.results:
                if result.category == "API Access":
                    for finding in result.findings:
                        if "yêu cầu xác thực=có" in finding.evidence:
                            report.api_expect_auth = True
                            break
                        if "yêu cầu xác thực=chưa xác định" in finding.evidence:
                            report.api_expect_auth = False
                            break
        return report


def scan(
    url: str,
    timeout: float = 15.0,
    use_osv: bool = True,
    *,
    allow_private: bool = False,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_seconds: float = 120.0,
    control: ScanControl | None = None,
    lockfile: tuple[str, bytes] | None = None,
    openapi_path: str | None = None,
    api_paths: list[str] | None = None,
    api_credential: ApiCredential | None = None,
    api_second_credential: ApiCredential | None = None,
    api_compare_fields: list[str] | None = None,
    browser_cors: bool = False,
    browser_cookie_attributes: str | None = None,
    js_discovery: bool = False,
) -> ScanReport:
    """Scan at most 30 HTML pages on the final URL's origin."""
    if not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise InvalidTarget(f"Số trang cần quét phải từ 1 đến {MAX_PAGES}.")
    if timeout <= 0:
        raise InvalidTarget("Thời gian chờ phải lớn hơn 0.")
    if not 1 <= max_seconds <= 600:
        raise InvalidTarget("Thời gian quét tối đa phải từ 1 đến 600 giây.")

    control = control or ScanControl(max_seconds=max_seconds)
    packages = parse_lockfile(*lockfile) if lockfile else None
    api_targets = parse_api_targets(api_paths)
    compare_fields = parse_comparison_fields(api_compare_fields, api_targets)
    openapi_path = validate_openapi_path(openapi_path)
    if api_credential is not None:
        if not isinstance(api_credential, ApiCredential) or not api_targets:
            raise InvalidTarget("Phiên thử nghiệm chỉ dùng khi đã chọn endpoint API GET.")
        api_credential = parse_api_credential(api_credential.mode, api_credential.secret)
    cookie_attributes = validate_browser_options(
        browser_cors, api_credential, browser_cookie_attributes,
    )
    if api_second_credential is not None:
        if not isinstance(api_second_credential, ApiCredential):
            raise InvalidTarget("Phiên tài khoản B không hợp lệ.")
        api_second_credential = parse_api_credential(
            api_second_credential.mode, api_second_credential.secret
        )
    if bool(compare_fields) != bool(api_second_credential) or (
        api_second_credential and not api_credential
    ):
        raise InvalidTarget(
            "So sánh hai tài khoản cần cả hai phiên và ít nhất một trường JSON đã chọn."
        )
    if api_second_credential == api_credential and api_second_credential is not None:
        raise InvalidTarget("Hai phiên thử nghiệm phải khác nhau.")

    secrets_to_redact = [
        credential.secret for credential in (api_credential, api_second_credential)
        if credential is not None
    ]

    def capture(response: requests.Response, **kwargs) -> dict:
        return snapshot_response(
            response, redact_values=secrets_to_redact, **kwargs,
        )

    dns = PinnedDNS(allow_private=allow_private, control=control)
    url = normalize_target(url, allow_private=allow_private, dns=dns)
    pacer = RequestPacer(
        max_requests=max_pages * 2 + 8 + len(api_targets) * (5 if api_credential else 3)
        + len(compare_fields)
        + (1 if openapi_path else 0)
        + (3 * len(api_targets) if browser_cors else 0)
        + (min(MAX_SCRIPT_REQUESTS, max_pages * MAX_SCRIPTS_PER_PAGE)
           if js_discovery else 0)
    )
    session = guarded_session(dns)
    session.headers["User-Agent"] = USER_AGENT
    session.trust_env = False
    try:
        first = fetch(
            session, url, timeout=timeout, allow_private=allow_private,
            pacer=pacer, initial_loopback=is_loopback_host(urlsplit(url).hostname),
            initial_host=urlsplit(url).hostname,
            control=control,
        )
        site_observations = [capture(first, purpose="site_root")]
        site_results = [
            check_tls(first.url, timeout=timeout, dns=dns, control=control),
            check_https_redirect(
                session, first.url, timeout=timeout,
                allow_private=allow_private, pacer=pacer,
                control=control, observations=site_observations,
                redact_values=secrets_to_redact,
            ),
        ]
        probe_response = None
        try:
            probe_response = fetch(
                session, first.url, timeout=timeout, allow_private=allow_private,
                pacer=pacer, expected_origin=origin(first.url),
                initial_loopback=is_loopback_host(urlsplit(first.url).hostname),
                control=control, request_headers={"Origin": AUDIT_ORIGIN},
            )
        except requests.RequestException:
            pass
        js_browser = None
        js_status = "not_requested"
        js_error = None
        if js_discovery:
            js_status = "completed" if is_html(first) else "unavailable"
            if is_html(first):
                js_browser = JsLinkDiscoverer(
                    dns=dns, pacer=pacer, control=control, timeout=timeout,
                    allow_private=allow_private, site_origin=origin(first.url),
                    user_agent=USER_AGENT,
                )
                try:
                    js_browser.start()
                except BrowserDiscoveryUnavailable as exc:
                    js_status = "unavailable"
                    js_error = str(exc)
                    js_browser = None

        def discover_rendered(response: requests.Response) -> list[str]:
            nonlocal js_status, js_error
            assert js_browser is not None
            try:
                return js_browser.discover(response)
            except BrowserDiscoveryUnavailable as exc:
                js_status = "partial"
                js_error = str(exc)
                return []

        try:
            page_responses, skipped, js_count = crawl_pages(
                session, url, first, max_pages=max_pages, timeout=timeout,
                allow_private=allow_private, pacer=pacer, control=control,
                discover_links=discover_rendered if js_browser else None,
            )
            if js_browser and js_browser.partial:
                js_status = "partial"
                js_error = js_error or "Một số tệp JavaScript không tải được trong giới hạn quét."
        finally:
            if js_browser:
                js_browser.close()
        if packages is not None:
            site_results.append(check_lockfile(
                lockfile[0], packages, use_osv=use_osv, control=control,
            ))
        advisory_cache: dict[tuple[str, str], list | None] = {}
        pages = []
        for index, (requested_url, response) in enumerate(page_responses):
            control.check()
            page_results = [
                check_headers(response),
                check_csp(response),
                check_cors(response, probe_response if index == 0 else None),
                check_cookies(response),
            ]
            if packages is None:
                page_results.append(check_libraries(
                    response, use_osv=use_osv,
                    advisory_cache=advisory_cache, control=control,
                ))
            pages.append(ScanReport(
                url=requested_url,
                final_url=response.url,
                status_code=response.status_code,
                results=page_results,
                observations=[
                    capture(response, purpose="page"),
                    *(
                        [capture(
                            probe_response, purpose="cors_probe",
                            request_headers={"Origin": AUDIT_ORIGIN},
                        )] if index == 0 and probe_response is not None else []
                    ),
                ],
            ))
        api_routes: list[dict] = []
        api_discovered = 0
        api_skipped = 0
        api_skipped_paths: list[str] = []
        openapi_status = "not_requested"
        api_endpoints: list[ScanReport] = []
        api_auth_requested = 0
        api_auth_skipped_paths: list[str] = []
        api_compare_skipped_paths: list[str] = []
        api_cors_preflight_skipped_paths: list[str] = []
        api_cors_credentialed_skipped_paths: list[str] = []
        api_cors_browser_skipped_paths: list[str] = []
        if openapi_path or api_targets:
            api_session = guarded_session(dns)
            api_session.headers["User-Agent"] = USER_AGENT
            auth_session = guarded_session(dns) if api_credential else None
            if auth_session:
                auth_session.headers["User-Agent"] = USER_AGENT
            second_session = guarded_session(dns) if api_second_credential else None
            if second_session:
                second_session.headers["User-Agent"] = USER_AGENT
            browser_verifier = None
            browser_unavailable = None
            try:
                site_origin = origin(first.url)
                loopback = is_loopback_host(urlsplit(first.url).hostname)
                if api_credential:
                    hostname = urlsplit(first.url).hostname or ""
                    validate_api_auth_transport(
                        first.url, dns.verify(hostname, site_origin[2])
                    )
                auth_paths: set[str] = set()
                if openapi_path:
                    openapi_status = "unavailable"
                    try:
                        spec_response = fetch(
                            api_session, urljoin(first.url, openapi_path),
                            timeout=timeout, allow_private=allow_private,
                            pacer=pacer, expected_origin=site_origin,
                            initial_loopback=loopback, control=control,
                        )
                        if spec_response.status_code == 200:
                            try:
                                api_routes, api_discovered, auth_paths = parse_openapi(
                                    spec_response.content,
                                    {target.path for target in api_targets},
                                )
                            except InvalidTarget:
                                openapi_status = "invalid"
                            else:
                                openapi_status = "loaded"
                        else:
                            openapi_status = f"http_{spec_response.status_code}"
                    except DNSChanged:
                        raise
                    except (InvalidTarget, requests.RequestException):
                        openapi_status = "unavailable"

                auth_target_paths = {
                    target.path for target in api_targets
                    if target.expect_auth or target.path in auth_paths
                } if api_credential else set()
                api_auth_requested = len(auth_target_paths)
                if browser_cors and auth_target_paths and api_credential:
                    browser_verifier = BrowserCorsVerifier(
                        dns=dns, pacer=pacer, control=control, timeout=timeout,
                        allow_private=allow_private, site_origin=site_origin,
                        initial_loopback=loopback, credential=api_credential,
                        cookie_attributes=cookie_attributes,
                    )
                    try:
                        browser_verifier.start(site_origin[0])
                    except BrowserUnavailable as exc:
                        browser_unavailable = str(exc)
                        browser_verifier = None
                for target in api_targets:
                    control.check()
                    endpoint_url = urljoin(first.url, target.path)
                    try:
                        api_session.cookies.clear()
                        response = fetch(
                            api_session, endpoint_url,
                            timeout=timeout, allow_private=allow_private,
                            pacer=pacer, expected_origin=site_origin,
                            initial_loopback=loopback, control=control,
                            read_body=False, follow_redirects=False,
                            request_headers={"Accept": "application/json"},
                        )
                    except DNSChanged:
                        raise
                    except (InvalidTarget, requests.RequestException):
                        api_skipped += 1
                        api_skipped_paths.append(target.path)
                        if target.path in auth_target_paths:
                            api_auth_skipped_paths.append(target.path)
                        if target.path in compare_fields:
                            api_compare_skipped_paths.append(target.path)
                        api_cors_preflight_skipped_paths.append(target.path)
                        if target.path in auth_target_paths:
                            api_cors_credentialed_skipped_paths.append(target.path)
                            if browser_cors:
                                api_cors_browser_skipped_paths.append(target.path)
                        continue
                    expected_auth = target.expect_auth or target.path in auth_paths
                    endpoint_observations = [capture(
                        response, purpose="api_anonymous",
                        request_headers={"Accept": "application/json"},
                    )]
                    api_session.cookies.clear()
                    try:
                        probe = fetch(
                            api_session, endpoint_url,
                            timeout=timeout, allow_private=allow_private,
                            pacer=pacer, expected_origin=site_origin,
                            initial_loopback=loopback, control=control,
                            read_body=False, follow_redirects=False,
                            request_headers={
                                "Accept": "application/json", "Origin": AUDIT_ORIGIN,
                            },
                        )
                        endpoint_observations.append(capture(
                            probe, purpose="api_cors_probe",
                            request_headers={
                                "Accept": "application/json", "Origin": AUDIT_ORIGIN,
                            },
                        ))
                        cors_result = check_cors(response, probe)
                    except DNSChanged:
                        raise
                    except (InvalidTarget, requests.RequestException):
                        cors_result = CheckResult(
                            category="CORS", error="Không thử được Origin lạ trên endpoint này."
                        )
                    endpoint_results = [
                        check_api_access(
                            response.status_code, target,
                            auth_declared=target.path in auth_paths,
                        ),
                        check_api_headers(response, expect_auth=expected_auth),
                        cors_result,
                    ]
                    preflight = None
                    preflight_status = None
                    requested_header = (
                        "authorization" if target.path in auth_target_paths
                        and api_credential and api_credential.mode == "bearer" else None
                    )
                    preflight_headers = {
                        "Origin": AUDIT_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    }
                    if requested_header:
                        preflight_headers["Access-Control-Request-Headers"] = requested_header
                    api_session.cookies.clear()
                    try:
                        preflight = fetch(
                            api_session, endpoint_url,
                            timeout=timeout, allow_private=allow_private,
                            pacer=pacer, expected_origin=site_origin,
                            initial_loopback=loopback, control=control,
                            method="OPTIONS", read_body=False, follow_redirects=False,
                            request_headers=preflight_headers,
                        )
                        preflight_status = preflight.status_code
                        endpoint_observations.append(capture(
                            preflight, purpose="api_preflight", method="OPTIONS",
                            request_headers=preflight_headers,
                        ))
                        endpoint_results.append(check_cors_preflight(
                            preflight, requested_header=requested_header,
                        ))
                    except DNSChanged:
                        raise
                    except (InvalidTarget, requests.RequestException):
                        api_cors_preflight_skipped_paths.append(target.path)
                        endpoint_results.append(CheckResult(
                            category="API CORS Preflight",
                            error="Không thử được OPTIONS trên endpoint này.",
                        ))
                    authenticated_status = None
                    credentialed_cors_status = None
                    browser_outcome = None
                    second_status = None
                    compared_pointers: list[str] = []
                    if target.path in auth_target_paths and auth_session and api_credential:
                        auth_session.cookies.clear()
                        try:
                            authenticated = fetch(
                                auth_session, endpoint_url,
                                timeout=timeout, allow_private=allow_private,
                                pacer=pacer, expected_origin=site_origin,
                                initial_loopback=loopback, control=control,
                                read_body=target.path in compare_fields,
                                follow_redirects=False,
                                request_headers=api_credential.headers(),
                            )
                            authenticated_status = authenticated.status_code
                            endpoint_observations.append(capture(
                                authenticated, purpose="api_authenticated",
                                credential_mode=api_credential.mode,
                            ))
                            endpoint_results.append(check_api_auth_comparison(
                                response.status_code, authenticated_status, target,
                            ))
                            if (
                                target.path in compare_fields
                                and second_session and api_second_credential
                            ):
                                second_session.cookies.clear()
                                try:
                                    second_response = fetch(
                                        second_session, endpoint_url,
                                        timeout=timeout, allow_private=allow_private,
                                        pacer=pacer, expected_origin=site_origin,
                                        initial_loopback=loopback, control=control,
                                        read_body=True, follow_redirects=False,
                                        request_headers=api_second_credential.headers(),
                                    )
                                    second_status = second_response.status_code
                                    endpoint_observations.append(capture(
                                        second_response, purpose="api_second_account",
                                        credential_mode=api_second_credential.mode,
                                    ))
                                    comparison, compared_pointers = check_api_cross_account(
                                        authenticated, second_response, target,
                                        compare_fields[target.path],
                                    )
                                    endpoint_results.append(comparison)
                                    if len(compared_pointers) < len(compare_fields[target.path]):
                                        api_compare_skipped_paths.append(target.path)
                                except DNSChanged:
                                    raise
                                except (InvalidTarget, requests.RequestException):
                                    api_compare_skipped_paths.append(target.path)
                                    endpoint_results.append(CheckResult(
                                        category="API Cross-Account Comparison",
                                        error="Không thử được tài khoản B trên endpoint này.",
                                    ))
                        except DNSChanged:
                            raise
                        except (InvalidTarget, requests.RequestException):
                            api_auth_skipped_paths.append(target.path)
                            if target.path in compare_fields:
                                api_compare_skipped_paths.append(target.path)
                                endpoint_results.append(CheckResult(
                                    category="API Cross-Account Comparison",
                                    error="Không thử được tài khoản A trên endpoint này.",
                                ))
                            endpoint_results.append(CheckResult(
                                category="API Authentication Comparison",
                                error="Không thử được phiên tài khoản trên endpoint này.",
                            ))
                    if target.path in auth_target_paths and auth_session and api_credential:
                        auth_session.cookies.clear()
                        try:
                            credentialed_probe = fetch(
                                auth_session, endpoint_url,
                                timeout=timeout, allow_private=allow_private,
                                pacer=pacer, expected_origin=site_origin,
                                initial_loopback=loopback, control=control,
                                read_body=False, follow_redirects=False,
                                request_headers={
                                    **api_credential.headers(), "Origin": AUDIT_ORIGIN,
                                },
                            )
                            credentialed_cors_status = credentialed_probe.status_code
                            endpoint_observations.append(capture(
                                credentialed_probe, purpose="api_credentialed_cors",
                                credential_mode=api_credential.mode,
                                request_headers={"Origin": AUDIT_ORIGIN},
                            ))
                            endpoint_results.append(check_cors_credentialed(
                                credentialed_probe, mode=api_credential.mode,
                                preflight=preflight,
                            ))
                        except DNSChanged:
                            raise
                        except (InvalidTarget, requests.RequestException):
                            api_cors_credentialed_skipped_paths.append(target.path)
                            endpoint_results.append(CheckResult(
                                category="API CORS Credentialed",
                                error="Không thử được Origin lạ với phiên tài khoản trên endpoint này.",
                            ))
                    if target.path in auth_target_paths and browser_cors:
                        if browser_unavailable or browser_verifier is None:
                            endpoint_results.append(CheckResult(
                                category="API CORS Browser",
                                error=browser_unavailable or "Trình duyệt chưa sẵn sàng.",
                            ))
                            browser_outcome = "inconclusive"
                        else:
                            try:
                                observation = browser_verifier.verify(endpoint_url)
                                browser_result, browser_outcome = check_browser_cors(observation)
                                endpoint_results.append(browser_result)
                            except (DNSChanged, ScanStopped):
                                raise
                            except BrowserUnavailable as exc:
                                browser_outcome = "inconclusive"
                                endpoint_results.append(CheckResult(
                                    category="API CORS Browser", error=str(exc),
                                ))
                        if browser_outcome == "inconclusive":
                            api_cors_browser_skipped_paths.append(target.path)
                    api_endpoints.append(ScanReport(
                        url=endpoint_url, final_url=response.url,
                        status_code=response.status_code,
                        api_expect_auth=expected_auth,
                        api_auth_status_code=authenticated_status,
                        api_second_auth_status_code=second_status,
                        api_cors_preflight_status_code=preflight_status,
                        api_cors_credentialed_status_code=credentialed_cors_status,
                        api_cors_browser_outcome=browser_outcome,
                        api_compared_pointers=compared_pointers,
                        results=endpoint_results,
                        observations=endpoint_observations,
                    ))
            finally:
                if browser_verifier:
                    browser_verifier.close()
                api_session.close()
                if auth_session:
                    auth_session.close()
                if second_session:
                    second_session.close()
        control.check()
        return ScanReport(
            url=url,
            final_url=first.url,
            status_code=first.status_code,
            results=site_results,
            pages=pages,
            api_endpoints=api_endpoints,
            api_routes=api_routes,
            skipped_urls=skipped,
            max_pages=max_pages,
            api_discovered=api_discovered,
            api_requested=len(api_targets),
            api_selected_paths=[target.path for target in api_targets],
            api_skipped=api_skipped,
            api_skipped_paths=api_skipped_paths,
            openapi_status=openapi_status,
            api_auth_mode=api_credential.mode if api_credential else "not_configured",
            api_auth_requested=api_auth_requested,
            api_auth_skipped_paths=api_auth_skipped_paths,
            api_compare_requested=len(compare_fields),
            api_compare_skipped_paths=api_compare_skipped_paths,
            api_cors_preflight_skipped_paths=api_cors_preflight_skipped_paths,
            api_cors_credentialed_skipped_paths=api_cors_credentialed_skipped_paths,
            api_cors_browser_enabled=browser_cors,
            api_cors_browser_requested=api_auth_requested if browser_cors else 0,
            api_cors_browser_skipped_paths=api_cors_browser_skipped_paths,
            js_discovery_enabled=js_discovery,
            js_discovery_status=js_status,
            js_discovered_urls=js_count,
            js_discovery_error=js_error,
            observations=site_observations,
        )
    finally:
        session.close()
