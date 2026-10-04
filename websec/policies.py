"""Focused CSP and CORS checks with response-header evidence."""

from __future__ import annotations

import re
import requests

from .findings import CheckResult, Severity, Verification

AUDIT_ORIGIN = "https://websec-audit.invalid"


def _evidence(name: str, value: str | None) -> str:
    safe = re.sub(r"'nonce-[^']+'", "'nonce-<đã ẩn>'", value or "[không có]", flags=re.I)
    return f"{name}: {safe[:350]}"


def check_csp(response: requests.Response) -> CheckResult:
    result = CheckResult(category="Content Security Policy")
    policy = response.headers.get("Content-Security-Policy", "")
    report_only = response.headers.get("Content-Security-Policy-Report-Only", "")
    if not policy:
        result.add(
            "csp-missing", "Thiếu CSP có hiệu lực", Severity.HIGH,
            "Trình duyệt không nhận chính sách giới hạn nguồn script và tài nguyên.",
            "Thêm Content-Security-Policy; bắt đầu với default-src 'self', "
            "rồi mở chính xác nguồn ứng dụng cần.",
            _evidence("Content-Security-Policy", None)
            + ("; " + _evidence("Content-Security-Policy-Report-Only", report_only)
               if report_only else ""),
        )
        return result

    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    script = directives.get("script-src", directives.get("default-src", []))
    script_text = " ".join(script).lower()
    has_nonce_or_hash = any(
        source.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
        for source in script
    )
    evidence = _evidence("Content-Security-Policy", policy)

    if not script:
        result.add(
            "csp-script", "CSP không giới hạn nguồn script", Severity.HIGH,
            "Thiếu script-src và default-src nên script có thể tải từ nhiều nguồn.",
            "Thêm script-src 'self' hoặc danh sách nguồn script cần thiết.", evidence,
        )
    if "'unsafe-inline'" in script_text:
        result.add(
            "csp-inline", "CSP chứa unsafe-inline",
            Severity.LOW if has_nonce_or_hash else Severity.MEDIUM,
            "unsafe-inline làm yếu bảo vệ trước XSS; trình duyệt hiện đại bỏ qua nó "
            "khi có nonce/hash hợp lệ." if has_nonce_or_hash else
            "unsafe-inline làm yếu bảo vệ trước XSS.",
            "Dùng nonce hoặc hash cho script nội tuyến và bỏ unsafe-inline.", evidence,
        )
    if "'unsafe-eval'" in script_text:
        result.add(
            "csp-eval", "CSP cho phép eval", Severity.MEDIUM,
            "unsafe-eval cho phép thực thi chuỗi JavaScript.",
            "Bỏ unsafe-eval sau khi thay các thư viện hoặc đoạn mã phụ thuộc eval.", evidence,
        )
    if "*" in script:
        result.add(
            "csp-wildcard", "Nguồn script quá rộng", Severity.MEDIUM,
            "Wildcard trong script-src/default-src cho phép nhiều nguồn không xác định.",
            "Liệt kê chính xác các host cần tải script.", evidence,
        )
    if "http:" in script:
        result.add(
            "csp-http-script", "CSP cho phép script từ HTTP", Severity.MEDIUM,
            "Nguồn script qua HTTP có thể bị thay đổi trên đường truyền.",
            "Bỏ http: khỏi script-src/default-src và dùng nguồn HTTPS cụ thể.", evidence,
        )
    if "object-src" not in directives and directives.get("default-src") != ["'none'"]:
        result.add(
            "csp-object", "CSP chưa giới hạn object-src", Severity.LOW,
            "Các tài nguyên plugin có thể chưa được chặn rõ ràng.",
            "Thêm object-src 'none' nếu không dùng plugin.", evidence,
        )
    if "base-uri" not in directives:
        result.add(
            "csp-base", "CSP chưa giới hạn base-uri", Severity.LOW,
            "Thẻ base có thể thay đổi cách trình duyệt giải các URL tương đối.",
            "Thêm base-uri 'self' hoặc 'none'.", evidence,
        )
    if not result.findings:
        result.add(
            "csp-ok", "CSP có các ràng buộc cơ bản", Severity.INFO,
            "Không thấy chỉ thị CSP yếu trong các quy tắc được kiểm tra.",
            evidence=evidence,
        )
    return result


def check_cors(
    response: requests.Response,
    probe_response: requests.Response | None = None,
) -> CheckResult:
    result = CheckResult(category="CORS")
    probe_origin = (
        probe_response.headers.get("Access-Control-Allow-Origin", "")
        if probe_response is not None else ""
    )
    allow_origin = probe_origin or response.headers.get("Access-Control-Allow-Origin", "")
    credentials = (
        (probe_response.headers.get("Access-Control-Allow-Credentials", "")
         if probe_response is not None else "")
        or response.headers.get("Access-Control-Allow-Credentials", "")
    )
    vary = (
        (probe_response.headers.get("Vary", "") if probe_response is not None else "")
        or response.headers.get("Vary", "")
    )
    evidence_parts = [
        _evidence("Request Origin", AUDIT_ORIGIN)
    ] if probe_response is not None else []
    evidence = "; ".join(evidence_parts + [
        _evidence("Access-Control-Allow-Origin", allow_origin),
        _evidence("Access-Control-Allow-Credentials", credentials),
        _evidence("Vary", vary),
    ])

    if allow_origin.lower() == "null" and credentials.lower() == "true":
        result.add(
            "cors-null-credentials", "CORS cho phép origin null với thông tin đăng nhập",
            Severity.MEDIUM,
            "Trang có thể cho phép các ngữ cảnh origin null đọc phản hồi có cookie.",
            "Bỏ origin null; dùng allowlist origin cụ thể và xác minh mỗi yêu cầu.",
            evidence,
        )
    elif allow_origin == "*":
        severity = Severity.LOW if credentials.lower() == "true" else Severity.INFO
        result.add(
            "cors-wildcard", "CORS cho phép mọi origin", severity,
            "Origin thử nghiệm được phép đọc phản hồi này từ website khác. "
            "Nếu đây là API có dữ liệu riêng, cần xác thực và giới hạn Origin. "
            "Trình duyệt sẽ từ chối wildcard kết hợp credentials.",
            "Chỉ giữ '*' cho tài nguyên công khai; dùng allowlist cho API dữ liệu riêng "
            "và không dùng '*' cùng credentials.", evidence,
        )
    if probe_response is not None:
        probe_credentials = probe_response.headers.get(
            "Access-Control-Allow-Credentials", ""
        )
        probe_vary = probe_response.headers.get("Vary", "")
        if probe_origin == AUDIT_ORIGIN:
            result.add(
                "cors-reflection", "Máy chủ phản chiếu Origin tùy ý", Severity.MEDIUM,
                "Origin thử nghiệm không thuộc website vẫn được chấp nhận. "
                "Cần kiểm tra thêm phản hồi có phiên trước khi kết luận dữ liệu riêng có thể bị đọc.",
                "Đối chiếu Origin với allowlist chính xác; chỉ bật credentials "
                "cho origin tin cậy.",
                "; ".join([
                    _evidence("Request Origin", AUDIT_ORIGIN),
                    _evidence("Access-Control-Allow-Origin", probe_origin),
                    _evidence("Access-Control-Allow-Credentials", probe_credentials),
                ]),
            )
            if "origin" not in probe_vary.lower():
                result.add(
                    "cors-vary", "CORS thiếu Vary: Origin", Severity.LOW,
                    "Phản hồi thay đổi theo Origin nhưng cache có thể dùng lại header cũ.",
                    "Thêm Vary: Origin cho phản hồi CORS động.",
                    "; ".join([
                        _evidence("Access-Control-Allow-Origin", probe_origin),
                        _evidence("Vary", probe_vary),
                    ]),
                )

    if not result.findings:
        result.add(
            "cors-observed", "Không thấy cấu hình CORS rủi ro trong phản hồi",
            Severity.INFO,
            "Kiểm tra chỉ dựa trên URL này"
            + (" và một Origin thử nghiệm." if probe_response is not None else "."),
            evidence=evidence,
        )
    return result


def _header_tokens(value: str) -> set[str]:
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def preflight_allows(
    response: requests.Response, *, requested_header: str | None = None,
    credentialed: bool = False,
) -> bool:
    """Apply browser CORS rules relevant to this bounded GET probe."""
    if not 200 <= response.status_code < 300:
        return False
    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    allow_methods = _header_tokens(response.headers.get("Access-Control-Allow-Methods", ""))
    allow_headers = _header_tokens(response.headers.get("Access-Control-Allow-Headers", ""))
    origin_ok = allow_origin == AUDIT_ORIGIN or (
        not credentialed and allow_origin == "*"
    )
    method_ok = "get" in allow_methods or (not credentialed and "*" in allow_methods)
    header_ok = (
        not requested_header or requested_header.lower() in allow_headers
        or (not credentialed and "*" in allow_headers)
    )
    credentials_ok = (
        not credentialed
        or response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    )
    return origin_ok and method_ok and header_ok and credentials_ok


def check_cors_preflight(
    response: requests.Response, *, requested_header: str | None = None,
) -> CheckResult:
    """Report a header-only OPTIONS preflight without claiming data exposure."""
    result = CheckResult(category="API CORS Preflight")
    evidence = "; ".join([
        f"OPTIONS HTTP {response.status_code}",
        _evidence("Request Origin", AUDIT_ORIGIN),
        _evidence("Access-Control-Request-Method", "GET"),
        _evidence("Access-Control-Request-Headers", requested_header),
        _evidence("Access-Control-Allow-Origin", response.headers.get("Access-Control-Allow-Origin")),
        _evidence("Access-Control-Allow-Methods", response.headers.get("Access-Control-Allow-Methods")),
        _evidence("Access-Control-Allow-Headers", response.headers.get("Access-Control-Allow-Headers")),
        _evidence("Access-Control-Allow-Credentials", response.headers.get("Access-Control-Allow-Credentials")),
        _evidence("Vary", response.headers.get("Vary")),
    ])
    if preflight_allows(response, requested_header=requested_header):
        result.add(
            "cors-preflight-allows", "Preflight cho phép GET từ Origin thử nghiệm",
            Severity.INFO,
            "Phản hồi OPTIONS cho phép GET theo các header đã yêu cầu; "
            "cần đối chiếu thêm phản hồi GET có phiên để đánh giá rủi ro dữ liệu.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
    elif response.status_code in {301, 302, 303, 307, 308} or response.status_code >= 500:
        result.add(
            "cors-preflight-inconclusive", "Preflight chưa kết luận được",
            Severity.INFO,
            "OPTIONS chuyển hướng hoặc lỗi; trình duyệt có thể không hoàn tất preflight.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
    else:
        result.add(
            "cors-preflight-denied", "Preflight không cho phép yêu cầu GET đã thử",
            Severity.INFO,
            "Thiếu hoặc không khớp Origin, phương thức GET, hoặc header được yêu cầu. "
            "Điều này không chứng minh tất cả Origin đều bị chặn.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
    vary = _header_tokens(response.headers.get("Vary", ""))
    if (
        response.headers.get("Access-Control-Allow-Origin") == AUDIT_ORIGIN
        and "origin" not in vary and "*" not in vary
    ):
        result.add(
            "cors-preflight-vary", "Preflight thiếu Vary: Origin", Severity.LOW,
            "Phản hồi OPTIONS thay đổi theo Origin có thể bị cache dùng lại sai.",
            "Thêm Vary: Origin vào phản hồi preflight động.", evidence,
        )
    return result


def check_cors_credentialed(
    response: requests.Response, *, mode: str,
    preflight: requests.Response | None = None,
) -> CheckResult:
    """Assess one explicit private GET with a test session and foreign Origin."""
    result = CheckResult(category="API CORS Credentialed")
    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    credentials = response.headers.get("Access-Control-Allow-Credentials", "")
    # The server has seen a test secret. Keep only the header facts required for
    # the finding; arbitrary echoed response-header values must not enter JSON.
    origin_evidence = (
        allow_origin if allow_origin in {AUDIT_ORIGIN, "*", "null"}
        else "[khác Origin thử nghiệm]" if allow_origin else "[không có]"
    )
    credentials_evidence = (
        credentials if credentials.lower() in {"true", "false"}
        else "[giá trị khác]" if credentials else "[không có]"
    )
    vary = _header_tokens(response.headers.get("Vary", ""))
    evidence = "; ".join([
        f"GET với phiên {mode} HTTP {response.status_code}",
        _evidence("Request Origin", AUDIT_ORIGIN),
        _evidence("Access-Control-Allow-Origin", origin_evidence),
        _evidence("Access-Control-Allow-Credentials", credentials_evidence),
        _evidence("Vary", "Origin" if "origin" in vary else "[không có Origin]"),
    ])
    if not 200 <= response.status_code < 300:
        result.add(
            "cors-credentialed-inconclusive", "GET có phiên chưa trả HTTP 2xx",
            Severity.INFO,
            "Không thể kết luận Origin lạ đọc được phản hồi riêng từ mã trạng thái này.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
    elif allow_origin != AUDIT_ORIGIN or credentials.lower() != "true":
        result.add(
            "cors-credentialed-blocked", "Header không cho phép trình duyệt đọc phản hồi có phiên",
            Severity.INFO,
            "Origin không khớp hoặc thiếu Access-Control-Allow-Credentials: true. "
            "Trình duyệt sẽ chặn đọc phản hồi này ở Origin thử nghiệm.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
    elif mode == "bearer" and (
        preflight is None
        or preflight.status_code in {301, 302, 303, 307, 308}
        or preflight.status_code >= 500
    ):
        result.add(
            "cors-credentialed-preflight-inconclusive", "Preflight chưa kết luận được",
            Severity.INFO,
            "Không có phản hồi OPTIONS hoặc OPTIONS chuyển hướng/lỗi; "
            "chưa xác nhận trình duyệt có thể gửi Authorization từ Origin thử nghiệm.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
    elif mode == "bearer" and not preflight_allows(
        preflight, requested_header="authorization", credentialed=True,
    ):
        result.add(
            "cors-credentialed-preflight-blocked", "Preflight chưa cho phép Authorization",
            Severity.INFO,
            "GET trực tiếp có header CORS nhưng preflight không cho phép yêu cầu "
            "Authorization có credentials từ Origin thử nghiệm.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
    elif mode == "bearer":
        result.add(
            "cors-bearer-cross-origin", "CORS cho phép GET mang Bearer từ Origin thử nghiệm",
            Severity.MEDIUM,
            "Preflight và GET cho phép Origin lạ dùng Authorization. "
            "Origin đó vẫn cần có Bearer token; đây chưa phải bằng chứng lộ token.",
            "Giới hạn Origin được phép và chỉ chấp nhận Bearer token tại ứng dụng tin cậy.",
            evidence, verification=Verification.SUSPECTED,
        )
    else:
        result.add(
            "cors-cookie-cross-origin", "Origin lạ có thể đọc phản hồi GET có Cookie",
            Severity.HIGH,
            "GET của endpoint riêng tư nhận Cookie và trả HTTP 2xx cùng header CORS "
            "cho phép Origin thử nghiệm đọc phản hồi có credentials. "
            "Cần xác minh SameSite và hành vi trình duyệt thực tế.",
            "Chỉ cho phép Origin tin cậy bằng allowlist chính xác; bỏ "
            "Access-Control-Allow-Credentials cho Origin không tin cậy và xem lại SameSite.",
            evidence, verification=Verification.SUSPECTED,
        )
    return result
