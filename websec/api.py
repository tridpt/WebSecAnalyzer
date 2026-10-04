"""Optional, bounded API discovery and owner-selected header-only GET probes."""

from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from .findings import CheckResult, Severity, Verification
from .targets import InvalidTarget, is_loopback_host

MAX_API_ENDPOINTS = 10
MAX_OPENAPI_ROUTES = 100
MAX_COMPARE_FIELDS = 20
_STATE_CHANGING_SEGMENTS = {
    "delete", "remove", "logout", "signout", "unsubscribe", "destroy",
}
_HTTP_METHODS = {"get", "head", "post", "put", "patch", "delete", "options"}


@dataclass(frozen=True)
class ApiTarget:
    path: str
    expect_auth: bool = False


@dataclass(frozen=True)
class ApiCredential:
    """A temporary test-session header; the secret must never enter a report."""

    mode: str
    secret: str = field(repr=False)

    def headers(self) -> dict[str, str]:
        if self.mode == "cookie":
            return {"Accept": "application/json", "Cookie": self.secret}
        return {"Accept": "application/json", "Authorization": f"Bearer {self.secret}"}


def parse_api_credential(mode: str | None, secret: str | None) -> ApiCredential | None:
    """Only accept a Cookie value or Bearer token for explicit same-origin GETs."""
    mode = (mode or "none").strip().lower()
    value = (secret or "").strip()
    if mode == "none":
        if value:
            raise InvalidTarget("Chọn loại phiên thử nghiệm trước khi nhập thông tin xác thực.")
        return None
    if mode not in {"cookie", "bearer"}:
        raise InvalidTarget("Chỉ hỗ trợ Cookie hoặc Bearer token của tài khoản thử nghiệm.")
    if (
        not value or len(value) > 4096
        or any(not 32 <= ord(char) <= 126 for char in value)
    ):
        raise InvalidTarget("Thông tin phiên thử nghiệm trống, quá dài hoặc chứa ký tự không hợp lệ.")
    if mode == "cookie":
        if value.lower().startswith("cookie:") or "=" not in value:
            raise InvalidTarget("Chỉ nhập giá trị Cookie, ví dụ session=..., không nhập tên header.")
    else:
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        if not value or any(char.isspace() for char in value):
            raise InvalidTarget("Bearer token phải là một chuỗi không chứa khoảng trắng.")
    return ApiCredential(mode, value)


def validate_api_auth_transport(url: str, resolved_ip: str) -> None:
    """Never send a test session over cleartext beyond the local machine."""
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return
    if (
        parsed.scheme != "http"
        or not is_loopback_host(parsed.hostname)
        or not ipaddress.ip_address(resolved_ip).is_loopback
    ):
        raise InvalidTarget(
            "Phiên thử nghiệm cần HTTPS; HTTP chỉ được dùng với localhost/loopback."
        )


def _safe_path(raw: str) -> str:
    value = raw.strip()
    if (
        not value.startswith("/") or value.startswith("//")
        or len(value) > 500 or any(ord(char) < 33 for char in value)
        or "\\" in value or "{" in value or "}" in value
    ):
        raise InvalidTarget("API endpoint phải là path cùng website, không có tham số mẫu.")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise InvalidTarget("API endpoint không được chứa tên miền, query hoặc fragment.")
    decoded = parsed.path
    for _ in range(3):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    if (
        any(char in decoded for char in ("?", "#", "\\"))
        or "//" in decoded
        or any(char.isspace() or ord(char) < 33 for char in decoded)
    ):
        raise InvalidTarget("API endpoint chứa ký tự mã hóa không an toàn.")
    segments = set(decoded.lower().split("/"))
    if segments & (_STATE_CHANGING_SEGMENTS | {".", ".."}):
        raise InvalidTarget("Không quét endpoint có đường dẫn thường dùng để đổi trạng thái.")
    return value


def parse_api_targets(lines: list[str] | None) -> list[ApiTarget]:
    """Accept /path or 'private /path' (expected to require authentication)."""
    if lines is not None and len(lines) > 100:
        raise InvalidTarget("Danh sách API quá dài.")
    targets: dict[str, ApiTarget] = {}
    for raw in lines or []:
        if not raw.strip():
            continue
        value = raw.strip()
        expect_auth = value.lower().startswith("private ")
        if expect_auth:
            value = value[8:].strip()
        path = _safe_path(value)
        previous = targets.get(path)
        targets[path] = ApiTarget(path, expect_auth or (previous.expect_auth if previous else False))
        if len(targets) > MAX_API_ENDPOINTS:
            raise InvalidTarget(f"Chỉ quét tối đa {MAX_API_ENDPOINTS} API endpoint mỗi lượt.")
    return list(targets.values())


def parse_comparison_fields(
    lines: list[str] | None, targets: list[ApiTarget],
) -> dict[str, list[str]]:
    """Select JSON pointers expected to differ between two test accounts."""
    if lines is not None and len(lines) > 100:
        raise InvalidTarget("Danh sách trường so sánh quá dài.")
    private_paths = {target.path for target in targets if target.expect_auth}
    selected: dict[str, list[str]] = {}
    for raw in lines or []:
        if not raw.strip():
            continue
        if len(raw) > 750:
            raise InvalidTarget("Dòng so sánh JSON quá dài.")
        parts = raw.strip().split()
        if len(parts) != 2:
            raise InvalidTarget("Mỗi dòng so sánh phải có path API và JSON Pointer.")
        path, pointer = parts
        path = _safe_path(path)
        if path not in private_paths:
            raise InvalidTarget(
                "Chỉ so sánh trường của endpoint GET đã chọn với tiền tố private."
            )
        if (
            len(pointer) > 200 or not pointer.startswith("/")
            or any(not segment for segment in pointer.split("/")[1:])
            or re.search(r"~(?![01])", pointer)
        ):
            raise InvalidTarget("JSON Pointer không hợp lệ; ví dụ /user/id.")
        pointers = selected.setdefault(path, [])
        if pointer not in pointers:
            pointers.append(pointer)
        if sum(len(items) for items in selected.values()) > MAX_COMPARE_FIELDS:
            raise InvalidTarget(
                f"Chỉ so sánh tối đa {MAX_COMPARE_FIELDS} trường JSON mỗi lượt."
            )
    return selected


def validate_openapi_path(path: str | None) -> str | None:
    return _safe_path(path) if path else None


def _matches_route(route: str, path: str) -> bool:
    """Match a selected concrete path to a same-length OpenAPI path template."""
    route_parts, path_parts = route.split("/"), path.split("/")
    return len(route_parts) == len(path_parts) and all(
        (part.startswith("{") and part.endswith("}") and bool(actual))
        or part == actual
        for part, actual in zip(route_parts, path_parts)
    )


def _requires_auth(security: object) -> bool:
    """OpenAPI permits anonymous access when any security alternative is empty."""
    return (
        isinstance(security, list) and bool(security)
        and all(isinstance(requirement, dict) and bool(requirement) for requirement in security)
    )


def _openapi_document(content: bytes) -> dict:
    try:
        data = json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise InvalidTarget("OpenAPI không phải JSON hợp lệ.") from exc
    if (
        not isinstance(data, dict) or not isinstance(data.get("paths"), dict)
        or not (
            isinstance(data.get("openapi"), str) and data["openapi"].startswith("3.")
            or data.get("swagger") == "2.0"
        )
    ):
        raise InvalidTarget("Tài liệu không phải OpenAPI 3.x hoặc Swagger 2.0 hợp lệ.")
    return data


def selectable_get_routes(content: bytes) -> tuple[list[dict], int, int]:
    """Offer bounded, safe GET templates for explicit owner selection."""
    data = _openapi_document(content)
    routes: list[dict] = []
    total_get = 0
    eligible_get = 0
    for path, item in data["paths"].items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        operation = next(
            (value for method, value in item.items()
             if isinstance(method, str) and method.lower() == "get" and isinstance(value, dict)),
            None,
        )
        if operation is None:
            continue
        total_get += 1
        declared_parameters = []
        for source in (item.get("parameters"), operation.get("parameters")):
            if isinstance(source, list):
                declared_parameters.extend(source)
        if operation.get("requestBody") or any(
            not isinstance(parameter, dict)
            or "$ref" in parameter
            or (parameter.get("in") == "query" and parameter.get("required") is True)
            for parameter in declared_parameters
        ):
            continue
        if len(path) > 500 or not path.startswith("/") or path.startswith("//"):
            continue
        parameters: list[str] = []
        concrete_parts: list[str] = []
        valid = True
        for segment in path.split("/")[1:]:
            if segment.startswith("{") and segment.endswith("}"):
                name = segment[1:-1]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", name):
                    valid = False
                    break
                parameters.append(name)
                concrete_parts.append("sample")
            elif "{" in segment or "}" in segment:
                valid = False
                break
            else:
                concrete_parts.append(segment)
        if not valid:
            continue
        try:
            _safe_path("/" + "/".join(concrete_parts))
        except InvalidTarget:
            continue
        eligible_get += 1
        if len(routes) < MAX_OPENAPI_ROUTES:
            routes.append({
                "method": "GET", "path": path,
                "auth_declared": _requires_auth(
                    operation.get("security", data.get("security"))
                ),
                "parameters": parameters,
            })
    return routes, total_get, eligible_get


def parse_openapi(
    content: bytes, selected_paths: set[str] | None = None,
) -> tuple[list[dict], int, set[str]]:
    """List operations and auth expectations; never call discovered routes."""
    data = _openapi_document(content)
    global_security = data.get("security")
    routes: list[dict] = []
    total = 0
    auth_matches: dict[str, tuple[int, bool]] = {}
    selected_paths = selected_paths or set()
    for path, item in data["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            total += 1
            security = operation.get("security", global_security)
            if method.lower() == "get" and selected_paths:
                specificity = sum(
                    not (part.startswith("{") and part.endswith("}"))
                    for part in path.split("/")
                )
                for selected in selected_paths:
                    if _matches_route(path, selected):
                        previous = auth_matches.get(selected)
                        if previous is None or specificity > previous[0]:
                            auth_matches[selected] = (specificity, _requires_auth(security))
                        elif specificity == previous[0]:
                            auth_matches[selected] = (
                                specificity, previous[1] or _requires_auth(security)
                            )
            if len(routes) < MAX_OPENAPI_ROUTES:
                routes.append({
                    "method": method.upper(),
                    "path": path[:500],
                    "auth_declared": _requires_auth(security),
                })
    auth_paths = {path for path, (_, expected) in auth_matches.items() if expected}
    return routes, total, auth_paths


def check_api_access(
    status_code: int, target: ApiTarget, *, auth_declared: bool = False,
) -> CheckResult:
    result = CheckResult(category="API Access")
    expected = target.expect_auth or auth_declared
    evidence = (
        f"GET {target.path} → HTTP {status_code}; "
        f"không gửi Cookie/Authorization; "
        f"yêu cầu xác thực={'có' if expected else 'chưa xác định'}"
    )
    if 200 <= status_code < 300 and expected:
        result.add(
            "api-auth-missing", "API dự kiến cần xác thực nhưng trả HTTP 2xx khi chưa đăng nhập",
            Severity.HIGH,
            "Endpoint trả HTTP 2xx khi yêu cầu không mang cookie hoặc Authorization. "
            "Đây là dấu hiệu cần xác minh, vì công cụ chỉ đọc header và không xem nội dung phản hồi.",
            "Yêu cầu xác thực và phân quyền trước khi trả dữ liệu; kiểm tra lại bằng tài khoản chưa đăng nhập.",
            evidence,
        )
    elif status_code in {401, 403}:
        result.add(
            "api-auth-denied", "API từ chối yêu cầu chưa đăng nhập", Severity.INFO,
            "Endpoint trả 401/403 khi không có thông tin đăng nhập.", evidence=evidence,
        )
    elif 200 <= status_code < 300:
        result.add(
            "api-auth-review", "API trả HTTP 2xx không cần đăng nhập", Severity.INFO,
            "Có thể là API công khai. Nếu trả dữ liệu riêng, hãy đánh dấu endpoint là private và quét lại.",
            "Thêm 'private ' trước path trong danh sách API nếu endpoint phải yêu cầu đăng nhập.",
            evidence,
        )
    else:
        result.add(
            "api-auth-inconclusive", "Chưa kết luận được xác thực API", Severity.INFO,
            f"Endpoint trả HTTP {status_code}; chuyển hướng/lỗi có thể cần kiểm tra thủ công.",
            evidence=evidence,
        )
    return result


def check_api_headers(response, *, expect_auth: bool) -> CheckResult:
    result = CheckResult(category="API Response Headers")
    nosniff = response.headers.get("X-Content-Type-Options", "")
    cache = response.headers.get("Cache-Control", "")
    content_type = response.headers.get("Content-Type", "")
    evidence = (
        f"Content-Type: {content_type[:100] or '[không có]'}; "
        f"X-Content-Type-Options: {nosniff[:60] or '[không có]'}; "
        f"Cache-Control: {cache[:100] or '[không có]'}"
    )
    if nosniff.lower() != "nosniff":
        result.add(
            "api-nosniff", "API thiếu X-Content-Type-Options: nosniff", Severity.LOW,
            "Trình duyệt có thể đoán kiểu nội dung khác với Content-Type khai báo.",
            "Thêm X-Content-Type-Options: nosniff cho phản hồi API.", evidence,
        )
    if expect_auth and 200 <= response.status_code < 300 and "no-store" not in cache.lower():
        result.add(
            "api-cache", "API riêng tư chưa đặt Cache-Control: no-store", Severity.MEDIUM,
            "Phản hồi dự kiến chứa dữ liệu riêng nhưng chưa ngăn lưu vào bộ nhớ đệm.",
            "Thêm Cache-Control: no-store cho dữ liệu nhạy cảm.", evidence,
        )
    if not result.findings:
        result.add(
            "api-headers-ok", "Header API cơ bản đã có", Severity.INFO,
            "Không thấy vấn đề trong các header API được kiểm tra.", evidence=evidence,
        )
    return result


def check_api_auth_comparison(
    anonymous_status: int, authenticated_status: int, target: ApiTarget,
) -> CheckResult:
    """Compare status codes only; never inspect or save API response bodies."""
    result = CheckResult(category="API Authentication Comparison")
    evidence = (
        f"GET {target.path}: ẩn danh HTTP {anonymous_status}; "
        f"tài khoản thử nghiệm HTTP {authenticated_status}; chỉ đối chiếu mã trạng thái"
    )
    if anonymous_status in {401, 403} and 200 <= authenticated_status < 300:
        result.add(
            "api-auth-boundary", "API phân biệt phiên chưa đăng nhập và tài khoản thử nghiệm",
            Severity.INFO,
            "Yêu cầu ẩn danh bị từ chối, còn phiên thử nghiệm nhận HTTP 2xx. "
            "Điều này chỉ xác nhận ranh giới đăng nhập cho endpoint và tài khoản này.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
    elif 200 <= anonymous_status < 300 and 200 <= authenticated_status < 300:
        result.add(
            "api-auth-both-2xx", "Cả hai phiên đều nhận HTTP 2xx",
            Severity.INFO,
            "Chỉ mã trạng thái được so sánh; cần kiểm tra thủ công xem phản hồi ẩn danh "
            "có chứa dữ liệu riêng hay không.",
            evidence=evidence, verification=Verification.SUSPECTED,
        )
    elif authenticated_status in {401, 403}:
        result.add(
            "api-auth-test-denied", "Phiên thử nghiệm không được chấp nhận",
            Severity.INFO,
            "Tài khoản/token thử nghiệm nhận 401/403; chưa thể đối chiếu quyền truy cập.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
    else:
        result.add(
            "api-auth-test-inconclusive", "Chưa kết luận được so sánh đăng nhập",
            Severity.INFO,
            "Một phản hồi chuyển hướng hoặc lỗi; cần kiểm tra thủ công.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
    return result


_MISSING = object()


def _json_pointer(document: object, pointer: str) -> object:
    value = document
    for segment in pointer.split("/")[1:]:
        key = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and key.isdecimal() and int(key) < len(value):
            value = value[int(key)]
        else:
            return _MISSING
    return value


def _json_for_comparison(response) -> tuple[object, str | None]:
    if not 200 <= response.status_code < 300:
        return _MISSING, "Một phiên không nhận HTTP 2xx."
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        return _MISSING, "Phản hồi không khai báo Content-Type JSON."
    try:
        return json.loads(response.content), None
    except (ValueError, UnicodeError, RecursionError):
        return _MISSING, "Phản hồi không phải JSON hợp lệ."


def check_api_cross_account(
    first_response, second_response, target: ApiTarget, pointers: list[str],
) -> tuple[CheckResult, list[str]]:
    """Compare selected scalar fields in memory; never retain their values."""
    result = CheckResult(category="API Cross-Account Comparison")
    first_doc, first_error = _json_for_comparison(first_response)
    second_doc, second_error = _json_for_comparison(second_response)
    checked: list[str] = []
    for pointer in pointers:
        evidence = (
            f"GET {target.path}; JSON Pointer {pointer}; "
            f"tài khoản A HTTP {first_response.status_code}; "
            f"tài khoản B HTTP {second_response.status_code}; không lưu giá trị"
        )
        first_value = _json_pointer(first_doc, pointer) if first_error is None else _MISSING
        second_value = _json_pointer(second_doc, pointer) if second_error is None else _MISSING
        if first_error or second_error or first_value is _MISSING or second_value is _MISSING:
            result.add(
                "api-cross-account-inconclusive", f"Chưa so sánh được trường JSON {pointer}",
                Severity.INFO,
                first_error or second_error or "Trường không có trong một hoặc cả hai phản hồi.",
                evidence=evidence, verification=Verification.INCONCLUSIVE,
            )
            continue
        if (
            isinstance(first_value, bool) or isinstance(second_value, bool)
            or first_value is None or second_value is None
            or not isinstance(first_value, (str, int, float))
            or not isinstance(second_value, (str, int, float))
            or first_value == "" or second_value == ""
        ):
            result.add(
                "api-cross-account-inconclusive", f"Trường JSON {pointer} không phù hợp để so sánh",
                Severity.INFO,
                "Chỉ so sánh giá trị chuỗi hoặc số khác rỗng; không so sánh null, boolean hay đối tượng.",
                evidence=evidence, verification=Verification.INCONCLUSIVE,
            )
            continue
        checked.append(pointer)
        if type(first_value) is type(second_value) and first_value == second_value:
            result.add(
                "api-cross-account-equal",
                f"Hai tài khoản thấy cùng giá trị ở trường dự kiến riêng {pointer}",
                Severity.HIGH,
                "Trường bạn đánh dấu phải khác theo tài khoản có cùng giá trị ở hai phiên. "
                "Đây là dấu hiệu cần xác minh; hai phiên có thể thuộc cùng một tài khoản.",
                "Xác nhận hai phiên thuộc hai tài khoản khác nhau và kiểm tra phân quyền dữ liệu tại endpoint.",
                evidence, verification=Verification.SUSPECTED,
            )
        else:
            result.add(
                "api-cross-account-distinct", f"Trường dự kiến riêng {pointer} có giá trị khác nhau",
                Severity.INFO,
                "Hai phiên thấy giá trị khác nhau ở trường đã chọn. "
                "Kết quả này chưa chứng minh phân quyền trên mọi tài nguyên.",
                evidence=evidence, verification=Verification.OBSERVED,
            )
    return result, checked
