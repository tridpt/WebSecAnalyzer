"""Short, conditional exploitation scenarios for actionable findings."""

from __future__ import annotations


_IMPACTS = {
    "tls-scheme": (
        "Với lượt truy cập HTTP qua mạng, người trên đường truyền có thể đọc hoặc sửa "
        "nội dung, kể cả dữ liệu đăng nhập nếu người dùng gửi qua trang này."
    ),
    "tls-cert": (
        "Trình duyệt có thể chặn trang hoặc hiện cảnh báo. Nếu người dùng bỏ qua cảnh báo, "
        "kẻ đứng giữa có thể giả mạo máy chủ và đọc dữ liệu truyền qua kết nối."
    ),
    "tls-protocol": (
        "Client còn dùng giao thức cũ có thể phải kết nối bằng cơ chế mã hóa yếu hơn; "
        "nguy cơ nghe lén hoặc sửa dữ liệu phụ thuộc bộ mã hóa và khả năng của kẻ tấn công."
    ),
    "tls-not-yet-valid": (
        "Trình duyệt có thể cảnh báo hoặc chặn kết nối; người dùng quen bỏ qua cảnh báo sẽ khó "
        "phân biệt website thật với kết nối bị giả mạo."
    ),
    "strict-transport-security": (
        "Người dùng truy cập bằng HTTP lần đầu hoặc sau khi HSTS hết hạn có thể bị kẻ đứng "
        "giữa giữ lại trên HTTP và đọc hoặc sửa nội dung trước khi HTTPS được dùng."
    ),
    "x-content-type-options": (
        "Nếu máy chủ trả nội dung do người dùng kiểm soát với Content-Type sai, trình duyệt có thể "
        "đoán kiểu nội dung và xử lý nó như mã thực thi."
    ),
    "x-frame-options": (
        "Nếu trang có thao tác nhạy cảm và bị nhúng vào iframe của website khác, kẻ tấn công "
        "có thể che lớp giao diện để dụ người dùng bấm nhầm (clickjacking)."
    ),
    "referrer-policy": (
        "Trong một số luồng điều hướng, URL nguồn có thể được gửi cho website khác qua Referer; "
        "query chứa mã hoặc định danh nhạy cảm có thể bị lộ."
    ),
    "permissions-policy": (
        "Nếu script hoặc iframe không tin cậy chạy trên trang, chúng có thể thử dùng các tính năng "
        "trình duyệt chưa bị giới hạn; quyền camera/vị trí vẫn phụ thuộc cấp phép của người dùng."
    ),
    "csp-missing": (
        "Nếu website có điểm chèn HTML hoặc script, thiếu CSP khiến mã chèn có ít rào cản hơn "
        "để chạy trong trình duyệt người dùng; thiếu CSP tự nó chưa chứng minh có XSS."
    ),
    "csp-script": (
        "Nếu kẻ tấn công chèn được thẻ script, trình duyệt có thể tải mã từ nguồn ngoài mà "
        "chính sách chưa giới hạn."
    ),
    "csp-inline": (
        "Nếu kẻ tấn công chèn được HTML chứa script nội tuyến, chỉ thị này có thể cho phép "
        "mã chạy; nonce hoặc hash hợp lệ có thể thay đổi kết quả trên trình duyệt hiện đại."
    ),
    "csp-eval": (
        "Nếu dữ liệu không tin cậy đi vào hàm tạo mã từ chuỗi, kẻ tấn công có thêm đường "
        "thực thi JavaScript trong trang."
    ),
    "csp-wildcard": (
        "Nếu một nguồn được wildcard cho phép bị kiểm soát hoặc chèn vào trang, script độc hại "
        "có thể được tải mà CSP không chặn."
    ),
    "csp-http-script": (
        "Trình duyệt có thể chặn script HTTP trên trang HTTPS; ở môi trường vẫn tải được, "
        "người đứng giữa có thể thay nội dung script trước khi nó chạy."
    ),
    "csp-object": (
        "Nếu kẻ tấn công chèn được nội dung nhúng, thiếu giới hạn object-src để lại thêm "
        "một loại tài nguyên mà CSP không kiểm soát rõ ràng."
    ),
    "csp-base": (
        "Nếu kẻ tấn công chèn được thẻ base, URL tương đối của form hoặc tài nguyên có thể "
        "đổi đích, dẫn tới tải mã ngoài hoặc gửi dữ liệu tới nơi khác."
    ),
    "cors-null-credentials": (
        "Nếu trình duyệt gửi Cookie trong ngữ cảnh origin null và API trả dữ liệu riêng, "
        "mã chạy trong ngữ cảnh đó có thể đọc phản hồi."
    ),
    "cors-wildcard": (
        "Website khác có thể đọc phản hồi công khai từ trình duyệt. Nếu endpoint trả dữ liệu "
        "riêng không cần xác thực, dữ liệu đó cũng có thể bị đọc; wildcard không cho phép đọc "
        "phản hồi mang Cookie theo quy tắc CORS của trình duyệt."
    ),
    "cors-reflection": (
        "Nếu API trả dữ liệu riêng và trình duyệt gửi phiên tới Origin lạ, việc phản chiếu Origin "
        "có thể cho phép mã ở website đó đọc phản hồi; cần kiểm tra thêm với phiên thật."
    ),
    "cors-vary": (
        "Bộ nhớ đệm dùng chung có thể phát lại header CORS của Origin này cho Origin khác, "
        "khiến trình duyệt cấp hoặc chặn quyền đọc sai tùy cách cache hoạt động."
    ),
    "cors-preflight-vary": (
        "Cache có thể dùng lại kết quả preflight của Origin khác, làm quyết định cho phép "
        "yêu cầu CORS sai với cấu hình dự kiến."
    ),
    "cors-bearer-cross-origin": (
        "Nếu mã ở Origin lạ đã có Bearer token hợp lệ, nó có thể gọi và đọc API bằng token đó; "
        "phát hiện này không chứng minh token bị lộ."
    ),
    "cors-cookie-cross-origin": (
        "Nếu trình duyệt thực sự gửi Cookie và phản hồi chứa dữ liệu riêng, mã ở Origin được cho phép "
        "có thể đọc dữ liệu của người dùng đang đăng nhập."
    ),
    "cors-browser-cookie-readable": (
        "Trình duyệt đã gửi Cookie và cho JavaScript ở Origin thử nghiệm đọc mã HTTP; nếu body "
        "chứa dữ liệu riêng, mã ở Origin đó có thể đọc dữ liệu. Công cụ chưa xem body."
    ),
    "cors-browser-bearer-readable": (
        "Origin lạ có thể đọc phản hồi khi đã có Bearer token; cần một cách khác để lấy token "
        "trước khi điều này trở thành đường truy cập dữ liệu."
    ),
    "cookie-httponly": (
        "Nếu trang có XSS, JavaScript độc hại có thể đọc cookie này và gửi ra ngoài; "
        "rủi ro chiếm phiên cao hơn khi đây là cookie đăng nhập."
    ),
    "cookie-secure": (
        "Nếu trình duyệt gửi cookie qua HTTP trên mạng, người trên đường truyền có thể đọc "
        "giá trị cookie và có thể dùng lại phiên nếu đó là cookie đăng nhập."
    ),
    "cookie-samesite": (
        "Nếu ứng dụng có thao tác đổi trạng thái thiếu chống CSRF, website khác có thể dụ "
        "trình duyệt gửi yêu cầu kèm cookie; hành vi còn phụ thuộc mặc định SameSite của trình duyệt."
    ),
    "cookie-samesite-invalid": (
        "Trình duyệt có thể bỏ qua thuộc tính này, làm hành vi gửi cookie giữa các website "
        "khác dự kiến và tăng rủi ro CSRF ở thao tác chưa được bảo vệ."
    ),
    "cookie-samesite-none": (
        "Trình duyệt hiện đại có thể từ chối cookie, khiến đăng nhập hoặc phiên hoạt động sai; "
        "đây chủ yếu là rủi ro vận hành, chưa phải bằng chứng chiếm phiên."
    ),
    "cookie-host-prefix": (
        "Trình duyệt có thể từ chối cookie mang tiền tố này; nếu ứng dụng dựa vào cookie đó, "
        "phiên đăng nhập có thể không hoạt động như dự kiến."
    ),
    "cookie-secure-prefix": (
        "Trình duyệt có thể từ chối cookie mang tiền tố này khi thiếu Secure, khiến "
        "tính năng dựa vào cookie hoạt động sai."
    ),
    "cookie-partitioned": (
        "Trình duyệt có thể từ chối cookie phân vùng khi thiếu Secure, khiến trạng thái "
        "trong ngữ cảnh bên thứ ba không được giữ đúng."
    ),
    "mixed-content-active": (
        "Trình duyệt hiện đại thường chặn tài nguyên này, làm trang mất chức năng; nếu một "
        "client vẫn tải qua HTTP, người đứng giữa có thể sửa script hoặc nội dung nhúng."
    ),
    "mixed-content-passive": (
        "Trình duyệt có thể nâng cấp hoặc chặn ảnh/media. Nếu vẫn tải qua HTTP, người đứng "
        "giữa có thể thay nội dung người dùng nhìn thấy."
    ),
    "insecure-form-action": (
        "Nếu biểu mẫu thực sự gửi qua HTTP, dữ liệu nhập vào có thể bị đọc hoặc sửa trên "
        "đường truyền, kể cả thông tin nhạy cảm nếu form thu thập chúng."
    ),
    "external-script-no-sri": (
        "Nếu máy chủ bên thứ ba hoặc đường phát hành script bị xâm nhập, nội dung script "
        "có thể bị thay và chạy với quyền của trang; SRI sẽ chặn bản không khớp hash."
    ),
    "api-auth-missing": (
        "Nếu endpoint thật sự chứa dữ liệu riêng, người chưa đăng nhập có thể gọi trực tiếp "
        "và đọc dữ liệu; mã HTTP 2xx một mình chưa xác nhận nội dung bị lộ."
    ),
    "api-nosniff": (
        "Nếu API phục vụ nội dung do người dùng kiểm soát với Content-Type sai, trình duyệt "
        "có thể xử lý nó như mã thực thi trong một số ngữ cảnh."
    ),
    "api-cache": (
        "Nếu phản hồi chứa dữ liệu riêng, bản lưu trong trình duyệt hoặc cache trung gian "
        "có thể bị người dùng khác trên cùng thiết bị/hạ tầng truy cập tùy chính sách cache."
    ),
    "api-cross-account-equal": (
        "Nếu hai phiên thực sự thuộc hai người dùng khác nhau và trường đó là dữ liệu riêng, "
        "việc cùng thấy một giá trị có thể báo hiệu lỗi phân quyền đọc dữ liệu người khác."
    ),
}

_FINGERPRINTING = (
    "Header này giúp người ngoài nhận diện phần mềm hoặc phiên bản để nhắm vào các lỗi "
    "đã biết; chỉ lộ header chưa chứng minh máy chủ có lỗ hổng."
)


def infer_impact(category: str, check: str, title: str) -> str:
    """Describe a plausible consequence without treating a finding as an exploit."""
    if check == "tls-expiry":
        if "sắp hết hạn" in title:
            return (
                "Khi chứng chỉ hết hạn, trình duyệt sẽ cảnh báo hoặc chặn trang; người dùng bỏ qua "
                "cảnh báo có thể chấp nhận kết nối bị giả mạo."
            )
        return (
            "Trình duyệt có thể cảnh báo hoặc chặn trang; người dùng bỏ qua cảnh báo "
            "có thể chấp nhận kết nối bị giả mạo."
        )
    if check == "https-redirect":
        return (
            "Lượt truy cập HTTP đầu tiên có thể bị người đứng giữa đọc hoặc sửa trước khi "
            "người dùng tới HTTPS; chuyển hướng sai còn có thể đưa họ tới đích ngoài dự kiến."
        )
    if check.startswith("tls-legacy-"):
        return (
            "Client còn hỗ trợ TLS cũ có thể thương lượng kết nối yếu, tạo thêm cơ hội "
            "cho kẻ đứng giữa tùy bộ mã hóa và khả năng của họ."
        )
    if check in {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}:
        return _FINGERPRINTING
    if check.startswith("npm:"):
        return (
            "Nếu ứng dụng dùng đường mã bị ảnh hưởng, kẻ tấn công có thể lợi dụng lỗ hổng "
            "được OSV ghi nhận; kiểu tấn công cụ thể cần xem advisory tương ứng."
        )
    if category == "JavaScript Libraries" and check.startswith("lib-"):
        return (
            "Phiên bản nhận diện từ tên file có thể chứa lỗi đã biết; nếu ứng dụng dùng tính năng "
            "bị ảnh hưởng, kẻ tấn công có thể lợi dụng lỗi đó. Cần xác minh phiên bản thật."
        )
    return _IMPACTS.get(check, "")
