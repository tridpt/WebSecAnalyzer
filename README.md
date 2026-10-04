# WebSecAnalyzer

Ứng dụng web chạy trên máy của bạn để kiểm tra nhanh cấu hình bảo mật của **website bạn sở hữu hoặc được phép kiểm tra**. Công cụ chỉ đọc phản hồi HTTP, cookie, chứng chỉ TLS và thẻ `<script>` công khai; không thử khai thác lỗ hổng. Một lần quét có thể kiểm tra tối đa 30 trang HTML cùng website. Bạn có thể bật thêm phần khám phá và kiểm tra API có giới hạn.

## Chạy trên Windows

Yêu cầu Python 3.10 trở lên. Trong PowerShell:

```powershell
cd path\to\WebSecAnalyzer
py -3 -m pip install -r requirements.txt
py -3 app.py
```

Mở **http://127.0.0.1:8000**. Bạn cũng có thể bấm đúp `start_app.bat` sau khi cài thư viện. Đổi cổng bằng `py -3 app.py --port 8080` hoặc biến môi trường `PORT`. Máy chủ chỉ lắng nghe trên `127.0.0.1` và không bật debug.

Nhập URL, chọn giới hạn trang (mặc định 20, tối đa 30), thời gian quét tối đa (mặc định 120 giây, từ 1 đến 600 giây), xác nhận quyền kiểm tra rồi bấm **Kiểm tra ngay**. Có thể tải lên `package-lock.json` hoặc `pnpm-lock.yaml` của chính dự án (tối đa 2 MB) để tra đúng phiên bản npm. Ứng dụng đọc liên kết nội bộ và `sitemap.xml` (gồm tối đa 3 sitemap nếu sitemap chính là index), chỉ đi theo URL cùng giao thức, tên miền và cổng của trang đích, và giữ khoảng cách ít nhất 350 ms giữa các yêu cầu HTTP. Nếu chỉ nhập tên miền công khai, ứng dụng sẽ thêm `https://`; với `localhost:3000`, `127.0.0.1:8000` hoặc `[::1]:8080`, ứng dụng tự thêm `http://`.

Báo cáo hiển thị điểm và lỗi theo từng trang, cùng phần **Phạm vi của điểm số**: số trang HTML, API đã chọn và API thực sự kiểm tra, URL bỏ qua, trạng thái OpenAPI. JSON lưu danh sách URL đầu vào và URL cuối cùng của từng trang/API đã kiểm tra trong `coverage.checked_urls`, cùng các path API đã chọn trong `coverage.api_selected_paths`. Điểm website là **điểm thấp nhất** trong các trang HTML và endpoint API đã kiểm tra, mỗi điểm có tính cả các kiểm tra chung của website. Route chỉ phát hiện qua OpenAPI và URL chưa quét không được tính điểm. Các kiểm tra HTTPS/TLS và chuyển hướng HTTP → HTTPS thực hiện một lần cho website. Lượt quét chạy nền, có nút **Hủy lần quét**; lần quét bị hủy hoặc hết thời gian không được lưu. Mỗi lần hoàn tất được lưu vào `history.db`; trang **Lịch sử** cho so sánh hai lần quét cùng URL, xem lỗi mới/đã sửa và tải HTML hoặc JSON. Khi phạm vi hai lần quét khác nhau, báo cáo so sánh cảnh báo và không gọi lỗi ở URL chưa quét lại là “đã sửa”.

## Khám phá liên kết SPA bằng JavaScript (tùy chọn)

Cài `py -3 -m pip install -r requirements-browser.txt` và dùng Edge/Chrome đã cài, hoặc `py -3 -m playwright install chromium`. Bật **Khám phá liên kết SPA bằng JavaScript** trong biểu mẫu, hay thêm `--js-discovery` trên CLI. Trình duyệt cô lập kết xuất từng trang HTML đã quét và lấy các thẻ `<a href>` được JavaScript tạo thêm. URL tìm thấy vẫn phải qua cùng quy tắc an toàn, giới hạn 30 trang, tốc độ quét và thời gian tối đa trước khi được quét như một trang thường.

Trình duyệt không nhận Cookie/phiên thử nghiệm và không kết nối trực tiếp tới website. Nó dùng bản HTML đã tải; chỉ các tệp `.js`/`.mjs` cùng origin được đọc qua kết nối DNS ghim, tối đa 8 tệp mới mỗi trang, 60 tệp mỗi lượt, 1 MB mỗi tệp và 8 MB bộ nhớ đệm script. Các yêu cầu API, POST, WebSocket, tài nguyên ngoài origin và điều hướng tự động bị chặn. Nếu thiếu trình duyệt hoặc một script không tải được, crawler HTML/sitemap vẫn chạy; báo cáo ghi `unavailable` hoặc `partial`. Các route chỉ xuất hiện sau khi gọi API hoặc thao tác người dùng có thể chưa được phát hiện. CI yêu cầu chạy lại chế độ này nếu baseline có kết quả khám phá hoàn tất.

## Kiểm tra API tùy chọn

Mở **Quét API tùy chọn** trong biểu mẫu. Nhập path tài liệu OpenAPI, ví dụ `/openapi.json`, rồi bấm **Đọc GET route từ OpenAPI**. Chọn các GET route muốn quét; với route có `{id}` hoặc tham số path khác, nhập một giá trị cụ thể như `42`. Nút **Thêm GET đã chọn vào danh sách quét** ghi các path cụ thể vào ô endpoint. Bạn cũng có thể nhập path thủ công. Công cụ không tự gọi các route chỉ mới phát hiện; chỉ tối đa 10 endpoint GET đã chọn/nhập cùng website mới được kiểm tra. Ví dụ:

```text
/api/health
private /api/account
```

Bước xem trước OpenAPI chỉ đọc trang đầu và tài liệu cùng origin, giới hạn 15 giây, 1 MB nội dung và tối đa 100 GET route đủ điều kiện hiển thị. Không gửi Cookie/Bearer token tới tài liệu. Route có path không an toàn, yêu cầu query bắt buộc, tham chiếu tham số không giải được hoặc GET có request body sẽ không được đề xuất; nếu nhiều hơn 100 route hợp lệ, giao diện báo tổng số và chỉ hiển thị 100. Báo cáo quét vẫn liệt kê tối đa 100 thao tác OpenAPI và ghi tổng số thao tác phát hiện.

Tiền tố `private ` nghĩa là endpoint dự kiến yêu cầu đăng nhập. Nếu tài liệu OpenAPI khai báo xác thực cho một GET route trùng path hoặc khớp path có tham số, công cụ cũng dùng khai báo đó để đánh giá. Một phản hồi HTTP 2xx từ endpoint dự kiến riêng tư được gắn mức cao **để bạn xác minh**; công cụ không đọc nội dung nên không khẳng định đã lộ dữ liệu. Endpoint không có kỳ vọng xác thực mà trả 2xx chỉ được ghi là thông tin.

Mỗi endpoint được gửi tối đa hai GET ẩn danh: một yêu cầu không mang cookie/Authorization và một yêu cầu thêm Origin thử nghiệm để xem CORS. Công cụ còn gửi một `OPTIONS` preflight không mang phiên, với `Origin: https://websec-audit.invalid` và `Access-Control-Request-Method: GET`; nếu thử Bearer trên endpoint riêng tư thì thêm `Access-Control-Request-Headers: authorization`. OPTIONS và hai GET này chỉ đọc header, không lưu body, không theo chuyển hướng. Báo cáo ghi mã HTTP, các header CORS liên quan, số endpoint có phản hồi preflight và endpoint chưa thử được. Path không được chứa tên miền, query, fragment, tham số mẫu hoặc đoạn đường dẫn phổ biến đổi trạng thái như `/delete` và `/logout`. Với API thiết kế GET có tác dụng phụ, chỉ chọn path mà bạn biết chắc là an toàn để đọc. Báo cáo ghi rõ endpoint nào bị bỏ qua và chỉ chấm điểm những endpoint có phản hồi kiểm tra được. OpenAPI cũng chỉ được đọc trong giới hạn 1 MB và cùng origin.

### So sánh với tài khoản thử nghiệm

Trong biểu mẫu, chọn **Giá trị Cookie** hoặc **Bearer token** rồi nhập phiên của tài khoản A quyền thấp. Chỉ nhập giá trị Cookie như `session=...`, không nhập `Cookie:`; với Bearer có thể nhập token hoặc `Bearer ...`. Công cụ không nhận tên người dùng/mật khẩu và không tự đăng nhập. Phiên A chỉ được gửi tới các endpoint đã chọn có tiền tố `private ` hoặc được OpenAPI khai báo cần xác thực: một GET để so mã HTTP hoặc JSON theo cấu hình, và một GET chỉ đọc header với Origin thử nghiệm để đánh giá CORS. OPTIONS không mang phiên. Các yêu cầu dùng kết nối riêng, cùng origin, kiểm tra lại DNS, giới hạn tốc độ và thời gian quét, không theo chuyển hướng. Phiên chỉ được gửi qua HTTPS, trừ HTTP tới địa chỉ loopback thực sự. Cookie/token không được lưu trong `history.db`, JSON, HTML hoặc log kết quả.

Phát hiện CORS mức cao với Cookie cần GET có phiên trả HTTP 2xx, `Access-Control-Allow-Origin` khớp Origin thử nghiệm và `Access-Control-Allow-Credentials: true`; đó vẫn là dấu hiệu **nghi ngờ** vì công cụ không đọc body hoặc kiểm tra SameSite trong trình duyệt. Với Bearer, preflight phải cho phép `GET` và `authorization` cùng Origin và credentials; phát hiện mức trung bình không có nghĩa Origin lạ sở hữu token. Wildcard `*` cùng credentials không cho phép trình duyệt đọc phản hồi. Kiểm tra chỉ dùng một Origin và các endpoint GET bạn chọn; hãy xác minh thêm trong trình duyệt với hai tài khoản thử nghiệm trước khi kết luận dữ liệu riêng bị lộ.

### Xác minh CORS trong trình duyệt (tùy chọn)

Cài phần phụ thuộc bằng `py -3 -m pip install -r requirements-browser.txt`. Công cụ dùng Edge hoặc Chrome đã cài; nếu không có, chạy `py -3 -m playwright install chromium`. Trong biểu mẫu, bật **Xác minh CORS bằng trình duyệt cô lập** và cấp phiên A. Với Cookie, chỉ hỗ trợ một cặp `name=value`; nhập **thuộc tính thật**, không nhập giá trị lần nữa, ví dụ `SameSite=None; Secure; Path=/`. Có thể thêm `HttpOnly`. CLI dùng thêm `--browser-cors --browser-cookie-attributes 'SameSite=None; Secure; Path=/'`; với Bearer chỉ cần `--browser-cors`.

Trình duyệt tạm thời chạy trên máy này với hai địa chỉ loopback khác site nhau. Một cầu nối chuyển tiếp tối đa ba GET/OPTIONS cho mỗi API riêng tư đã chọn qua kết nối DNS ghim và chỉ chuyển mã HTTP cùng header CORS về trình duyệt. Nó không chuyển body hoặc `Set-Cookie` và không theo chuyển hướng. Trình duyệt quyết định có gửi Cookie theo thuộc tính đã khai báo hay không và JavaScript có đọc được **mã HTTP** hay không. Giá trị Cookie/Bearer chỉ ở bộ nhớ trong lượt quét; JSON, HTML và lịch sử chỉ lưu kết quả, không lưu body hoặc giá trị phiên. Nếu thiếu trình duyệt, phiên bị từ chối hoặc kết nối lỗi, báo cáo ghi không kết luận được.

Đây là phép thử trình duyệt với cầu nối nội bộ và một Origin lạ, dựa trên thuộc tính Cookie bạn cung cấp. Nó không xác minh thuộc tính Cookie thực trên mọi đường dẫn/tên miền, không đọc dữ liệu riêng trong body và không chứng minh Bearer token có thể bị Origin khác lấy được. Hãy đối chiếu `Set-Cookie` thực tế trong DevTools trước khi kết luận. CI yêu cầu chạy lại phép thử nếu baseline đã có kết quả trình duyệt hoàn tất.

Ví dụ CLI khi biến môi trường `WEBSEC_TEST_COOKIE` đã được cấp bởi hệ thống quản lý secret của CI hoặc thiết lập trong phiên PowerShell hiện tại:

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --api-private-url /api/account --auth-cookie-env WEBSEC_TEST_COOKIE --json > report-api.json
```

Với Bearer token, dùng `--auth-bearer-env WEBSEC_TEST_BEARER` thay cho `--auth-cookie-env`. Không đặt giá trị token trực tiếp trong tham số lệnh. Nếu OpenAPI khai báo xác thực cho một path được chọn bằng `--api-url`, công cụ cũng thử phiên trên path đó. Khi không có phiên, cách quét API ẩn danh vẫn hoạt động như trước.

Với một tài khoản, so sánh chỉ dựa vào mã HTTP: ẩn danh 401/403 và tài khoản 2xx là bằng chứng về **ranh giới đăng nhập ở endpoint đó với tài khoản đó**. Hai phiên cùng 2xx cần kiểm tra thủ công xem dữ liệu có khác nhau không. Một tài khoản 401/403 hoặc phản hồi lỗi/chuyển hướng là không kết luận được. Phát hiện mức cao do endpoint `private` trả 2xx ẩn danh vẫn cần xác minh.

### So sánh trường JSON của hai tài khoản

Chỉ bật cho hai tài khoản thử nghiệm **khác người dùng** mà bạn kiểm soát. Trong form, nhập phiên B và các dòng gồm một endpoint đã chọn với tiền tố `private `, theo sau là [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) tới trường **phải khác theo tài khoản**. Ví dụ endpoint `private /api/account` và dòng `/api/account /user/id`. Có thể chọn tối đa 20 trường trên tối đa 10 endpoint. Chỉ giá trị chuỗi hoặc số khác rỗng được so sánh; trường thiếu, `null`, boolean, đối tượng, phản hồi không phải JSON hoặc không phải HTTP 2xx được ghi là không kết luận được.

Ví dụ CLI khi hai biến môi trường đã được cấp từ kho secret của CI:

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --api-private-url /api/account --auth-cookie-env WEBSEC_ACCOUNT_A --auth-second-cookie-env WEBSEC_ACCOUNT_B --api-compare-field '/api/account /user/id' --json > report-api.json
```

Có thể dùng `--auth-second-bearer-env` cho tài khoản B. Tài khoản A gửi tối đa hai GET tới mỗi endpoint riêng tư được chọn: một để so sánh và một để thử CORS với Origin lạ; tài khoản B gửi tối đa một GET trên endpoint có trường JSON được chọn. Công cụ chỉ đọc body của **hai GET dùng để so sánh** trên endpoint được chọn, giới hạn 1 MB mỗi phản hồi, rồi bỏ body khỏi bộ nhớ sau lượt quét. GET thử CORS chỉ đọc header. Báo cáo chỉ lưu path, JSON Pointer, mã HTTP và kết quả **trùng/khác/không kết luận được**; không lưu giá trị trường hay body. Trường dự kiến riêng nhưng trùng được đánh dấu **nghi ngờ mức cao** để bạn xác minh hai phiên thực sự thuộc hai người dùng khác nhau. Giá trị khác nhau chỉ chứng minh khác nhau ở trường đó; công cụ chưa xác nhận phân quyền trên mọi bản ghi hoặc tài nguyên.

## Phạm vi kiểm tra

| Nhóm | Nội dung |
| --- | --- |
| HTTPS & TLS | Giao thức đang dùng, chứng chỉ/đơn vị cấp/hạn chứng chỉ, thử TLS 1.0 và 1.1; kiểm tra HTTP có chuyển trực tiếp sang HTTPS cùng tên miền |
| HTTP headers | HSTS trên HTTPS, X-Content-Type-Options, chống nhúng iframe, Referrer-Policy, Permissions-Policy, header tiết lộ phần mềm |
| CSP và CORS | CSP thiếu/yếu, nguồn script rộng, unsafe-inline/eval, thử một Origin lạ trên trang đầu, CORS wildcard/phản chiếu Origin/credentials; hiện bằng chứng header và cách sửa |
| Cookie | HttpOnly, Secure, SameSite hợp lệ, `SameSite=None` với Secure, quy tắc `__Host-`/`__Secure-`; giá trị cookie được ẩn trong bằng chứng |
| Thư viện JavaScript | Khi có lockfile: tra OSV theo phiên bản npm chính xác (tối đa 200 cặp gói/phiên bản). Khi không có: nhận diện phiên bản trong URL script và tra OSV nếu bật |
| API tùy chọn | Đọc metadata OpenAPI; với GET được chọn, xem mã trạng thái ẩn danh, `X-Content-Type-Options`, `Cache-Control`, CORS với một Origin thử nghiệm và OPTIONS preflight; nếu cấp phiên thử nghiệm, kiểm tra thêm GET có Origin lạ và so sánh mã trạng thái hoặc trường JSON bạn chọn |

Mỗi trang HTML có tối đa 5 lần chuyển hướng và 1 MB nội dung. Toàn bộ lượt quét có giới hạn `2 × số trang tối đa + 8 + 3 × số API được chọn + 1 × số API được chọn khi cấp phiên A + 1 × số API được chọn khi cấp phiên A để thử CORS + 1 × số API được chọn để so sánh với B + 1 nếu đọc OpenAPI + 3 × số API được chọn nếu bật trình duyệt CORS + min(60, 8 × số trang tối đa) nếu bật khám phá JavaScript` yêu cầu HTTP. Đây là mức dự phòng tối đa; chỉ API riêng tư đủ điều kiện mới nhận GET có phiên hoặc phép thử CORS trong trình duyệt. Ứng dụng bỏ qua file tĩnh, trang không phải HTML, URL lỗi và các đường dẫn phổ biến có thể đổi trạng thái như `/logout` hoặc `/delete`. `localhost` và IP loopback được phép quét trực tiếp. Các địa chỉ mạng nội bộ khác bị chặn theo mặc định; chuyển hướng từ website công khai tới localhost cũng bị chặn. Mỗi yêu cầu phân giải lại DNS, xác minh dải IP và chỉ kết nối tới IP đã ghim; nếu DNS đổi đích, lượt quét dừng. Tên miền gốc vẫn được dùng cho HTTP Host, TLS SNI và kiểm tra chứng chỉ. Nếu bạn đang kiểm tra **website nội bộ khác do mình quản lý**, bật chế độ riêng trước khi chạy:

```powershell
$env:ALLOW_PRIVATE_TARGETS = '1'
py -3 app.py
```

Nhập đầy đủ `http://` nếu website nội bộ khác chưa có HTTPS. Tắt chế độ này bằng `Remove-Item Env:ALLOW_PRIVATE_TARGETS` sau khi dùng.

## Dòng lệnh

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --max-pages 30
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --json
py -3 main.py localhost:8080 --yes-i-own-this --no-osv
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --lockfile .\package-lock.json --max-seconds 180 --json > report.json
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --js-discovery --evidence-file .\evidence.json --json > report.json
py -3 main.py localhost:8809 --yes-i-own-this --openapi-path /openapi.json --api-url /api/health --no-osv --json > report-api.json
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --api-private-url /api/account --json > report-api.json
```

Các tùy chọn khác: `--timeout` (mỗi yêu cầu), `--max-seconds` (cả lượt quét), `--no-color`, `--no-osv`; `--api-url` và `--api-private-url` có thể lặp lại. Khi bật tra cứu OSV, chỉ tên gói và phiên bản được gửi tới `api.osv.dev`; URL website và nội dung lockfile không được gửi. Với lockfile, công cụ dùng API OSV theo lô; nếu OSV không phản hồi, báo cáo ghi rõ số gói chưa tra được. Không có lockfile, các trang dùng chung phiên bản chỉ tra OSV một lần trong mỗi lượt quét, và mốc phiên bản offline vẫn là ước lượng.

## Khóa phạm vi và chặn lỗi mức cao mới trong CI

Tạo một báo cáo gốc sau khi đã xem và chấp nhận các phát hiện hiện tại:

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --lockfile .\package-lock.json --json > baseline.json
```

Trong pipeline, quét cùng URL với cùng giới hạn trang, API được chọn và lockfile, rồi so với báo cáo gốc:

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --lockfile .\package-lock.json --json --fail-on-new-high .\baseline.json > current.json
```

Lệnh trả mã `0` khi mọi URL/trang/API đã chọn trong baseline được kiểm tra lại và không có lỗi mức cao mới. Mã `3` báo một endpoint đã chọn bị bỏ khỏi danh sách hoặc không nhận được phản hồi ở lần quét mới, thiếu URL/API từng kiểm tra được, đổi đích chuyển hướng, bỏ kỳ vọng xác thực `private` của API, mất lượt kiểm tra có tài khoản hoặc phép thử CORS/khám phá JavaScript từng hoàn thành, mất trường JSON từng so sánh được, tài khoản từng nhận 2xx nay không còn nhận 2xx, hoặc có lỗi mức cao mới (kể cả phát hiện cũ tăng từ thấp/trung bình lên cao). Trang/API bổ sung được phép. Nếu baseline có kiểm tra bằng tài khoản, pipeline cần cấp lại secret qua biến môi trường; JSON baseline chỉ lưu mã trạng thái và kết quả so sánh, không lưu secret hoặc giá trị trường. Mã `1` là kết nối quét thất bại; mã `2` là đầu vào/baseline không hợp lệ hoặc hết thời gian. `current.json` vẫn được ghi khi CI thất bại; mục `ci_gate` ghi trạng thái, phạm vi thiếu và lỗi mức cao chưa có ngoại lệ. CI nên giữ file này làm artifact. Báo cáo gốc phải là JSON do WebSecAnalyzer xuất cho cùng URL; khi cố ý đổi phạm vi, hãy xem kết quả rồi tạo lại baseline có chủ đích.

## Xuất bằng chứng HTTP đã che dữ liệu nhạy cảm

Trong báo cáo đã lưu, chọn **Tải bằng chứng JSON**. CLI dùng `--evidence-file .\evidence.json`; JSON báo cáo thường cũng có trường `observations`. Gói bằng chứng nối từng phát hiện (nhóm, mã kiểm tra và thứ tự) với các phản hồi liên quan qua `response_ids`: thời điểm UTC, phương thức, URL, mã HTTP, header yêu cầu thử nghiệm và các header phản hồi cần thiết. Chỉ lưu metadata; không lưu body, `Authorization` hay giá trị Cookie. `Set-Cookie` chỉ giữ tên và cờ, URL che giá trị query cùng các đoạn đường dẫn giống token, CSP che nonce. Header phản chiếu đúng phiên thử nghiệm cũng được che. Các kiểm tra không dựa vào phản hồi HTTP, như tra OSV, có thể không có `response_ids`; xem chi tiết ở báo cáo chính. Trước khi chia sẻ bằng chứng, hãy xem lại các đoạn path thông thường vì chúng có thể chứa định danh riêng của ứng dụng.

## Xác minh phát hiện và ngoại lệ

Mỗi phát hiện có một nhãn xác minh:

- **Có bằng chứng:** công cụ quan sát trực tiếp cấu hình, phản hồi hoặc phiên bản trong lockfile. Nhãn này không chứng minh đã khai thác được lỗ hổng.
- **Nghi ngờ:** kết luận phụ thuộc giả định hoặc cách nhận diện gần đúng, như phiên bản JavaScript từ tên file hay API trả 2xx dù tài liệu khai báo cần đăng nhập.
- **Không kết luận được:** phép kiểm tra thiếu dữ liệu, bị lỗi hoặc không được thư viện TLS hiện tại hỗ trợ. Nhóm kiểm tra bị lỗi cũng hiển thị trạng thái này.

Trong một **báo cáo đã lưu**, chọn **Ghi ngoại lệ có thời hạn** ở phát hiện cần chấp nhận tạm thời, nhập lý do và ngày hết hạn theo UTC. Trang **Ngoại lệ** cho xem, thu hồi và tải `websec-exceptions.json`. Ngoại lệ khớp chính xác website đầu vào, loại trang/API, URL cuối cùng, nhóm và phát hiện. Ngày hết hạn còn hiệu lực đến hết ngày UTC đó. Ngoại lệ hết hạn tự mất hiệu lực; điểm và phát hiện gốc không bị xóa hoặc giảm mức độ. JSON của báo cáo đã lưu cũng ghi ngoại lệ liên quan và trạng thái còn hiệu lực.

Để dùng ngoại lệ đã xuất trong CI:

```powershell
py -3 main.py https://ten-mien-cua-ban.vn --yes-i-own-this --json --fail-on-new-high .\baseline.json --waivers .\websec-exceptions.json > current.json
```

CI chỉ bỏ qua lỗi mức cao mới khi ngoại lệ khớp chính xác và còn hạn. Ngoại lệ không bỏ qua việc thiếu URL/API của baseline. `current.json` vẫn chứa phát hiện mức cao gốc; mục `ci_gate.applied_exceptions` ghi lý do và ngày hết hạn đã áp dụng. Tệp ngoại lệ có giới hạn 10 MB và tối đa 1000 mục.

## Hiểu kết quả

Mỗi nhóm bắt đầu từ 100 điểm. Phát hiện mức cao trừ 20, trung bình trừ 10, thấp trừ 4. Điểm từng trang HTML hoặc API là trung bình các nhóm chạy thành công trên URL đó cùng với kiểm tra chung của website; điểm website là điểm thấp nhất trong các URL đã kiểm tra. Nhãn xác minh và ngoại lệ không đổi công thức tính điểm. Đây là **điểm tham khảo về cấu hình trong phạm vi báo cáo**, không phải chứng nhận website an toàn. Công cụ không tự đăng nhập, không thu thập toàn site và không kiểm thử XSS, SQL injection hay lỗi logic. CORS chỉ thử một Origin lạ tại trang đầu và các API được chọn; phép thử trình duyệt tùy chọn dựa trên thuộc tính Cookie do bạn khai báo và chỉ đọc mã HTTP, nên không xác nhận toàn bộ chính sách CORS hoặc dữ liệu riêng bị lộ. Kết quả thử TLS 1.0/1.1 phụ thuộc thư viện TLS cục bộ; khi không thể kết luận, báo cáo ghi rõ. Thư viện gộp trong bundle có thể không lộ phiên bản; hãy đối chiếu lockfile của dự án.

## Kiểm tra ứng dụng

```powershell
py -3 -m pytest -q
```

Bộ kiểm tra chạy offline, gồm kiểm tra giao diện, giới hạn URL/chuyển hướng và một máy chủ HTTP trên localhost.
