## 🚀 Backend Bộ Giải Mã Doraemon
Đây là máy chủ backend cho ứng dụng Bộ Giải Mã Doraemon, cung cấp dịch vụ dịch các cụm từ đặc biệt thành tên nhân vật hoặc thuật ngữ liên quan đến Doraemon. Ngoài ra, nó còn tích hợp một bảng điều khiển quản trị để quản lý người dùng và giám sát hoạt động API.

## ✨ Tính Năng
Giải Mã Cụm Từ Doraemon: Dịch các từ khóa người dùng nhập vào dựa trên từ điển nội bộ.

Tích Hợp reCAPTCHA v3: Bảo vệ endpoint /giai-ma khỏi bot và xác minh tương tác người dùng.

Chặn IP và Dấu Vân Tay (Fingerprint): Tự động và thủ công chặn các địa chỉ IP và dấu vân tay độc hại dựa trên lỗi reCAPTCHA hoặc hành động của quản trị viên.

API Bảng Điều Khiển Quản Trị: Cung cấp các endpoint an toàn cho quản trị viên để:

Đăng nhập và nhận JWT để xác thực.

Xem thống kê sử dụng API (tổng yêu cầu, số lần reCAPTCHA thất bại).

Quản lý (chặn/bỏ chặn) IP và dấu vân tay.

Truy xuất danh sách người dùng từ Firebase Authentication.

Tích Hợp Firebase Firestore: Lưu trữ danh sách chặn và số liệu thống kê.

Tích Hợp Firebase Authentication (Admin SDK): Cho phép liệt kê người dùng từ dự án Firebase.

Bảo Mật: Bao gồm các tiêu đề bảo mật HTTP (Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Content-Security-Policy) và xử lý lỗi toàn cục.

Cấu Hình CORS: Cho phép yêu cầu từ các miền frontend cụ thể (GitHub Pages, môi trường phát triển cục bộ, v.v.).

## 🛠️ Công Nghệ Sử Dụng
Node.js: Môi trường thời gian chạy JavaScript.

Express.js: Framework web tối giản cho Node.js.

CORS: Middleware Express để bật CORS.

node-fetch: Module fetch cho Node.js.

dotenv: Tải biến môi trường từ .env.

jsonwebtoken (JWT): Dùng cho xác thực quản trị viên.

crypto: Module mã hóa tích hợp của Node.js.

Firebase Admin SDK: Tích hợp Firestore và Authentication.

## 🚀 Bắt Đầu
Điều Kiện Tiên Quyết
Node.js (phiên bản LTS).

Khóa Bí Mật reCAPTCHA v3 của Google.

Dự án Firebase đã bật Firestore.

File JSON Khóa Tài Khoản Dịch Vụ Firebase.

## Biến Môi Trường

RECAPTCHA_SECRET_KEY= thông tin bí mật
ADMIN_USERNAME= thông tin bí mật
ADMIN_PASSWORD= thông tin bí mật
JWT_SECRET=mot_chuoi_bi_mat_rat_manh_de_ky_jwt # Có thể tạo bằng crypto.randomBytes(64).toString('hex')
FIREBASE_SERVICE_ACCOUNT_KEY= thông tin bí mật
RENDER_SERVICE_ID= thông tin bí mật

Lưu ý quan trọng về FIREBASE_SERVICE_ACCOUNT_KEY:
Sao chép toàn bộ nội dung file JSON khóa tài khoản dịch vụ Firebase của bạn vào một dòng duy nhất cho biến này, đảm bảo nó được bao quanh bởi dấu ngoặc đơn ' hoặc dấu ngoặc kép ".

## Cài Đặt
Clone repository:

git clone <URL_repo_cua_ban>
cd doraemon-decoder-backend

Cài đặt các gói phụ thuộc:

npm install

Chạy Máy Chủ
Để khởi động máy chủ:

npm start

Máy chủ sẽ chạy trên http://0.0.0.0:3000 (hoặc cổng bạn đã chỉ định).

## 💡 Các Endpoint API
Các Endpoint Công Khai
GET /
Mô tả: Kiểm tra trạng thái máy chủ.

Phản hồi: Backend Doraemon đang chạy và hoạt động tốt! (HTTP 200 OK)

POST /giai-ma
Mô tả: Giải mã input và xác minh reCAPTCHA v3.

Body Yêu Cầu (JSON):

**{
    "userInput": "cái loa biết đi",
    "recaptchaToken": "TOKEN_CLIENT_RECAPTCHA_CUA_BAN",
    "visitorId": "ID_VAN_TAY_TUY_CHON"
}**

Phản Hồi (JSON):

**Thành công (HTTP 200 OK): {"success": true, "ketQua": "Jaian"}**

**Lỗi (HTTP 400/401/403/500): {"error": "Thông báo lỗi", "details": "Chi tiết tùy chọn"}**

**Bị chặn (HTTP 403): {"error": "Truy cập của bạn đã bị chặn tạm thời. Vui lòng thử lại sau: [Ngày/Giờ]."}**

Các Endpoint Quản Trị (Yêu Cầu Xác Thực JWT)
Tất cả các endpoint quản trị yêu cầu tiêu đề Authorization: Bearer TOKEN_JWT_CUA_BAN

POST /admin/login
Mô tả: Xác thực quản trị viên và trả về JWT.

**Body Yêu Cầu (JSON): {"username": "ten_dang_nhap_admin_cua_ban", "password": "mat_khau_admin_cua_ban"}**

Phản Hồi (JSON):

**Thành công (HTTP 200 OK): {"success": true, "token": "TOKEN_JWT_CUA_BAN"}**

**Lỗi (HTTP 401): {"error": "Tên đăng nhập hoặc mật khẩu không đúng."}**

GET /api/users
Mô tả: Truy xuất danh sách người dùng từ Firebase Authentication.

Xác thực: Yêu cầu JWT của Admin.

Phản hồi (JSON): Mảng các đối tượng người dùng (HTTP 200 OK) hoặc lỗi (HTTP 401/403/500).

GET /admin/stats
Mô tả: Truy xuất số liệu thống kê toàn cầu và danh sách IP/dấu vân tay bị chặn.

Xác thực: Yêu cầu JWT của Admin.

Phản hồi (JSON): Thống kê và danh sách bị chặn (HTTP 200 OK) hoặc lỗi (HTTP 401/403/500).

POST /admin/ban
Mô tả: Chặn vĩnh viễn IP hoặc dấu vân tay.

Xác thực: Yêu cầu JWT của Admin.

**Body Yêu Cầu (JSON): {"type": "ip" | "fingerprint", "value": "IP_HOAC_ID_VAN_TAY", "reason": "Lý do chặn (tùy chọn)"}**

Phản hồi (JSON): Thành công (HTTP 200 OK) hoặc lỗi (HTTP 400/401/403/409/500).

POST /admin/unban
Mô tả: Bỏ chặn IP hoặc dấu vân tay.

Xác thực: Yêu cầu JWT của Admin.

**Body Yêu Cầu (JSON): {"type": "ip" | "fingerprint", "value": "IP_HOAC_ID_VAN_TAY"}**

**Phản hồi (JSON): Thành công (HTTP 200 OK) hoặc lỗi (HTTP 400/401/403/404/500).**

## ⚠️ Thông Tin Về Bảo Mật
Biến Môi Trường: Không bao giờ commit file .env lên Git.

JWT Secret: Đảm bảo JWT_SECRET là một chuỗi mạnh, ngẫu nhiên.

Thông Tin Đăng Nhập Admin: Sử dụng ADMIN_USERNAME và ADMIN_PASSWORD mạnh, duy nhất.

Khóa Tài Khoản Dịch Vụ Firebase: Xử lý file này cực kỳ cẩn thận, không để lộ công khai.

## 🤝 Đóng Góp
Mở issues hoặc gửi pull requests nếu bạn có đề xuất hoặc sửa lỗi.



## Tác giả:
**_Nguyễn Đắc Hoàng Việt_**
