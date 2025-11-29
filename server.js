// server.js (Node.js/Express Backend) - ĐÃ THÊM ERROR HANDLER

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');

// --- Cấu hình Mongoose (Database) ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/doraemonDB'; 
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.log('LỖI KẾT NỐI MONGODB:', err));

// --- Định nghĩa Schema & Model cho User (ví dụ) ---
const userSchema = new mongoose.Schema({
    username: String,
    passwordHash: String, // Dùng để lưu mật khẩu đã mã hóa
    twoFactorSecret: String, // Dùng cho 2FA
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// --- Khởi tạo App ---
const app = express();

// --- Middleware ---
app.use(cors()); 
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

// --- Middleware Xác thực và Phân quyền (Giả lập) ---
// Thay thế bằng logic JWT, Passport hoặc Session thực tế của bạn
const isAdmin = (req, res, next) => {
    // *** Thay thế logic giả lập này bằng việc kiểm tra JWT/Session thực tế ***
    // const userRole = req.user ? req.user.role : 'guest';
    const userRole = 'admin'; // <== GIẢ ĐỊNH VAI TRÒ ĐỂ CHẠY THỬ
    
    if (userRole === 'admin') {
        next();
    } else {
        // LUÔN TRẢ VỀ JSON: Lỗi 403 Forbidden
        res.status(403).json({ error: 'Truy cập bị từ chối. Cần quyền Admin.' });
    }
};

// --- ROUTE ADMIN (BẢO VỆ) ---
// Admin Dashboard
app.get('/admin/dashboard', isAdmin, (req, res) => {
    res.json({ message: 'Chào mừng đến Admin Dashboard! Bạn đã xác thực.', status: 'OK' });
});

// --- ROUTE GIẢI MÃ (API chính) ---
app.post('/giai-ma', async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body; 

    // 1. Kiểm tra dữ liệu đầu vào
    if (!userInput || !recaptchaToken) {
        // LUÔN TRẢ VỀ JSON: Lỗi 400 Bad Request
        return res.status(400).json({ error: "Thiếu dữ liệu đầu vào hoặc token reCAPTCHA." });
    }

    // 2. Xử lý Logic reCAPTCHA (Giả lập/Thực tế):
    // const isHuman = await verifyRecaptcha(recaptchaToken); // Thay bằng hàm xác thực thực tế

    const isHuman = true; // <== GIẢ ĐỊNH XÁC THỰC THÀNH CÔNG

    if (!isHuman) {
        // LUÔN TRẢ VỀ JSON: Lỗi 401 Unauthorized
        return res.status(401).json({ error: "Xác thực reCAPTCHA thất bại. Yêu cầu bị từ chối." });
    }

    // 3. Xử lý Giải mã (Logic chính)
    const result = `[ĐÃ GIẢI MÃ] Mã của bạn: ${userInput.toUpperCase()}`;
    
    // 4. Trả về kết quả JSON
    res.json({ 
        success: true, 
        result: result, 
        timestamp: new Date().toISOString()
    });
});

// --- MIDDLEWARE BẮT LỖI CUỐI CÙNG (QUAN TRỌNG ĐỂ FIX LỖI JSON DECODE) ---
app.use((err, req, res, next) => {
    // Log lỗi để bạn debug
    console.error('Lỗi Server Chưa Xử Lý (500):', err.stack);
    
    // Nếu header đã được gửi (đã gửi phản hồi rồi), chuyển lỗi cho Express xử lý tiếp
    if (res.headersSent) {
        return next(err);
    }

    // TRẢ VỀ JSON CHUẨN: Đảm bảo mọi lỗi 500 đều là JSON
    res.status(err.status || 500).json({
        error: "Lỗi máy chủ nội bộ. Vui lòng kiểm tra log server.",
        message: err.message
    });
});

// --- Khởi động Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server đang chạy trên cổng ${PORT}`);
});
