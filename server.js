// server.js - BỘ NÃO AN TOÀN CỦA ỨNG DỤNG

// --- 1. IMPORT CÁC THƯ VIỆN CẦN THIẾT ---
const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config(); // Tải biến môi trường từ file .env

// --- 2. KHỞI TẠO ỨNG DỤNG VÀ CẤU HÌNH ---
const app = express();
const PORT = 3000;

app.use(cors({
    origin: 'https://viet-8101.github.io/giai-ma-doraemon' // Đặt lại URL frontend cụ thể của bạn
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// ADDED: Trust the X-Forwarded-For header from a reverse proxy (like Render, Heroku)
app.set('trust proxy', 1);

// --- 3. LƯU TRỮ CÁC GIÁ TRỊ BÍ MẬT VÀ DỮ LIỆU ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
if (!RECAPTCHA_SECRET_KEY) {
    console.error('Lỗi: RECAPTCHA_SECRET_KEY chưa được đặt trong biến môi trường!');
    process.exit(1); 
}

// ADDED: IPInfo API Token from user request
const IPINFO_TOKEN = '97322fdbb8213c';

// ADDED: Simple in-memory blocklists for demonstration
const BANNED_IPS = new Set(['123.45.67.89']);
const BANNED_FINGERPRINTS = new Set(['example_banned_fingerprint']);

// Từ điển Doraemon (giữ nguyên)
const tuDienDoraemon = {
    "cái loa biết đi": "Jaian",
    "thánh chảnh": "Suneo",
    "cục nợ quốc dân": "Nobita",
    "trùm chém gió": "Suneo",
    "boss ăn vặt": "Doraemon",
    "siêu nhân gục ngã": "Nobita",
    "máy phát kẹo": "Doraemon",
    "ổ bom di động": "Jaian",
    "thánh phá đồ": "Nobita",
    "chuyên gia gây họa": "Nobita",
    "nhà tài trợ nước mắt": "mẹ Nobita",
    "lò luyện điểm 0": "lớp học của Nobita",
    "trùm thất tình": "Nobita",
    "đứa trẻ cuối cùng của mushika": "Micca",
    "máy ATM biết đi": "Doraemon",
    "trí tuệ nhân tạo có tâm": "Doraemon",
    "con tinh tinh": "Jaian",
    "con khỉ đột": "Jaian", "khỉ đột": "Jaian",
    "tinh tinh": "Jaian",
    "con cáo": "Suneo", "cáo": "Suneo",
    "bạch tuộc": "Noise",
    "quần dài": "2 con cá trắm đen đc làm ở Pháp rất là mắc tiền (của Suneo)",
    "mụ phù thủy": "mẹ của Nobita",
    "tên ngốc hậu đậu": "Nobita",
    "tên robinson phiền phức": "Nobita",
    "thiên tài ngủ": "Nobita",
    "diễn viên suất sắc": "Nobita",
    "bậc thầy năn nỉ": "Nobita",
    "thiên tài thắt dây": "Nobita",
    "tay vua súng": "Nobita",
    "xe buýt": "Nobita", "xe bus":
    "Nobita", "mèo máy": "Doraemon",
    "mỏ nhọn": "Suneo",
    "lồi rốn": "Jaian",
    "yên ắng": "nhà Shizuka",
    "hình tròn": "bánh rán dorayaki",
    "kẻ tham lam": "Jaian",
    "hai người nổi tiếng ham ăn": "Jaian và Suneo",
    "điểm đen": "điểm 0",
    "bàn tay vàng trong làng ngáo ngơ": "Nobita",
    "cục tạ quốc dân": "Nobita",
    "đại ca sân trường": "Jaian",
    "người mẫu sừng sỏ": "Suneo",
    "cô gái tắm mỗi tập": "Shizuka",
    "vua bánh rán": "Doraemon",
    "thánh cầu cứu": "Nobita",
    "người đến từ tương lai": "Doraemon",
    "cây ATM sống": "Doraemon",
    "lồng tiếng động đất": "Jaian",
    "diễn viên chính của bi kịch": "Nobita",
    "fan cuồng công nghệ": "Suneo",
    "kẻ lười biếng nhỏ bé": "Nobita",
    "chồn xanh nhỏ đáng yêu": "Doraemon",
    "bình yên trước cơn bão": "nhà Shizuka",
    "cậu bé sáo lạc điệu": "Nobita",
    "loa phóng thanh biết đi": "Jaian",
    "trùm phá nốt": "Nobita",
    "người cứu âm nhạc địa cầu": "Doraemon",
    "quái vật hút âm": "bào tử noise",
    "người bạn đến từ hành tinh âm nhạc": "Micca",
    "thánh phá bản nhạc": "Nobita",
    "cây sáo truyền thuyết": "cây sáo dọc của mushika",
    "bản nhạc giải cứu trái đất": "bản giao hưởng địa cầu",
    "phi công nghiệp dư": "Nobita",
    "vùng đất trong mơ": "Utopia",
    "cư dân đám mây": "người sống ở Utopia",
    "nhà trên trời view đẹp": "Utopia",
    "người bạn Utopia": "Sonya",
    "trùm điều khiển thời tiết": "quản lý Utopia",
    "mặt trăng bay lạc": "Utopia",
    "chuyến phiêu lưu trên trời": "hành trình của nhóm Nobita",
    "lâu đài mây thần bí": "trung tâm điều hành Utopia",
    "trùm chấn động bầu trời": "Suneo lái máy bay",
    "cậu bé bay không bằng lái": "Nobita",
    "thánh nhảy moonwalk ngoài vũ trụ": "Nobita",
    "chuyên gia té không trọng lực": "Nobita",
    "trạm vũ trụ di động": "tàu của Doraemon",
    "người bạn tai dài trên mặt trăng": "Luca",
    "cư dân mặt trăng bí ẩn": "tộc người Espal",
    "đội thám hiểm mặt trăng": "nhóm Nobita",
    "mặt trăng giả tưởng": "thế giới do bảo bối tạo ra",
    "cuộc chiến không trọng lực": "trận đấu trên mặt trăng",
    "lũ bạn ngoài hành tinh đáng yêu": "Luca và đồng bọn",
    "bầu trời đêm đầy ảo mộng": "khung cảnh mặt trăng",
    "cậu bé lười biếng nhất thành phố": "Nobita",
    "cậu bé xấu tính nhất thành phố": "Jaian",
    "nhạc sĩ vũ trụ": "Trupet",
    "nhà soạn nhạc vĩ đại": "Trupet",
    "người sáng tác giao hưởng địa cầu": "Trupet",
    "chủ nhân bản giao hưởng địa cầu": "Trupet",
    "nhà sáng tạo âm nhạc vũ trụ": "Trupet",
    "nhạc sĩ bảo vệ hòa bình âm nhạc": "Trupet",
    "rùa siêu tốc vũ trụ": "Moto",
    "rùa vũ trụ có mai thép": "Moto",
    "rùa siêu bền": "Moto",
    "tốc độ vũ trụ từ mai rùa": "Moto",
    "vũ trụ đua rùa": "Moto",
    "con rùa nhanh nhất trong không gian": "Moto",
    "viên đạn của đại bác không khí": "Moto"
};

// --- 4. ADDED: SECURITY MIDDLEWARE ---
const securityCheck = async (req, res, next) => {
    // MODIFIED: Get visitorId from request body
    const { visitorId } = req.body;
    // Get client IP address, trusting the 'x-forwarded-for' header if behind a proxy
    const ip = req.ip;

    // Check blocklists first
    if (BANNED_IPS.has(ip) || (visitorId && BANNED_FINGERPRINTS.has(visitorId))) {
        console.warn(`[BLOCK] Denied access for banned IP: ${ip} or Fingerprint: ${visitorId}`);
        return res.status(403).json({ error: 'Truy cập bị từ chối. Bạn đã bị chặn.' });
    }

    try {
        const response = await fetch(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
        if (!response.ok) {
            throw new Error(`IPInfo API request failed with status ${response.status}`);
        }
        const ipData = await response.json();

        // Log required information to the console
        console.log(`[IPInfo] Visitor ID: ${visitorId || 'N/A'}`);
        console.log(`  - IP: ${ipData.ip}`);
        console.log(`  - Country: ${ipData.country}`);
        console.log(`  - Region: ${ipData.region}`);
        console.log(`  - Org: ${ipData.org}`);
        console.log(`  - Hostname: ${ipData.hostname || 'N/A'}`);
        
        // Example of issuing a warning based on country
        if (ipData.country !== 'VN') {
            console.warn(`[Suspicious Access] Request from outside Vietnam. Country: ${ipData.country}`);
        }

        next(); // Continue to the next middleware/route handler
    } catch (error) {
        console.error('[Security Check Error]', error.message);
        // In case of error, we'll let the request pass but log the issue.
        // For a stricter policy, you could return an error response here.
        next();
    }
};


// --- 5. ĐỊNH NGHĨA CÁC ĐIỂM CUỐI (API ENDPOINTS) ---
app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

// MODIFIED: Added the securityCheck middleware to the /giai-ma route
app.post('/giai-ma', securityCheck, async (req, res) => {
    // MODIFIED: visitorId is now also in the request body, but handled by middleware.
    const { userInput, recaptchaToken } = req.body;

    if (!userInput || !recaptchaToken) {
        return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.' });
    }

    try {
        const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify`;
        
        const verificationResponse = await fetch(recaptchaVerificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`
        });

        const recaptchaData = await verificationResponse.json();

        if (!recaptchaData.success) {
            console.warn('Xác thực reCAPTCHA thất bại:', recaptchaData['error-codes']);
            return res.status(401).json({ error: 'Xác thực không thành công. Có thể bạn là bot!' });
        }

        console.log('✅ Xác thực reCAPTCHA thành công!');
        let text = userInput.trim().toLowerCase();
        
        const entries = Object.entries(tuDienDoraemon).sort((a, b) => b[0].length - a[0].length);
        let replaced = false;
        for (const [k, v] of entries) {
            const re = new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
            if (text.match(re)) {
                text = text.replace(re, v);
                replaced = true;
            }
        }
        
        const ketQua = replaced ? text : "Không tìm thấy từ khóa phù hợp trong từ điển.";

        res.json({ success: true, ketQua: ketQua });

    } catch (error) {
        console.error('Lỗi server:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});


// --- 6. KHỞI CHẠY SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
