// server.js - BỘ NÃO AN TOÀN CỦA ỨNG DỤNG (PHIÊN BẢN SỬA LỖI)

// --- 1. IMPORT CÁC THƯ VIỆN CẦN THIẾT ---
const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

// --- 2. KHỞI TẠO ỨNG DỤNG VÀ CẤU HÌNH ---
const app = express();
const PORT = 3000;

// FIX: Cấu hình CORS đúng và an toàn, chỉ cho phép frontend của bạn truy cập
app.use(cors({
    origin: 'https://viet-8101.github.io'
}));

app.use(express.json());
app.set('trust proxy', 1);

// --- 3. CẤU HÌNH BẢO MẬT VÀ DỮ LIỆU ---

// -- Biến môi trường và các khóa bí mật --
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const IPQS_API_KEY = process.env.IPQS_API_KEY || 'YOUR_IPQUALITYSCORE_API_KEY';

if (!RECAPTCHA_SECRET_KEY) {
    console.error('Lỗi: RECAPTCHA_SECRET_KEY chưa được đặt trong biến môi trường!');
    process.exit(1);
}
if (IPQS_API_KEY === 'YOUR_IPQUALITYSCORE_API_KEY') {
    console.warn('Cảnh báo: Bạn đang sử dụng API Key mặc định của IPQualityScore.');
}

// -- Danh sách cấm tạm thời --
const BANNED_IPS = new Map();
const BANNED_FINGERPRINTS = new Set(); // Giữ lại cấm vĩnh viễn cho fingerprint nếu cần
const BAN_DURATION_MS = 12 * 60 * 60 * 1000; // Cấm IP trong 12 giờ

// -- Cơ chế theo dõi lỗi reCAPTCHA --
const FAILED_ATTEMPTS_THRESHOLD = 5;
const failedAttempts = new Map();

// -- Dữ liệu từ điển Doraemon (đầy đủ) --
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
    "xe buýt": "Nobita", "xe bus": "Nobita",
    "mèo máy": "Doraemon",
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


// --- 4. HÀM HỖ TRỢ BẢO MẬT ---

/**
 * Ghi nhận một lần xác thực reCAPTCHA thất bại.
 * Nếu vượt ngưỡng, cấm IP tạm thời và cấm fingerprint vĩnh viễn.
 */
function handleFailedAttempt(ip, visitorId) {
    let attempts = failedAttempts.get(ip) || { count: 0 };
    attempts.count++;
    failedAttempts.set(ip, attempts);

    console.warn(`[RECAPTCHA FAIL] IP: ${ip} failed reCAPTCHA. Attempt: ${attempts.count}`);

    if (attempts.count >= FAILED_ATTEMPTS_THRESHOLD) {
        const banExpiresAt = Date.now() + BAN_DURATION_MS;
        BANNED_IPS.set(ip, banExpiresAt);
        if (visitorId) {
            BANNED_FINGERPRINTS.add(visitorId); // Cấm fingerprint của bot
        }
        const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
        console.error(`[TEMP-BAN] IP: ${ip} has been temporarily banned. VisitorID: ${visitorId} banned. Expires at: ${banExpiresDate}`);
        failedAttempts.delete(ip);
    }
}

/**
 * FIX: Kiểm tra IP với các tham số giảm lỗi sai.
 */
async function checkIpRealtime(ip) {
    try {
        // Thêm tham số để giảm sai sót: strictness=0 (ít nghiêm ngặt), allow_public_access_points=true (cho phép wifi công cộng)
        const url = `https://www.ipqualityscore.com/api/json/ip/${IPQS_API_KEY}/${ip}?strictness=0&allow_public_access_points=true`;
        const response = await fetch(url);
        if (!response.ok) {
            console.error(`IPQS API request failed with status ${response.status}`);
            return { valid: true }; // Cho qua nếu API lỗi
        }
        const data = await response.json();

        // Thêm log chi tiết để debug
        if (data.vpn || data.proxy) {
            console.warn(`[SECURITY FLAG] IP: ${ip} flagged. Full response:`, JSON.stringify(data));
        }

        // Chặn nếu là VPN hoặc Proxy
        if (data.vpn || data.proxy) {
            return {
                valid: false,
                reason: `Kết nối của bạn bị chặn vì có dấu hiệu sử dụng VPN/Proxy.`
            };
        }
        
        // Chặn nếu không phải từ Việt Nam
        if (data.country_code !== 'VN') {
            console.warn(`[SECURITY BLOCK] IP: ${ip} is from a disallowed country: ${data.country_code}.`);
            return {
                valid: false,
                reason: `Dịch vụ chỉ dành cho người dùng tại Việt Nam.`
            };
        }
        
        console.log(`[IP Check] IP: ${ip} passed initial checks. Country: ${data.country_code}`);
        return { valid: true };

    } catch (error) {
        console.error('Lỗi khi gọi IPQualityScore API:', error.message);
        return { valid: true };
    }
}


// --- 5. MIDDLEWARE BẢO MẬT CHÍNH ---

const securityMiddleware = async (req, res, next) => {
    const ip = req.ip;
    const { visitorId } = req.body;

    // Bước 1: Kiểm tra fingerprint có bị cấm vĩnh viễn không
    if (visitorId && BANNED_FINGERPRINTS.has(visitorId)) {
        return res.status(403).json({ error: 'Truy cập của bạn đã bị chặn vĩnh viễn.' });
    }

    // Bước 2: Kiểm tra IP có bị cấm tạm thời không
    const banExpiresAt = BANNED_IPS.get(ip);
    if (banExpiresAt) {
        if (Date.now() < banExpiresAt) {
            const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
            return res.status(403).json({ error: `IP của bạn đang bị chặn tạm thời. Vui lòng thử lại sau: ${banExpiresDate}` });
        } else {
            BANNED_IPS.delete(ip);
            console.log(`[UNBAN] Temporary ban expired for IP: ${ip}.`);
        }
    }

    // Bước 3: Kiểm tra IP theo thời gian thực
    const ipCheckResult = await checkIpRealtime(ip);
    if (!ipCheckResult.valid) {
        return res.status(403).json({ error: ipCheckResult.reason });
    }

    next();
};


// --- 6. ĐỊNH NGHĨA CÁC ĐIỂM CUỐI (API ENDPOINTS) ---

app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

app.post('/giai-ma', securityMiddleware, async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body;
    const ip = req.ip;

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
            handleFailedAttempt(ip, visitorId); 
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.' });
        }
        
        if (failedAttempts.has(ip)) {
            failedAttempts.delete(ip);
        }
        
        console.log(`[SUCCESS] reCAPTCHA valid for IP: ${ip}`);
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

// --- 7. KHỞI CHẠY SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
