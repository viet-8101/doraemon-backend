// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch'; // Cập nhật import cho ES Modules
import dotenv from 'dotenv'; // Cập nhật import cho ES Modules

dotenv.config(); // Gọi config sau khi import

// --- 2. KHỞI TẠO ỨNG DỤNG ---
const app = express();
const PORT = process.env.PORT || 3000; // Sử dụng cổng của Render hoặc 3000 nếu chạy cục bộ

app.use(cors({
    origin: 'https://viet-8101.github.io/giai-ma-doraemon' // ĐÃ SỬA LẠI ĐÚNG ĐỊA CHỈ FRONTEND
}));

app.use(express.json());
app.set('trust proxy', 1); // Nếu app chạy sau proxy/nginx

// --- 3. BIẾN BẢO MẬT ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
if (!RECAPTCHA_SECRET_KEY) {
    console.error('Lỗi: RECAPTCHA_SECRET_KEY chưa được đặt!');
    process.exit(1);
}

const BANNED_IPS = new Map();  // ip -> banExpires timestamp
const BANNED_FINGERPRINTS = new Set(); // visitorId bị banned vĩnh viễn

const BAN_DURATION_MS = 12 * 60 * 60 * 1000; // 12 giờ
const FAILED_ATTEMPTS_THRESHOLD = 5;
const FAILED_ATTEMPTS_RESET_MS = 60 * 60 * 1000; // reset count sau 1 giờ

// Lưu số lần fail reCAPTCHA theo IP
const failedAttempts = new Map(); // ip -> { count, lastFailTime }

// --- 4. TỪ ĐIỂN DORAEMON ---
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

// --- 5. HỖ TRỢ BẢO MẬT ---

// Hàm lấy IP thực của client từ X-Forwarded-For hoặc req.ip
function getClientIp(req) {
    const forwardedIpsStr = req.headers['x-forwarded-for'];
    if (forwardedIpsStr) {
        // X-Forwarded-For có thể chứa nhiều IP (client, proxy1, proxy2...).
        // IP đầu tiên trong chuỗi thường là IP thực của client.
        const forwardedIps = forwardedIpsStr.split(',');
        return forwardedIps[0].trim();
    }
    // Nếu không có X-Forwarded-For, dùng req.ip
    return req.ip;
}

// Chuẩn hóa IP (loại bỏ ::ffff: để tránh trùng IP)
function normalizeIp(ip) {
    if (ip && ip.startsWith('::ffff:')) { // Thêm kiểm tra ip tồn tại
        return ip.substring(7);
    }
    return ip;
}

// Ghi nhận lần fail reCAPTCHA, nếu vượt ngưỡng sẽ banned
function handleFailedAttempt(ip, visitorId) {
    const now = Date.now();
    let data = failedAttempts.get(ip);

    if (!data || now - data.lastFailTime > FAILED_ATTEMPTS_RESET_MS) {
        // reset nếu quá thời gian
        data = { count: 1, lastFailTime: now };
    } else {
        data.count++;
        data.lastFailTime = now;
    }

    failedAttempts.set(ip, data);

    console.warn(`[RECAPTCHA FAIL] IP: ${ip} thất bại lần ${data.count}`);

    if (data.count >= FAILED_ATTEMPTS_THRESHOLD) {
        const banExpiresAt = now + BAN_DURATION_MS;
        BANNED_IPS.set(ip, banExpiresAt);
        if (visitorId) {
            BANNED_FINGERPRINTS.add(visitorId); // banned vĩnh viễn fingerprint
        }
        failedAttempts.delete(ip);
        const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
        console.error(`[TEMP-BAN] IP: ${ip} bị banned đến ${banExpiresDate}, visitorId ${visitorId} banned vĩnh viễn.`);
    }
}

// Middleware kiểm tra banned IP và fingerprint
function securityMiddleware(req, res, next) {
    // Lấy IP client thực
    const clientIpRaw = getClientIp(req);
    const ip = normalizeIp(clientIpRaw);
    const visitorId = req.body.visitorId;

    // // ĐÃ XÁC NHẬN IP, CÓ THỂ BỎ COMMENT CÁC DÒNG DEBUG NÀY ĐI
    // console.log(`[DEBUG Middleware IP] req.ip (Original): ${req.ip}`);
    // console.log(`[DEBUG Middleware IP] X-Forwarded-For: ${req.headers['x-forwarded-for']}`);
    // console.log(`[DEBUG Middleware IP] Client IP (processed): ${ip}`);


    // Kiểm tra banned vĩnh viễn fingerprint
    if (visitorId && BANNED_FINGERPRINTS.has(visitorId)) {
        return res.status(403).json({ error: 'Truy cập của bạn đã bị chặn vĩnh viễn.' });
    }

    // Kiểm tra banned tạm thời IP
    const banExpiresAt = BANNED_IPS.get(ip);
    if (banExpiresAt) {
        if (Date.now() < banExpiresAt) {
            const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
            return res.status(403).json({ error: `IP của bạn đang bị chặn tạm thời. Vui lòng thử lại sau: ${banExpiresDate}` });
        } else {
            BANNED_IPS.delete(ip);
            console.log(`[UNBAN] IP ${ip} đã được gỡ chặn.`);
        }
    }

    next();
}

// --- 6. API ENDPOINTS ---

// Kiểm tra server có hoạt động hay không
app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

// API để giải mã từ điển Doraemon và xác thực reCAPTCHA
app.post('/giai-ma', securityMiddleware, async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body;
    
    // Lấy IP client thực cho endpoint này
    const clientIpRaw = getClientIp(req);
    const ip = normalizeIp(clientIpRaw);

    // // ĐÃ XÁC NHẬN IP, CÓ THỂ BỎ COMMENT CÁC DÒNG DEBUG NÀY ĐI
    // console.log(`[DEBUG Endpoint IP] req.ip (Original): ${req.ip}`);
    // console.log(`[DEBUG Endpoint IP] X-Forwarded-For: ${req.headers['x-forwarded-for']}`);
    // console.log(`[DEBUG Endpoint IP] Client IP (processed): ${ip}`);

    // Kiểm tra đầu vào
    if (!userInput || !recaptchaToken) {
        return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.' });
    }

    try {
        // Kiểm tra reCAPTCHA
        const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify`;
        const params = new URLSearchParams();
        params.append('secret', RECAPTCHA_SECRET_KEY);
        params.append('response', recaptchaToken);

        const verificationResponse = await fetch(recaptchaVerificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });

        const recaptchaData = await verificationResponse.json();

        // Nếu reCAPTCHA không thành công, ghi nhận lần thất bại
        if (!recaptchaData.success) {
            handleFailedAttempt(ip, visitorId);
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.' });
        }

        // Reset lại failedAttempts nếu reCAPTCHA thành công
        if (failedAttempts.has(ip)) {
            failedAttempts.delete(ip);
        }

        console.log(`[SUCCESS] reCAPTCHA valid cho IP: ${ip}`);

        // Xử lý từ điển Doraemon
        let text = userInput.trim().toLowerCase();
        const entries = Object.entries(tuDienDoraemon).sort((a, b) => b[0].length - a[0].length); // Sắp xếp theo độ dài từ khóa
        let replaced = false;
        
        // Tìm kiếm và thay thế các từ khóa
        for (const [k, v] of entries) {
            const re = new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'); // Đảm bảo ký tự đặc biệt được escape
            if (text.match(re)) {
                text = text.replace(re, v);
                replaced = true;
            }
        }

        const ketQua = replaced ? text : "Không tìm thấy từ khóa phù hợp trong từ điển.";

        res.json({ success: true, ketQua });

    } catch (error) {
        console.error('Lỗi server:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});

// --- 7. KHỞI ĐỘNG SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
