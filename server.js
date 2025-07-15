// server.js - BỘ NÃO AN TOÀN CỦA ỨNG DỤNG (bỏ kiểm tra VPN, giữ bảo mật tấn công)

// --- 1. IMPORT CÁC THƯ VIỆN ---
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch'); // cần cài package node-fetch
require('dotenv').config();

// --- 2. KHỞI TẠO ỨNG DỤNG ---
const app = express();
const PORT = 3000;

// CORS an toàn, chỉ cho phép frontend truy cập
app.use(cors({
    origin: 'https://viet-8101.github.io'
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

// --- 4. TỪ ĐIỂN DORAEMON (giữ nguyên) ---
const tuDienDoraemon = {
    // ... (giữ nguyên từ điển như bạn gửi)
// server.js - BỘ NÃO AN TOÀN CỦA ỨNG DỤNG (bỏ kiểm tra VPN, giữ bảo mật tấn công)

// --- 1. IMPORT CÁC THƯ VIỆN ---
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch'); // cần cài package node-fetch
require('dotenv').config();

// --- 2. KHỞI TẠO ỨNG DỤNG ---
const app = express();
const PORT = 3000;

// CORS an toàn, chỉ cho phép frontend truy cập
app.use(cors({
    origin: 'https://viet-8101.github.io'
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

// --- 4. TỪ ĐIỂN DORAEMON (giữ nguyên) ---
const tuDienDoraemon = {
    // ... (giữ nguyên từ điển như bạn gửi)
    "cái loa biết đi": "Jaian",
    "thánh chảnh": "Suneo",
    "cục nợ quốc dân": "Nobita",
    "trùm chém gió": "Suneo",
    "boss ăn vặt": "Doraemon",
    // ... tiếp tục
    "viên đạn của đại bác không khí": "Moto"
};

// --- 5. HỖ TRỢ BẢO MẬT ---

// Chuẩn hóa IP (loại bỏ ::ffff:)
function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
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
    const ipRaw = req.ip;
    const ip = normalizeIp(ipRaw);
    const visitorId = req.body.visitorId;

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

app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

app.post('/giai-ma', securityMiddleware, async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body;
    const ipRaw = req.ip;
    const ip = normalizeIp(ipRaw);

    if (!userInput || !recaptchaToken) {
        return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.' });
    }

    try {
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

        if (!recaptchaData.success) {
            handleFailedAttempt(ip, visitorId);
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.' });
        }

        // reset failedAttempts nếu trước đó có
        if (failedAttempts.has(ip)) {
            failedAttempts.delete(ip);
        }

        console.log(`[SUCCESS] reCAPTCHA valid cho IP: ${ip}`);

        // Xử lý từ điển Doraemon
        let text = userInput.trim().toLowerCase();
        const entries = Object.entries(tuDienDoraemon).sort((a, b) => b[0].length - a[0].length);
        let replaced = false;
        for (const [k, v] of entries) {
            const re = new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
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

};

// --- 5. HỖ TRỢ BẢO MẬT ---

// Chuẩn hóa IP (loại bỏ ::ffff:)
function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
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
    const ipRaw = req.ip;
    const ip = normalizeIp(ipRaw);
    const visitorId = req.body.visitorId;

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

app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

app.post('/giai-ma', securityMiddleware, async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body;
    const ipRaw = req.ip;
    const ip = normalizeIp(ipRaw);

    if (!userInput || !recaptchaToken) {
        return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.' });
    }

    try {
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

        if (!recaptchaData.success) {
            handleFailedAttempt(ip, visitorId);
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.' });
        }

        // reset failedAttempts nếu trước đó có
        if (failedAttempts.has(ip)) {
            failedAttempts.delete(ip);
        }

        console.log(`[SUCCESS] reCAPTCHA valid cho IP: ${ip}`);

        // Xử lý từ điển Doraemon
        let text = userInput.trim().toLowerCase();
        const entries = Object.entries(tuDienDoraemon).sort((a, b) => b[0].length - a[0].length);
        let replaced = false;
        for (const [k, v] of entries) {
            const re = new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
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
