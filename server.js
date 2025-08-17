// server.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Firebase Admin SDK imports
import admin from 'firebase-admin';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

dotenv.config();

// --- THÊM CÁC CƠ CHẾ BẮT LỖI TOÀN CỤC ---
process.on('unhandledRejection', (reason, promise) => {
    console.error('Lỗi không được xử lý (Unhandled Rejection) ở Promise:', promise, 'Lý do:', reason);
});

process.on('uncaughtException', (err, origin) => {
    console.error('Lỗi không được bắt (Uncaught Exception):', err, 'Nguồn gốc:', origin);
});

// --- 2. KHỞI TẠO ỨNG DỤNG ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: [
        'https://viet-8101.github.io',
        'https://viet-8101.github.io/admin-dashboard-doraemon/',
        'http://localhost:5173',
        'https://admin-dashboard-doraemon.onrender.com',
        'http://localhost:3000',
    ],
    credentials: true,
}));
app.use(express.json());
app.set('trust proxy', 1);

// --- THÊM CÁC HTTP SECURITY HEADERS ---
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' https://www.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    );
    next();
});

// --- 3. KẾT NỐI FIREBASE ADMIN SDK VÀ FIRESTORE ---
let db = null;
let firebaseAdminInitialized = false;

const initializeFirebaseAdmin = async () => {
    try {
        if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
            console.error('Lỗi: Thiếu biến môi trường FIREBASE_SERVICE_ACCOUNT_KEY.');
            return;
        }

        const serviceAccount = JSON.parse(
            Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_KEY, 'base64').toString('utf-8')
        );

        if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
        }

        db = getFirestore();
        firebaseAdminInitialized = true;
        console.log('Kết nối Firebase Admin SDK thành công.');
    } catch (error) {
        console.error('Lỗi khi kết nối Firebase Admin SDK:', error);
        firebaseAdminInitialized = false;
        db = null; // Ensure db is null on failure
    }
};

// Lấy app_id từ môi trường Render (hoặc dùng mặc định nếu chạy cục bộ không có)
const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id';

// Lấy tham chiếu đến collection admin_data
const getAdminDataDocRef = () => {
    if (!db) {
        console.error('Firestore chưa được khởi tạo hoặc không khả dụng. Không thể truy cập admin_data.');
        return null;
    }
    return db.collection('artifacts').doc(appId).collection('public').doc('data').collection('admin_data').doc('main_data');
};

const getAdminData = async () => {
    const docRef = getAdminDataDocRef();
    if (!docRef) return {};

    try {
        const docSnap = await docRef.get();
        if (docSnap.exists) {
            return docSnap.data();
        } else {
            const initialData = {
                banned_ips: {},
                banned_fingerprints: {},
                total_requests: 0,
                total_failed_recaptcha: 0,
                failedAttempts: {}
            };
            await docRef.set(initialData);
            return initialData;
        }
    } catch (error) {
        console.error('Lỗi khi lấy admin data từ Firestore:', error);
        return {};
    }
};

const updateAdminData = async (dataToUpdate) => {
    const docRef = getAdminDataDocRef();
    if (!docRef) {
        console.error('Firestore chưa được khởi tạo hoặc không khả dụng. Không thể cập nhật admin_data.');
        return;
    }
    try {
        await docRef.set(dataToUpdate, { merge: true });
    } catch (error) {
        console.error('Lỗi khi cập nhật admin data vào Firestore:', error);
    }
};

// --- 4. BIẾN BẢO MẬT VÀ CẤU HÌNH ADMIN ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const TFA_SECRET = process.env.TFA_SECRET || crypto.randomBytes(32).toString('hex');

if (!RECAPTCHA_SECRET_KEY || !ADMIN_USERNAME || !ADMIN_PASSWORD || !TFA_SECRET) {
    console.error('Lỗi: Thiếu một trong các biến môi trường cần thiết: RECAPTCHA_SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD hoặc TFA_SECRET!');
}

// --- 5. HỖ TRỢ BẢO MẬT VÀ CÁC HÀM TIỆN ÍCH ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000; // 12 giờ cho ban tạm thời (từ reCAPTCHA)
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER;
const FAILED_ATTEMPTS_THRESHOLD = 5;
const FAILED_ATTEMPTS_RESET_MS = 30 * 60 * 1000;

// Hàm lấy IP thực của client từ X-Forwarded-For hoặc req.ip
function getClientIp(req) {
    const forwardedIpsStr = req.headers['x-forwarded-for'];
    if (forwardedIpsStr) {
        const forwardedIps = forwardedIpsStr.split(',');
        return forwardedIps[0].trim();
    }
    return req.ip;
}

// Chuẩn hóa IP (loại bỏ ::ffff: để tránh trùng IP)
function normalizeIp(ip) {
    if (ip && ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip;
}

// Hàm xác thực và làm sạch đầu vào người dùng
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return '';
    }
    const MAX_INPUT_LENGTH = 200;
    let sanitized = input.trim().toLowerCase();

    if (sanitized.length > MAX_INPUT_LENGTH) {
        sanitized = sanitized.substring(0, MAX_INPUT_LENGTH);
    }
    sanitized = sanitized.replace(/[^a-z0-9àáạảãăắằặẳẵâấầậẩẫèéẹẻẽêếềệểễìíịỉĩòóọỏõôốồộổỗơớờợởỡùúụủũưứừựửữđ\s.,!?-]/g, '');
    return sanitized;
}

// Ghi nhận lần fail reCAPTCHA, nếu vượt ngưỡng sẽ banned
async function handleFailedAttempt(ip, visitorId) {
    const now = Date.now();
    const adminData = await getAdminData();
    const currentBannedIps = adminData.banned_ips || {};
    const currentBannedFingerprints = adminData.banned_fingerprints || {};

    let data = adminData.failedAttempts?.[ip] || { count: 0, lastFailTime: 0 };

    if (now - data.lastFailTime > FAILED_ATTEMPTS_RESET_MS) {
        data = { count: 1, lastFailTime: now };
    } else {
        data.count++;
        data.lastFailTime = now;
    }

    if (db) {
        await updateAdminData({
            [`failedAttempts.${ip}`]: data,
            total_failed_recaptcha: FieldValue.increment(1)
        });
        console.log(`[FAILED-ATTEMPT-RECORDED] Lần thất bại mới đã được ghi nhận cho IP: ${ip}, tổng số lần là: ${data.count}`);
    } else {
        console.warn('Firestore chưa được khởi tạo, không thể ghi nhận thất bại reCAPTCHA vào Firestore.');
    }

    console.warn(`[RECAPTCHA FAIL] IP: ${ip} thất bại lần ${data.count}`);

    if (data.count >= FAILED_ATTEMPTS_THRESHOLD) {
        const banExpiresAt = now + BAN_DURATION_MS;
        currentBannedIps[ip] = banExpiresAt;
        if (visitorId) {
            currentBannedFingerprints[visitorId] = banExpiresAt;
        }
        
        if (db) {
            await updateAdminData({
                banned_ips: currentBannedIps,
                banned_fingerprints: currentBannedFingerprints,
                [`failedAttempts.${ip}`]: FieldValue.delete()
            });
        } else {
             console.warn('Firestore chưa được khởi tạo, không thể cập nhật danh sách ban.');
        }

        const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
        console.error(`[TEMP-BAN] IP: ${ip} bị banned đến ${banExpiresDate}, visitorId ${visitorId || 'N/A'} banned tạm thời.`);
    }
}

// Middleware kiểm tra banned IP và fingerprint
async function securityMiddleware(req, res, next) {
    const clientIpRaw = getClientIp(req);
    const ip = normalizeIp(clientIpRaw);
    const visitorId = req.body.visitorId;

    console.log(`[SECURITY-CHECK] Bắt đầu kiểm tra IP: ${ip}, VisitorId: ${visitorId}`);

    const adminData = await getAdminData();
    const currentBannedIps = adminData.banned_ips || {};
    const currentBannedFingerprints = adminData.banned_fingerprints || {};
    
    // Kiểm tra banned fingerprint
    if (visitorId && currentBannedFingerprints[visitorId]) {
        const banExpiresAt = currentBannedFingerprints[visitorId];
        if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
            const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
            return res.status(403).json({ error: `Truy cập của bạn đã bị chặn ${banMessage}.` });
        } else if (Date.now() >= banExpiresAt) {
            delete currentBannedFingerprints[visitorId];
            if (db) {
                await updateAdminData({ banned_fingerprints: currentBannedFingerprints });
            }
            console.log(`[UNBAN] Fingerprint ${visitorId} đã được gỡ chặn tự động.`);
        }
    }

    // Kiểm tra banned IP
    const banExpiresAt = currentBannedIps[ip];
    if (banExpiresAt) {
        if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
            const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
            return res.status(403).json({ error: `IP của bạn đang bị chặn ${banMessage}.` });
        } else if (Date.now() >= banExpiresAt) {
            delete currentBannedIps[ip];
            if (db) {
                await updateAdminData({ banned_ips: currentBannedIps });
            }
            console.log(`[UNBAN] IP ${ip} đã được gỡ chặn tự động.`);
        }
    }

    next();
}

// Middleware xác thực admin
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Không tìm thấy Token xác thực.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') {
            req.user = decoded;
            next();
        } else {
            res.status(403).json({ error: 'Truy cập bị từ chối, bạn không có quyền Admin.' });
        }
    } catch (err) {
        res.status(403).json({ error: 'Token không hợp lệ hoặc đã hết hạn.' });
    }
};

// --- 6. TỪ ĐIỂN DORAEMON ---
const tuDienDoraemon = {
    "cái loa biết đi": "Jaian", "thánh chảnh": "Suneo", "cục nợ quốc dân": "Nobita", "trùm chém gió": "Suneo", "boss ăn vặt": "Doraemon", "siêu nhân gục ngã": "Nobita", "máy phát kẹo": "Doraemon", "ổ bom di động": "Jaian", "thánh phá đồ": "Nobita", "chuyên gia gây họa": "Nobita", "nhà tài trợ nước mắt": "mẹ Nobita", "lò luyện điểm 0": "lớp học của Nobita", "trùm thất tình": "Nobita", "đứa trẻ cuối cùng của mushika": "Micca", "máy ATM biết đi": "Doraemon", "trí tuệ nhân tạo có tâm": "Doraemon", "con tinh tinh": "Jaian", "con khỉ đột": "Jaian", "khỉ đột": "Jaian", "tinh tinh": "Jaian", "con cáo": "Suneo", "cáo": "Suneo", "bạch tuộc": "Noise", "quần dài": "2 con cá trắm đen đc làm ở Pháp rất là mắc tiền (của Suneo)", "mụ phù thủy": "mẹ của Nobita", "tên ngốc hậu hậu": "Nobita", "tên robinson phiền phức": "Nobita", "thiên tài ngủ": "Nobita", "diễn viên suất sắc": "Nobita", "bậc thầy năn nỉ": "Nobita", "thiên tài thắt dây": "Nobita", "tay vua súng": "Nobita", "xe buýt": "Nobita", "xe bus": "Nobita", "mèo máy": "Doraemon", "mỏ nhọn": "Suneo", "lồi rốn": "Jaian", "yên ắng": "nhà Shizuka", "hình tròn": "bánh rán dorayaki", "kẻ tham lam": "Jaian", "hai người nổi tiếng ham ăn": "Jaian và Suneo", "điểm đen": "điểm 0", "bàn tay vàng trong làng ngáo ngơ": "Nobita", "cục tạ quốc dân": "Nobita", "đại ca sân trường": "Jaian", "người mẫu sừng sỏ": "Suneo", "cô gái tắm mỗi tập": "Shizuka", "vua bánh rán": "Doraemon", "thánh cầu cứu": "Nobita", "người đến từ tương lai": "Doraemon", "cây ATM sống": "Doraemon", "lồng tiếng động đất": "Jaian", "diễn viên chính của bi kịch": "Nobita", "fan cuồng công nghệ": "Suneo", "kẻ lười biếng nhỏ bé": "Nobita", "chồn xanh nhỏ đáng yêu": "Doraemon", "bình yên trước cơn bão": "nhà Shizuka", "cậu bé sáo lạc điệu": "Nobita", "loa phóng thanh biết đi": "Jaian", "trùm phá nốt": "Nobita", "người cứu âm nhạc địa cầu": "Doraemon", "quái vật hút âm": "bào tử noise", "người bạn đến từ hành tinh âm nhạc": "Micca", "thánh phá bản nhạc": "Nobita", "cây sáo truyền thuyết": "cây sáo dọc của mushika", "bản nhạc giải cứu trái đất": "bản giao hưởng địa cầu", "phi công nghiệp dư": "Nobita", "vùng đất trong mơ": "Utopia", "cư dân đám mây": "người sống ở Utopia", "nhà trên trời view đẹp": "Utopia", "người bạn Utopia": "Sonya", "trùm điều khiển thời tiết": "quản lý Utopia", "mặt trăng bay lạc": "Utopia", "chuyến phiêu lưu trên trời": "hành trình của nhóm Nobita", "lâu đài mây thần bí": "trung tâm điều hành Utopia", "trùm chấn động bầu trời": "Suneo lái máy bay", "cậu bé bay không bằng lái": "Nobita", "thánh nhảy moonwalk ngoài vũ trụ": "Nobita", "chuyên gia té không trọng lực": "Nobita", "trạm vũ trụ di động": "tàu của Doraemon", "người bạn tai dài trên mặt trăng": "Luca", "cư dân mặt trăng bí ẩn": "tộc người Espal", "đội thám hiểm mặt trăng": "nhóm Nobita", "mặt trăng giả tưởng": "thế giới do bảo bối tạo ra", "cuộc chiến không trọng lực": "trận đấu trên mặt trăng", "lũ bạn ngoài hành tinh đáng yêu": "Luca và đồng bọn", "bầu trời đêm đầy ảo mộng": "khung cảnh mặt trăng", "cậu bé lười biếng nhất thành phố": "Nobita", "cậu bé xấu tính nhất thành phố": "Jaian", "nhạc sĩ vũ trụ": "Trupet", "nhà soạn nhạc vĩ đại": "Trupet", "người sáng tác giao hưởng địa cầu": "Trupet", "chủ nhân bản giao hưởng địa cầu": "Trupet", "nhà sáng tạo âm nhạc vũ trụ": "Trupet", "nhạc sĩ bảo vệ hòa bình âm nhạc": "Trupet", "rùa siêu tốc vũ trụ": "Moto", "rùa vũ trụ có mai thép": "Moto", "rùa siêu bền": "Moto", "tốc độ vũ trụ từ mai rùa": "Moto", "vũ trụ đua rùa": "Moto", "con rùa nhanh nhất trong không gian": "Moto", "viên đạn của đại bác không khí": "Moto"
};

// --- 7. CÁC ENDPOINT API ---

// Endpoint kiểm tra trạng thái
app.get('/status', (req, res) => {
    res.json({
        message: 'Backend Doraemon đang chạy!',
        dbStatus: db ? 'Kết nối thành công' : 'Không kết nối được',
        firebaseAdminInitialized: firebaseAdminInitialized
    });
});

// Endpoint xác thực IP và Fingerprint (có thêm middleware bảo mật)
app.post('/check-access', securityMiddleware, async (req, res) => {
    const { ip, fingerprint, token, visitorId } = req.body;
    if (!ip || !fingerprint || !token) {
        return res.status(400).json({ error: 'Thiếu IP, Fingerprint, hoặc reCAPTCHA token.' });
    }

    // Xác thực reCAPTCHA
    const recaptchaUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`;
    try {
        const recaptchaRes = await fetch(recaptchaUrl, { method: 'POST' });
        const recaptchaData = await recaptchaRes.json();

        if (!recaptchaData.success || recaptchaData.score < 0.5) {
            console.warn(`[RECAPTCHA FAILED] Score: ${recaptchaData.score}, IP: ${ip}`);
            await handleFailedAttempt(ip, visitorId);
            return res.status(403).json({ error: 'Xác thực reCAPTCHA thất bại. Vui lòng thử lại.' });
        }
    } catch (error) {
        console.error('Lỗi khi xác thực reCAPTCHA:', error);
        return res.status(500).json({ error: 'Lỗi server khi xác thực reCAPTCHA.' });
    }

    let adminData = null;
    try {
        adminData = await getAdminData();
    } catch (error) {
        console.error('Lỗi khi lấy dữ liệu Admin:', error);
        return res.status(500).json({ error: 'Lỗi server khi kiểm tra quyền truy cập.' });
    }

    // Tăng tổng số yêu cầu
    if (db) {
        try {
            await updateAdminData({
                total_requests: FieldValue.increment(1)
            });
        } catch (error) {
            console.error('Lỗi khi tăng total_requests:', error);
        }
    }

    res.json({ accessGranted: true, message: 'Truy cập được cấp phép.' });
});

// Endpoint trả về từ điển
app.get('/dictionary', (req, res) => {
    res.json(tuDienDoraemon);
});

// Endpoint tra cứu từ điển
app.post('/lookup', (req, res) => {
    const { keyword } = req.body;
    const sanitizedKeyword = sanitizeInput(keyword);
    console.log(`[LOOKUP] Từ khóa được tra cứu: "${sanitizedKeyword}"`);

    const result = tuDienDoraemon[sanitizedKeyword];
    if (result) {
        res.json({ found: true, character: result });
    } else {
        res.json({ found: false, message: "Không tìm thấy từ khóa này trong từ điển." });
    }
});

// API ADMIN DASHBOARD

// API Bước 1: Đăng nhập bằng tên đăng nhập/mật khẩu
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const tfaCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const expiryTime = Date.now() + 5 * 60 * 1000;
        
        const tfaToken = jwt.sign(
            { username: ADMIN_USERNAME, tfaCode, expiryTime },
            TFA_SECRET,
            { expiresIn: '5m' } 
        );

        console.log(`Mã xác thực của bạn là ${tfaCode}. Mã đó có hiệu lực trong 5 phút.`);

        res.json({ 
            success: true, 
            message: 'Đăng nhập thành công bước 1. Vui lòng kiểm tra log trên Render để lấy mã xác thực và nhập vào.', 
            tfaToken 
        });
    } else {
        res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
    }
});

// API Bước 2: Xác thực mã 2FA
app.post('/admin/verify-tfa', async (req, res) => {
    const { tfaToken, tfaCode } = req.body;

    if (!tfaToken || !tfaCode) {
        return res.status(400).json({ error: 'Thiếu token hoặc mã xác thực.' });
    }

    try {
        const decoded = jwt.verify(tfaToken, TFA_SECRET);

        if (decoded.tfaCode === tfaCode.toUpperCase()) {
            if (Date.now() > decoded.expiryTime) {
                return res.status(401).json({ error: 'Mã xác thực đã hết hạn. Vui lòng đăng nhập lại.' });
            }

            const adminToken = jwt.sign({ username: ADMIN_USERNAME, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ success: true, adminToken, message: 'Đăng nhập thành công!' });
        } else {
            return res.status(401).json({ error: 'Mã xác thực không đúng.' });
        }
    } catch (err) {
        return res.status(403).json({ error: 'Phiên xác thực đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.', details: err.message });
    }
});

// Endpoint lấy dữ liệu dashboard (yêu cầu xác thực admin)
app.get('/admin/dashboard-data', authenticateAdmin, async (req, res) => {
    let adminData = null;
    try {
        adminData = await getAdminData();
        if (!adminData) {
            return res.status(500).json({ error: 'Không thể lấy dữ liệu dashboard.' });
        }
    } catch (error) {
        console.error('Lỗi khi lấy dữ liệu dashboard:', error);
        return res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ khi lấy dữ liệu.' });
    }
    res.json(adminData);
});

// Endpoint để ban IP hoặc Fingerprint (yêu cầu xác thực admin)
app.post('/admin/ban', authenticateAdmin, async (req, res) => {
    const { type, value, duration } = req.body;
    if (!type || !value || !duration) {
        return res.status(400).json({ error: 'Thiếu type, value, hoặc duration.' });
    }

    if (!db) {
        return res.status(500).json({ error: 'Firestore không khả dụng.' });
    }

    try {
        let adminData = await getAdminData();
        const now = Date.now();
        const banExpiresAt = duration === 'permanent' ? PERMANENT_BAN_VALUE : now + parseInt(duration) * 60 * 60 * 1000;

        let message = '';
        let banned = false;
        if (type === 'ip') {
            if (adminData.banned_ips[value] && adminData.banned_ips[value] > now) {
                message = `IP: ${value} đã bị ban từ trước.`;
            } else {
                adminData.banned_ips[value] = banExpiresAt;
                banned = true;
                message = `Đã ban thành công IP: ${value} ${duration === 'permanent' ? 'vĩnh viễn' : `trong ${duration} giờ`}.`;
            }
        } else if (type === 'fingerprint') {
            if (adminData.banned_fingerprints[value] && adminData.banned_fingerprints[value] > now) {
                message = `Fingerprint: ${value} đã bị ban từ trước.`;
            } else {
                adminData.banned_fingerprints[value] = banExpiresAt;
                banned = true;
                message = `Đã ban thành công Fingerprint: ${value} ${duration === 'permanent' ? 'vĩnh viễn' : `trong ${duration} giờ`}.`;
            }
        } else {
            return res.status(400).json({ error: 'Loại ban không hợp lệ.' });
        }

        if (banned) {
            await updateAdminData({
                banned_ips: adminData.banned_ips,
                banned_fingerprints: adminData.banned_fingerprints
            });
        }
        
        res.json({ success: true, message });
    } catch (error) {
        console.error(`Lỗi khi ban ${type}:`, error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});

// Endpoint để unban IP hoặc Fingerprint (yêu cầu xác thực admin)
app.post('/admin/unban', authenticateAdmin, async (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) {
        return res.status(400).json({ error: 'Thiếu type hoặc value.' });
    }

    if (!db) {
        return res.status(500).json({ error: 'Firestore không khả dụng.' });
    }

    try {
        let adminData = await getAdminData();
        let message = '';
        let unbanned = false;
        if (type === 'ip') {
            if (adminData.banned_ips[value]) {
                delete adminData.banned_ips[value];
                unbanned = true;
                message = `Đã unban thành công IP: ${value}.`;
                console.log(`[ADMIN UNBAN] IP ${value} đã được gỡ ban.`);
            } else {
                message = `IP: ${value} không bị ban.`;
            }
        } else if (type === 'fingerprint') {
            if (adminData.banned_fingerprints[value]) {
                delete adminData.banned_fingerprints[value];
                unbanned = true;
                message = `Đã unban thành công Fingerprint: ${value}.`;
                console.log(`[ADMIN UNBAN] Fingerprint ${value} đã được gỡ ban.`);
            } else {
                message = `Fingerprint: ${value} không bị ban.`;
            }
        } else {
            return res.status(400).json({ error: 'Loại unban không hợp lệ.' });
        }

        if (unbanned) {
            await updateAdminData({
                banned_ips: adminData.banned_ips,
                banned_fingerprints: adminData.banned_fingerprints
            });
        }
        
        res.json({ success: true, message });
    } catch (error) {
        console.error(`Lỗi khi unban ${type}:`, error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});

// Khởi động server
(async () => {
    // Attempt to initialize Firebase Admin SDK
    await initializeFirebaseAdmin();

    // The app will now listen on the port regardless of Firebase initialization status.
    // If Firebase initialization failed, the `db` variable will be null, and
    // database-dependent functions will handle the error gracefully.
    app.listen(PORT, () => {
        console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
        if (!firebaseAdminInitialized) {
            console.warn('Lưu ý: Firebase Admin SDK không được khởi tạo. Các chức năng liên quan đến cơ sở dữ liệu sẽ không hoạt động.');
        }
    });
})();
