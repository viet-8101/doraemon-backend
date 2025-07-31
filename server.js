// server.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'; // Để tạo và xác minh token admin
import crypto from 'crypto'; // Cần cho crypto.randomBytes nếu JWT_SECRET không có trong ENV

// Firebase Admin SDK imports
import admin from 'firebase-admin';
import { getFirestore, FieldValue } from 'firebase-admin/firestore'; // Sử dụng FieldValue từ admin SDK

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
        'https://viet-8101.github.io/admin-dashboard-doraemon/', // URL cụ thể của Dashboard trên GitHub Pages
        'http://localhost:5173',      // Cổng mặc định của Vite dev server (giữ lại để phát triển cục bộ)
        'http://localhost:3001',      // Cổng của frontend có thể khác 3000 (nếu bạn dùng)
        'https://admin-dashboard-doraemon.onrender.com',
        'http://localhost:3000',      // Cổng của backend mặc định (nếu bạn dùng)
        // Thêm URL Firebase Hosting của bạn vào đây khi bạn triển khai frontend lên Firebase (nếu có)
        // Ví dụ: 'https://your-firebase-project-id.web.app',
        // 'https://your-firebase-project-id.firebaseapp.com'
    ]
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

// --- 3. BIẾN BẢO MẬT VÀ CẤU HÌNH ADMIN ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

if (!RECAPTCHA_SECRET_KEY || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('Lỗi: RECAPTCHA_SECRET_KEY, ADMIN_USERNAME hoặc ADMIN_PASSWORD chưa được đặt trong biến môi trường!');
}

// --- KHỞI TẠO FIREBASE ADMIN SDK ---
let db; // Firestore instance
let firebaseAdminInitialized = false; // Biến cờ để theo dõi trạng thái khởi tạo

async function initializeFirebaseAdmin() {
    console.log('Firebase Init: Bắt đầu khởi tạo Firebase Admin SDK...');
    // Đảm bảo chỉ khởi tạo một lần
    if (admin.apps.length > 0) {
        db = getFirestore();
        firebaseAdminInitialized = true;
        console.log('Firebase Init: Firebase Admin SDK đã được khởi tạo trước đó.');
        return;
    }

    const serviceAccountKeyString = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
    if (!serviceAccountKeyString) {
        console.error('Firebase Init: Lỗi: FIREBASE_SERVICE_ACCOUNT_KEY chưa được đặt trong biến môi trường! Firestore sẽ không hoạt động.');
        db = null;
        return;
    }

    let serviceAccount;
    try {
        serviceAccount = JSON.parse(serviceAccountKeyString);
        console.log('Firebase Init: Firebase Service Account Key được đọc từ ENV.');
    } catch (e) {
        console.error('Firebase Init: Lỗi: FIREBASE_SERVICE_ACCOUNT_KEY không phải là chuỗi JSON hợp lệ.', e);
        db = null;
        return;
    }

    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        db = getFirestore(); // Lấy Firestore instance từ Admin SDK
        firebaseAdminInitialized = true;
        console.log('Firebase Init: Firebase Admin SDK đã được khởi tạo và kết nối với Firestore.');
    } catch (error) {
        console.error('Firebase Init: Lỗi khi khởi tạo Firebase Admin SDK:', error);
        db = null;
    }
}

// Lấy app_id từ môi trường Render (hoặc dùng mặc định nếu chạy cục bộ không có)
const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id'; // Render cung cấp RENDER_SERVICE_ID

// --- 4. TỪ ĐIỂN DORAEMON ---
const tuDienDoraemon = {
    "cái loa biết đi": "Jaian", "thánh chảnh": "Suneo", "cục nợ quốc dân": "Nobita", "trùm chém gió": "Suneo", "boss ăn vặt": "Doraemon", "siêu nhân gục ngã": "Nobita", "máy phát kẹo": "Doraemon", "ổ bom di động": "Jaian", "thánh phá đồ": "Nobita", "chuyên gia gây họa": "Nobita", "nhà tài trợ nước mắt": "mẹ Nobita", "lò luyện điểm 0": "lớp học của Nobita", "trùm thất tình": "Nobita", "đứa trẻ cuối cùng của mushika": "Micca", "máy ATM biết đi": "Doraemon", "trí tuệ nhân tạo có tâm": "Doraemon", "con tinh tinh": "Jaian", "con khỉ đột": "Jaian", "khỉ đột": "Jaian", "tinh tinh": "Jaian", "con cáo": "Suneo", "cáo": "Suneo", "bạch tuộc": "Noise", "quần dài": "2 con cá trắm đen đc làm ở Pháp rất là mắc tiền (của Suneo)", "mụ phù thủy": "mẹ của Nobita", "tên ngốc hậu hậu": "Nobita", "tên robinson phiền phức": "Nobita", "thiên tài ngủ": "Nobita", "diễn viên suất sắc": "Nobita", "bậc thầy năn nỉ": "Nobita", "thiên tài thắt dây": "Nobita", "tay vua súng": "Nobita", "xe buýt": "Nobita", "xe bus": "Nobita", "mèo máy": "Doraemon", "mỏ nhọn": "Suneo", "lồi rốn": "Jaian", "yên ắng": "nhà Shizuka", "hình tròn": "bánh rán dorayaki", "kẻ tham lam": "Jaian", "hai người nổi tiếng ham ăn": "Jaian và Suneo", "điểm đen": "điểm 0", "bàn tay vàng trong làng ngáo ngơ": "Nobita", "cục tạ quốc dân": "Nobita", "đại ca sân trường": "Jaian", "người mẫu sừng sỏ": "Suneo", "cô gái tắm mỗi tập": "Shizuka", "vua bánh rán": "Doraemon", "thánh cầu cứu": "Nobita", "người đến từ tương lai": "Doraemon", "cây ATM sống": "Doraemon", "lồng tiếng động đất": "Jaian", "diễn viên chính của bi kịch": "Nobita", "fan cuồng công nghệ": "Suneo", "kẻ lười biếng nhỏ bé": "Nobita", "chồn xanh nhỏ đáng yêu": "Doraemon", "bình yên trước cơn bão": "nhà Shizuka", "cậu bé sáo lạc điệu": "Nobita", "loa phóng thanh biết đi": "Jaian", "trùm phá nốt": "Nobita", "người cứu âm nhạc địa cầu": "Doraemon", "quái vật hút âm": "bào tử noise", "người bạn đến từ hành tinh âm nhạc": "Micca", "thánh phá bản nhạc": "Nobita", "cây sáo truyền thuyết": "cây sáo dọc của mushika", "bản nhạc giải cứu trái đất": "bản giao hưởng địa cầu", "phi công nghiệp dư": "Nobita", "vùng đất trong mơ": "Utopia", "cư dân đám mây": "người sống ở Utopia", "nhà trên trời view đẹp": "Utopia", "người bạn Utopia": "Sonya", "trùm điều khiển thời tiết": "quản lý Utopia", "mặt trăng bay lạc": "Utopia", "chuyến phiêu lưu trên trời": "hành trình của nhóm Nobita", "lâu đài mây thần bí": "trung tâm điều hành Utopia", "trùm chấn động bầu trời": "Suneo lái máy bay", "cậu bé bay không bằng lái": "Nobita", "thánh nhảy moonwalk ngoài vũ trụ": "Nobita", "chuyên gia té không trọng lực": "Nobita", "trạm vũ trụ di động": "tàu của Doraemon", "người bạn tai dài trên mặt trăng": "Luca", "cư dân mặt trăng bí ẩn": "tộc người Espal", "đội thám hiểm mặt trăng": "nhóm Nobita", "mặt trăng giả tưởng": "thế giới do bảo bối tạo ra", "cuộc chiến không trọng lực": "trận đấu trên mặt trăng", "lũ bạn ngoài hành tinh đáng yêu": "Luca và đồng bọn", "bầu trời đêm đầy ảo mộng": "khung cảnh mặt trăng", "cậu bé lười biếng nhất thành phố": "Nobita", "cậu bé xấu tính nhất thành phố": "Jaian", "nhạc sĩ vũ trụ": "Trupet", "nhà soạn nhạc vĩ đại": "Trupet", "người sáng tác giao hưởng địa cầu": "Trupet", "chủ nhân bản giao hưởng địa cầu": "Trupet", "nhà sáng tạo âm nhạc vũ trụ": "Trupet", "nhạc sĩ bảo vệ hòa bình âm nhạc": "Trupet", "rùa siêu tốc vũ trụ": "Moto", "rùa vũ trụ có mai thép": "Moto", "rùa siêu bền": "Moto", "tốc độ vũ trụ từ mai rùa": "Moto", "vũ trụ đua rùa": "Moto", "con rùa nhanh nhất trong không gian": "Moto", "viên đạn của đại bác không khí": "Moto"
};

// --- 5. HỖ TRỢ BẢO MẬT VÀ FIREBASE ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000; // 12 giờ cho ban tạm thời (từ reCAPTCHA)
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER; // Giá trị biểu thị ban vĩnh viễn
const FAILED_ATTEMPTS_THRESHOLD = 5;
const FAILED_ATTEMPTS_RESET_MS = 30 * 60 * 1000; // Đã thay đổi: reset count sau 30 phút

// Lấy tham chiếu đến collection admin_data
const getAdminDataDocRef = () => {
    if (!db) {
        console.error('Firestore chưa được khởi tạo hoặc không khả dụng. Không thể truy cập admin_data.');
        return null;
    }
    // Sử dụng appId để tạo đường dẫn collection động
    return db.collection('artifacts').doc(appId).collection('public').doc('data').collection('admin_data').doc('main_data'); // Thay đổi đường dẫn cho Admin SDK
};

async function getAdminData() {
    const docRef = getAdminDataDocRef();
    if (!docRef) return {};

    try {
        const docSnap = await docRef.get(); // Sử dụng .get() cho Admin SDK
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
            await docRef.set(initialData); // Sử dụng .set() cho Admin SDK
            return initialData;
        }
    } catch (error) {
        console.error('Lỗi khi lấy admin data từ Firestore:', error);
        return {};
    }
}

async function updateAdminData(dataToUpdate) {
    const docRef = getAdminDataDocRef();
    if (!docRef) {
        console.error('Firestore chưa được khởi tạo hoặc không khả dụng. Không thể cập nhật admin_data.');
        return;
    }
    try {
        await docRef.update(dataToUpdate); // Sử dụng .update() cho Admin SDK
    } catch (error) {
        console.error('Lỗi khi cập nhật admin data vào Firestore:', error);
    }
}

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

    if (now - data.lastFailTime > FAILED_ATTEMPTS_RESET_MS) { // Nếu thời gian giữa các lần thất bại lớn hơn ngưỡng reset
        data = { count: 1, lastFailTime: now }; // Đặt lại số lần thất bại về 1
    } else {
        data.count++; // Tăng số lần thất bại
        data.lastFailTime = now;
    }

    if (db) { // Chỉ cập nhật nếu Firestore đã được khởi tạo
        await updateAdminData({
            [`failedAttempts.${ip}`]: data,
            total_failed_recaptcha: FieldValue.increment(1) // Sử dụng FieldValue.increment
        });
    } else {
        console.warn('Firestore chưa được khởi tạo, không thể ghi nhận thất bại reCAPTCHA vào Firestore.');
    }

    console.warn(`[RECAPTCHA FAIL] IP: ${ip} thất bại lần ${data.count}`);

    if (data.count >= FAILED_ATTEMPTS_THRESHOLD) {
        const banExpiresAt = now + BAN_DURATION_MS; // Vẫn dùng BAN_DURATION_MS cho ban tạm thời từ reCAPTCHA
        currentBannedIps[ip] = banExpiresAt;
        if (visitorId) {
            // Fingerprint từ reCAPTCHA cũng sẽ bị ban tạm thời
            currentBannedFingerprints[visitorId] = banExpiresAt;
        }
        
        if (db) { // Chỉ cập nhật nếu Firestore đã được khởi tạo
            await updateAdminData({
                banned_ips: currentBannedIps,
                banned_fingerprints: currentBannedFingerprints,
                [`failedAttempts.${ip}`]: FieldValue.delete() // Xóa mục failedAttempts khi ban
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
            // Fingerprint đã hết thời gian ban, gỡ ban tự động
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
            // IP đã hết thời gian ban, gỡ ban tự động
            delete currentBannedIps[ip];
            if (db) {
                await updateAdminData({ banned_ips: currentBannedIps });
            }
            console.log(`[UNBAN] IP ${ip} đã được gỡ chặn tự động.`);
        }
    }

    next();
}

// Middleware xác thực Admin JWT
function authenticateAdminToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Không có token xác thực.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token không hợp lệ hoặc đã hết hạn.' });
        req.user = user;
        next();
    });
}

// --- 6. API ENDPOINTS ---

app.get('/', (req, res) => {
    res.status(200).send('Backend Doraemon đang chạy và hoạt động tốt!');
});

// --- Endpoint để lấy danh sách tất cả người dùng từ Firebase Authentication ---
// Đây là endpoint mới cho UsersPage trên frontend
app.get('/api/users', authenticateAdminToken, async (req, res) => { // Thêm authenticateAdminToken để bảo vệ endpoint này
    if (!firebaseAdminInitialized || !admin.auth()) {
        console.error('Firebase Admin SDK hoặc Auth chưa được khởi tạo. Không thể lấy người dùng.');
        return res.status(503).json({ error: 'Dịch vụ xác thực người dùng chưa sẵn sàng.' });
    }
    try {
        // Lấy tất cả người dùng từ Firebase Authentication
        const listUsersResult = await admin.auth().listUsers(1000); // Lấy tối đa 1000 người dùng
        const users = listUsersResult.users.map(userRecord => ({
            uid: userRecord.uid, // ID duy nhất của người dùng
            email: userRecord.email,
            displayName: userRecord.displayName || 'Người dùng mới', // displayName có thể null
            photoURL: userRecord.photoURL,
            emailVerified: userRecord.emailVerified,
            disabled: userRecord.disabled,
            createdAt: userRecord.metadata ? userRecord.metadata.creationTime : null,
            lastSignInTime: userRecord.metadata ? userRecord.metadata.lastSignInTime : null,
            // Bạn có thể thêm các trường khác từ userRecord nếu cần
            // Ví dụ: phoneNumber: userRecord.phoneNumber
        }));

        res.status(200).json(users);
    } catch (error) {
        console.error('Lỗi khi lấy danh sách người dùng từ Firebase Authentication:', error);
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách người dùng.', error: error.message });
    }
});


app.post('/giai-ma', securityMiddleware, async (req, res) => {
    const { userInput, recaptchaToken, visitorId } = req.body;
    
    const clientIpRaw = getClientIp(req);
    const ip = normalizeIp(clientIpRaw);

    if (db) { // Chỉ cập nhật nếu Firestore đã được khởi tạo
        await updateAdminData({ total_requests: FieldValue.increment(1) }); // Sử dụng FieldValue.increment
    } else {
        console.warn('Firestore chưa được khởi tạo, không thể cập nhật total_requests.');
    }

    if (!userInput || !recaptchaToken) {
        console.error('Lỗi 400: Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.');
        return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào hoặc reCAPTCHA token.' });
    }

    const sanitizedUserInput = sanitizeInput(userInput);
    if (!sanitizedUserInput) {
        console.error('Lỗi 400: Dữ liệu đầu vào không hợp lệ hoặc quá dài sau khi làm sạch.');
        return res.status(400).json({ error: 'Dữ liệu đầu vào không hợp lệ hoặc quá dài.' });
    }

    try {
        const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify`;
        const params = new URLSearchParams();
        params.append('secret', RECAPTCHA_SECRET_KEY);
        params.append('response', recaptchaToken);
        if (ip) {
            params.append('remoteip', ip);
        }

        console.log(`Đang gửi yêu cầu xác minh reCAPTCHA đến: ${recaptchaVerificationUrl}`);
        console.log(`Với các tham số: ${params.toString()}`);

        const verificationResponse = await fetch(recaptchaVerificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });

        if (!verificationResponse.ok) {
            // Ghi log trạng thái HTTP và nội dung phản hồi nếu không thành công
            const errorText = await verificationResponse.text();
            console.error(`Lỗi HTTP từ reCAPTCHA API: ${verificationResponse.status} ${verificationResponse.statusText}. Phản hồi: ${errorText}`);
            if (db) {
                await handleFailedAttempt(ip, visitorId);
            }
            return res.status(verificationResponse.status).json({ error: 'Xác thực reCAPTCHA thất bại do lỗi HTTP từ Google.', details: errorText });
        }

        const recaptchaData = await verificationResponse.json();
        console.log('Phản hồi reCAPTCHA nhận được:', recaptchaData);

        if (!recaptchaData.success) {
            if (db) { // Chỉ xử lý nếu Firestore đã được khởi tạo
                await handleFailedAttempt(ip, visitorId);
            } else {
                console.warn('Firestore chưa được khởi tạo, không thể ghi nhận thất bại reCAPTCHA.');
            }
            console.error(`Xác thực reCAPTCHA không thành công. Lý do: ${JSON.stringify(recaptchaData['error-codes'])}`);
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.', details: recaptchaData['error-codes'] });
        }

        // Nếu reCAPTCHA thành công, reset số lần thử thất bại của IP này
        if (db) { // Chỉ xử lý nếu Firestore đã được khởi tạo
            console.log(`Firestore Reset: Đang cố gắng xóa failedAttempts cho IP: ${ip}`); // Log mới
            try {
                // Attempt to delete directly. Firestore will handle if it doesn't exist.
                await updateAdminData({ [`failedAttempts.${ip}`]: FieldValue.delete() });
                console.log(`Firestore Reset: Đã xóa thành công failedAttempts cho IP: ${ip} (hoặc không tồn tại để xóa).`); // Log mới
            } catch (deleteError) {
                console.error(`Firestore Reset: Lỗi khi xóa failedAttempts cho IP ${ip}:`, deleteError); // Log lỗi mới
            }
        } else {
            console.warn('Firestore chưa được khởi tạo, không thể reset failedAttempts.');
        }

        console.log(`[SUCCESS] reCAPTcha valid cho IP: ${ip}`);

        let text = sanitizedUserInput;
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
        console.error('Lỗi khi gọi reCAPTCHA API hoặc lỗi server:', error);
        // Ghi log toàn bộ đối tượng lỗi để có thêm thông tin chi tiết
        console.error(error); 
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ khi xác thực reCAPTCHA.', details: error.message });
    }
});

// --- API ADMIN DASHBOARD ---

// API đăng nhập Admin
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ username: ADMIN_USERNAME, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token });
    } else {
        res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
    }
});

// API lấy thống kê và danh sách bị ban
app.get('/admin/stats', authenticateAdminToken, async (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }
    try {
        const adminData = await getAdminData();
        res.json({
            success: true,
            stats: {
                total_requests: adminData.total_requests || 0,
                total_failed_recaptcha: adminData.total_failed_recaptcha || 0
            },
            banned_ips: adminData.banned_ips || {},
            banned_fingerprints: adminData.banned_fingerprints || {}
        });
    } catch (error) {
        console.error('Lỗi khi lấy thống kê admin:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra khi lấy dữ liệu admin.' });
    }
});

// API để ban một IP hoặc Fingerprint (MỚI THÊM)
app.post('/admin/ban', authenticateAdminToken, async (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }
    const { type, value, reason = 'Admin manually banned' } = req.body;

    if (!type || !value) {
        return res.status(400).json({ error: 'Thiếu loại hoặc giá trị để ban.' });
    }

    try {
        const adminData = await getAdminData();
        
        // Đối với ban từ admin dashboard, đặt là vĩnh viễn
        const banExpiresAt = PERMANENT_BAN_VALUE; 

        if (type === 'ip') {
            if (adminData.banned_ips[value] && adminData.banned_ips[value] === PERMANENT_BAN_VALUE) {
                return res.status(409).json({ error: `IP ${value} đã bị ban vĩnh viễn.` });
            }
            adminData.banned_ips[value] = banExpiresAt;
            console.log(`[ADMIN BAN] IP ${value} bị ban vĩnh viễn. Lý do: ${reason}`);
        } else if (type === 'fingerprint') {
            if (adminData.banned_fingerprints[value] && adminData.banned_fingerprints[value] === PERMANENT_BAN_VALUE) {
                return res.status(409).json({ error: `Fingerprint ${value} đã bị ban vĩnh viễn.` });
            }
            adminData.banned_fingerprints[value] = banExpiresAt; // Lưu thời gian hết hạn là vĩnh viễn
            console.log(`[ADMIN BAN] Fingerprint ${value} bị ban vĩnh viễn. Lý do: ${reason}`);
        } else {
            return res.status(400).json({ error: 'Loại ban không hợp lệ. Chỉ chấp nhận "ip" hoặc "fingerprint".' });
        }

        await updateAdminData({
            banned_ips: adminData.banned_ips,
            banned_fingerprints: adminData.banned_fingerprints
        });
        res.json({ success: true, message: `${type} ${value} đã được ban vĩnh viễn.` });

    } catch (error) {
        console.error('Lỗi khi ban:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra khi ban.' });
    }
});


// API để unban một IP hoặc Fingerprint
app.post('/admin/unban', authenticateAdminToken, async (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }
    const { type, value } = req.body;

    if (!type || !value) {
        return res.status(400).json({ error: 'Thiếu loại hoặc giá trị để unban.' });
    }

    try {
        const adminData = await getAdminData();
        let updated = false;

        if (type === 'ip') {
            if (adminData.banned_ips && adminData.banned_ips[value]) {
                delete adminData.banned_ips[value];
                updated = true;
                console.log(`[ADMIN UNBAN] IP ${value} đã được unban.`);
            }
        } else if (type === 'fingerprint') {
            if (adminData.banned_fingerprints && adminData.banned_fingerprints[value]) {
                delete adminData.banned_fingerprints[value];
                updated = true;
                console.log(`[ADMIN UNBAN] Fingerprint ${value} đã được unban.`);
            }
        } else {
            return res.status(400).json({ error: 'Loại unban không hợp lệ. Chỉ chấp nhận "ip" hoặc "fingerprint".' });
        }

        if (updated) {
            await updateAdminData({
                banned_ips: adminData.banned_ips,
                banned_fingerprints: adminData.banned_fingerprints
            });
            res.json({ success: true, message: `${type} ${value} đã được unban.` });
        } else {
            res.status(404).json({ error: `${type} ${value} không tìm thấy trong danh sách bị ban.` });
        }

    } catch (error) {
        console.error('Lỗi khi unban:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra khi unban.' });
    }
});


// --- 7. KHỞI ĐỘNG SERVER ---
// Bọc việc khởi động server trong một hàm async để đảm bảo Firebase được khởi tạo trước
async function startServer() {
    console.log('Server Startup: Bắt đầu khởi động server...');
    await initializeFirebaseAdmin(); // Đảm bảo Firebase được khởi tạo hoàn chỉnh
    console.log('Server Startup: Firebase Admin SDK đã khởi tạo xong, chuẩn bị lắng nghe cổng.');

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Server đang chạy tại http://0.0.0.0:${PORT}`);
    });
}

startServer(); // Gọi hàm khởi động server
