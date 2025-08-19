// server.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

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
const JWT_SECRET = process.env.JWT_SECRET;

// Bắt buộc phải có JWT_SECRET để đảm bảo an toàn
if (!JWT_SECRET) {
    console.error('Lỗi: JWT_SECRET chưa được đặt trong biến môi trường! Server sẽ không khởi động.');
    process.exit(1);
}

if (!RECAPTCHA_SECRET_KEY || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('Lỗi: RECAPTCHA_SECRET_KEY, ADMIN_USERNAME hoặc ADMIN_PASSWORD chưa được đặt trong biến môi trường!');
}

// --- KHỞI TẠO FIREBASE ADMIN SDK ---
let db;
let firebaseAdminInitialized = false;

async function initializeFirebaseAdmin() {
    console.log('Firebase Init: Bắt đầu khởi tạo Firebase Admin SDK...');
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
        db = getFirestore();
        firebaseAdminInitialized = true;
        console.log('Firebase Init: Firebase Admin SDK đã được khởi tạo và kết nối với Firestore.');
    } catch (error) {
        console.error('Firebase Init: Lỗi khi khởi tạo Firebase Admin SDK:', error);
        db = null;
    }
}

const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id';

// --- 4. TỪ ĐIỂN DORAEMON ---
const tuDienDoraemon = {
    "cái loa biết đi": "Jaian", "thánh chảnh": "Suneo", "cục nợ quốc dân": "Nobita", "trùm chém gió": "Suneo", "boss ăn vặt": "Doraemon", "siêu nhân gục ngã": "Nobita", "máy phát kẹo": "Doraemon", "ổ bom di động": "Jaian", "thánh phá đồ": "Nobita", "chuyên gia gây họa": "Nobita", "nhà tài trợ nước mắt": "mẹ Nobita", "lò luyện điểm 0": "lớp học của Nobita", "trùm thất tình": "Nobita", "đứa trẻ cuối cùng của mushika": "Micca", "máy ATM biết đi": "Doraemon", "trí tuệ nhân tạo có tâm": "Doraemon", "con tinh tinh": "Jaian", "con khỉ đột": "Jaian", "khỉ đột": "Jaian", "tinh tinh": "Jaian", "con cáo": "Suneo", "cáo": "Suneo", "bạch tuộc": "Noise", "quần dài": "2 con cá trắm đen đc làm ở Pháp rất là mắc tiền (của Suneo)", "mụ phù thủy": "mẹ của Nobita", "tên ngốc hậu hậu": "Nobita", "tên robinson phiền phức": "Nobita", "thiên tài ngủ": "Nobita", "diễn viên suất sắc": "Nobita", "bậc thầy năn nỉ": "Nobita", "thiên tài thắt dây": "Nobita", "tay vua súng": "Nobita", "xe buýt": "Nobita", "xe bus": "Nobita", "mèo máy": "Doraemon", "mỏ nhọn": "Suneo", "lồi rốn": "Jaian", "yên ắng": "nhà Shizuka", "hình tròn": "bánh rán dorayaki", "kẻ tham lam": "Jaian", "hai người nổi tiếng ham ăn": "Jaian và Suneo", "điểm đen": "điểm 0", "bàn tay vàng trong làng ngáo ngơ": "Nobita", "cục tạ quốc dân": "Nobita", "đại ca sân trường": "Jaian", "người mẫu sừng sỏ": "Suneo", "cô gái tắm mỗi tập": "Shizuka", "vua bánh rán": "Doraemon", "thánh cầu cứu": "Nobita", "người đến từ tương lai": "Doraemon", "cây ATM sống": "Doraemon", "lồng tiếng động đất": "Jaian", "diễn viên chính của bi kịch": "Nobita", "fan cuồng công nghệ": "Suneo", "kẻ lười biếng nhỏ bé": "Nobita", "chồn xanh nhỏ đáng yêu": "Doraemon", "bình yên trước cơn bão": "nhà Shizuka", "cậu bé sáo lạc điệu": "Nobita", "loa phóng thanh biết đi": "Jaian", "trùm phá nốt": "Nobita", "người cứu âm nhạc địa cầu": "Doraemon", "quái vật hút âm": "bào tử noise", "người bạn đến từ hành tinh âm nhạc": "Micca", "thánh phá bản nhạc": "Nobita", "cây sáo truyền thuyết": "cây sáo dọc của mushika", "bản nhạc giải cứu trái đất": "bản giao hưởng địa cầu", "phi công nghiệp dư": "Nobita", "vùng đất trong mơ": "Utopia", "cư dân đám mây": "người sống ở Utopia", "nhà trên trời view đẹp": "Utopia", "người bạn Utopia": "Sonya", "trùm điều khiển thời tiết": "quản lý Utopia", "mặt trăng bay lạc": "Utopia", "chuyến phiêu lưu trên trời": "hành trình của nhóm Nobita", "lâu đài mây thần bí": "trung tâm điều hành Utopia", "trùm chấn động bầu trời": "Suneo lái máy bay", "cậu bé bay không bằng lái": "Nobita", "thánh nhảy moonwalk ngoài vũ trụ": "Nobita", "chuyên gia té không trọng lực": "Nobita", "trạm vũ trụ di động": "tàu của Doraemon", "người bạn tai dài trên mặt trăng": "Luca", "cư dân mặt trăng bí ẩn": "tộc người Espal", "đội thám hiểm mặt trăng": "nhóm Nobita", "mặt trăng giả tưởng": "thế giới do bảo bối tạo ra", "cuộc chiến không trọng lực": "trận đấu trên mặt trăng", "lũ bạn ngoài hành tinh đáng yêu": "Luca và đồng bọn", "bầu trời đêm đầy ảo mộng": "khung cảnh mặt trăng", "cậu bé lười biếng nhất thành phố": "Nobita", "cậu bé xấu tính nhất thành phố": "Jaian", "nhạc sĩ vũ trụ": "Trupet", "nhà soạn nhạc vĩ đại": "Trupet", "người sáng tác giao hưởng địa cầu": "Trupet", "chủ nhân bản giao hưởng địa cầu": "Trupet", "nhà sáng tạo âm nhạc vũ trụ": "Trupet", "nhạc sĩ bảo vệ hòa bình âm nhạc": "Trupet", "rùa siêu tốc vũ trụ": "Moto", "rùa vũ trụ có mai thép": "Moto", "rùa siêu bền": "Moto", "tốc độ vũ trụ từ mai rùa": "Moto", "vũ trụ đua rùa": "Moto", "con rùa nhanh nhất trong không gian": "Moto", "viên đạn của đại bác không khí": "Moto"
};

// Sắp xếp từ điển một lần duy nhất khi server khởi động để tối ưu hiệu suất
const sortedDoraemonEntries = Object.entries(tuDienDoraemon).sort((a, b) => b[0].length - a[0].length);

// --- 5. HỖ TRỢ BẢO MẬT VÀ FIREBASE ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000;
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER;
const FAILED_ATTEMPTS_THRESHOLD = 5;
const FAILED_ATTEMPTS_RESET_MS = 30 * 60 * 1000;

const getAdminDataDocRef = () => {
    if (!db) {
        console.error('Firestore chưa được khởi tạo hoặc không khả dụng. Không thể truy cập admin_data.');
        return null;
    }
    return db.collection('artifacts').doc(appId).collection('public').doc('data').collection('admin_data').doc('main_data');
};

async function getAdminData() {
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
                failedAttempts: {},
                tfa_secret: null, // Thêm trường tfa_secret
            };
            await docRef.set(initialData);
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
        await docRef.update(dataToUpdate);
    } catch (error) {
        console.error('Lỗi khi cập nhật admin data vào Firestore:', error);
    }
}

function getClientIp(req) {
    const forwardedIpsStr = req.headers['x-forwarded-for'];
    if (forwardedIpsStr) {
        const forwardedIps = forwardedIpsStr.split(',');
        return forwardedIps[0].trim();
    }
    return req.ip;
}

function normalizeIp(ip) {
    if (ip && ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip;
}

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

// Sử dụng Firestore Transaction để đảm bảo tính nguyên tử
async function handleFailedAttempt(ip, visitorId) {
    if (!db) {
        console.warn('Firestore chưa được khởi tạo, không thể ghi nhận thất bại reCAPTCHA.');
        return;
    }

    const docRef = getAdminDataDocRef();
    if (!docRef) {
        console.error('Không tìm thấy tài liệu Firestore.');
        return;
    }

    await db.runTransaction(async (transaction) => {
        const docSnap = await transaction.get(docRef);
        const adminData = docSnap.data() || {};
        const currentBannedIps = adminData.banned_ips || {};
        const currentBannedFingerprints = adminData.banned_fingerprints || {};

        const now = Date.now();
        let failedAttempts = adminData.failedAttempts || {};
        let data = failedAttempts[ip] || { count: 0, lastFailTime: 0 };

        if (now - data.lastFailTime > FAILED_ATTEMPTS_RESET_MS) {
            data = { count: 1, lastFailTime: now };
        } else {
            data.count++;
            data.lastFailTime = now;
        }

        const updates = {
            total_failed_recaptcha: FieldValue.increment(1),
            [`failedAttempts.${ip}`]: data
        };

        console.warn(`[RECAPTCHA FAIL] IP: ${ip} thất bại lần ${data.count}`);

        if (data.count >= FAILED_ATTEMPTS_THRESHOLD) {
            const banExpiresAt = now + BAN_DURATION_MS;
            currentBannedIps[ip] = banExpiresAt;
            if (visitorId) {
                currentBannedFingerprints[visitorId] = banExpiresAt;
            }
            updates.banned_ips = currentBannedIps;
            updates.banned_fingerprints = currentBannedFingerprints;
            updates[`failedAttempts.${ip}`] = FieldValue.delete();
            const banExpiresDate = new Date(banExpiresAt).toLocaleString('vi-VN');
            console.error(`[TEMP-BAN] IP: ${ip} bị banned đến ${banExpiresDate}, visitorId ${visitorId || 'N/A'} banned tạm thời.`);
        }

        transaction.update(docRef, updates);
    });
}

async function securityMiddleware(req, res, next) {
    const clientIpRaw = getClientIp(req);
    const ip = normalizeIp(clientIpRaw);
    const visitorId = req.body.visitorId;

    // Log IP và visitorId để dễ dàng theo dõi
    console.log(`[REQUEST IN] IP: ${ip}, VisitorId: ${visitorId}`);

    if (!db) {
        console.warn('Firestore chưa được khởi tạo. Bỏ qua kiểm tra bảo mật.');
        return next();
    }

    try {
        const adminData = await getAdminData();
        const currentBannedIps = adminData.banned_ips || {};
        const currentBannedFingerprints = adminData.banned_fingerprints || {};

        // Kiểm tra và gỡ ban tự động cho visitorId
        if (visitorId && currentBannedFingerprints[visitorId]) {
            const banExpiresAt = currentBannedFingerprints[visitorId];
            if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
                const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
                return res.status(403).json({ error: `Truy cập của bạn đã bị chặn ${banMessage}.` });
            } else if (Date.now() >= banExpiresAt) {
                delete currentBannedFingerprints[visitorId];
                await updateAdminData({ banned_fingerprints: currentBannedFingerprints });
                console.log(`[UNBAN-AUTO] Fingerprint ${visitorId} đã được gỡ chặn tự động.`);
            }
        }

        // Kiểm tra và gỡ ban tự động cho IP
        const banExpiresAt = currentBannedIps[ip];
        if (banExpiresAt) {
            if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
                const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
                return res.status(403).json({ error: `IP của bạn đang bị chặn ${banMessage}.` });
            } else if (Date.now() >= banExpiresAt) {
                delete currentBannedIps[ip];
                await updateAdminData({ banned_ips: currentBannedIps });
                console.log(`[UNBAN-AUTO] IP ${ip} đã được gỡ chặn tự động.`);
            }
        }
    } catch (error) {
        console.error('Lỗi trong security middleware:', error);
        return res.status(500).json({ error: 'Lỗi server khi kiểm tra bảo mật.' });
    }

    next();
}


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

app.get('/api/users', authenticateAdminToken, async (req, res) => {
    if (!firebaseAdminInitialized || !admin.auth()) {
        console.error('Firebase Admin SDK hoặc Auth chưa được khởi tạo. Không thể lấy người dùng.');
        return res.status(503).json({ error: 'Dịch vụ xác thực người dùng chưa sẵn sàng.' });
    }
    try {
        const listUsersResult = await admin.auth().listUsers(1000);
        const users = listUsersResult.users.map(userRecord => ({
            uid: userRecord.uid,
            email: userRecord.email,
            displayName: userRecord.displayName || 'Người dùng mới',
            photoURL: userRecord.photoURL,
            emailVerified: userRecord.emailVerified,
            disabled: userRecord.disabled,
            createdAt: userRecord.metadata ? userRecord.metadata.creationTime : null,
            lastSignInTime: userRecord.metadata ? userRecord.metadata.lastSignInTime : null,
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

    if (db) {
        await updateAdminData({ total_requests: FieldValue.increment(1) });
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

        const verificationResponse = await fetch(recaptchaVerificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });

        if (!verificationResponse.ok) {
            const errorText = await verificationResponse.text();
            console.error(`Lỗi HTTP từ reCAPTCHA API: ${verificationResponse.status} ${verificationResponse.statusText}. Phản hồi: ${errorText}`);
            await handleFailedAttempt(ip, visitorId);
            return res.status(verificationResponse.status).json({ error: 'Xác thực reCAPTCHA thất bại do lỗi HTTP từ Google.', details: errorText });
        }

        const recaptchaData = await verificationResponse.json();
        if (!recaptchaData.success) {
            await handleFailedAttempt(ip, visitorId);
            console.error(`Xác thực reCAPTCHA không thành công. Lý do: ${JSON.stringify(recaptchaData['error-codes'])}`);
            return res.status(401).json({ error: 'Xác thực không thành công. Vui lòng thử lại.', details: recaptchaData['error-codes'] });
        }
        
        // Cập nhật Firestore bằng transaction để reset số lần thất bại
        if (db) {
            const docRef = getAdminDataDocRef();
            if (docRef) {
                await db.runTransaction(async (transaction) => {
                    const docSnap = await transaction.get(docRef);
                    const adminData = docSnap.data() || {};
                    const failedAttempts = adminData.failedAttempts || {};
                    if (failedAttempts[ip]) {
                        transaction.update(docRef, { [`failedAttempts.${ip}`]: FieldValue.delete() });
                        console.log(`[SUCCESS] reCAPTCHA valid. Đã xóa failedAttempts cho IP: ${ip}`);
                    }
                });
            }
        }

        let text = sanitizedUserInput;
        let replaced = false;
        
        for (const [k, v] of sortedDoraemonEntries) {
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
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ khi xác thực reCAPTCHA.', details: error.message });
    }
});

// --- API ADMIN DASHBOARD ---

// Bước 1: API đăng nhập Admin, trả về token 2FA tạm thời
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        try {
            const adminDataDocRef = getAdminDataDocRef();
            const adminData = await (await adminDataDocRef.get()).data();
            
            let tfaSecret = adminData.tfa_secret;
            let qrCodeUrl = null;
            let message = 'Vui lòng nhập mã xác thực từ Google Authenticator.';

            if (!tfaSecret) {
                // Nếu chưa có secret, tạo secret mới và lưu vào Firestore
                const secret = speakeasy.generateSecret({ length: 20 });
                tfaSecret = secret.base32;
                await updateAdminData({ tfa_secret: tfaSecret });
                console.log(`[ADMIN 2FA] Đã tạo và lưu secret mới vào Firestore.`);
                
                const otpauthUrl = speakeasy.otpauthURL({
                    secret: tfaSecret,
                    label: `DoraemonAdmin (${username})`,
                    issuer: 'Doraemon Backend',
                });
                qrCodeUrl = await new Promise((resolve, reject) => {
                    qrcode.toDataURL(otpauthUrl, (err, data_url) => {
                        if (err) reject(err);
                        resolve(data_url);
                    });
                });
                message = 'Bạn cần thiết lập Google Authenticator. Vui lòng quét mã QR sau và nhập mã xác thực.';
            }

            const tfaToken = jwt.sign(
                { username, secret: tfaSecret },
                JWT_SECRET,
                { expiresIn: '5m' }
            );

            res.json({ 
                success: true, 
                message,
                tfaToken,
                qrCodeUrl
            });
        } catch (error) {
            console.error('Lỗi khi xử lý 2FA:', error);
            res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ khi xử lý 2FA.' });
        }

    } else {
        res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
    }
});

// Bước 2: API xác thực mã 2FA
app.post('/admin/verify-tfa', async (req, res) => {
    const { tfaToken, tfaCode } = req.body;
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }

    if (!tfaToken || !tfaCode) {
        return res.status(400).json({ error: 'Thiếu token hoặc mã xác thực.' });
    }

    jwt.verify(tfaToken, JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Mã xác thực không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại.' });
        }

        const adminDataDocRef = getAdminDataDocRef();
        const adminData = await (await adminDataDocRef.get()).data();
        const tfaSecret = adminData.tfa_secret;

        if (!tfaSecret || tfaSecret !== decoded.secret) {
             return res.status(403).json({ error: 'Mã xác thực không hợp lệ. Vui lòng thử lại.' });
        }

        const verified = speakeasy.totp.verify({
            secret: tfaSecret,
            encoding: 'base32',
            token: tfaCode,
            window: 1
        });

        if (verified) {
            const adminToken = jwt.sign(
                { username: decoded.username, role: 'admin' },
                JWT_SECRET,
                { expiresIn: '8h' }
            );
            res.json({ success: true, adminToken });
        } else {
            res.status(401).json({ error: 'Mã xác thực không chính xác.' });
        }
    });
});


// API lấy thống kê
app.get('/admin/dashboard-data', authenticateAdminToken, async (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }
    try {
        const adminData = await getAdminData();
        const now = Date.now();
        
        const permanentBannedIps = {};
        const temporaryBannedIps = {};
        if (adminData.banned_ips) {
            for (const [ip, expiry] of Object.entries(adminData.banned_ips)) {
                if (expiry === PERMANENT_BAN_VALUE) {
                    permanentBannedIps[ip] = expiry;
                } else if (expiry > now) {
                    temporaryBannedIps[ip] = expiry;
                }
            }
        }

        const permanentBannedFingerprints = {};
        const temporaryBannedFingerprints = {};
        if (adminData.banned_fingerprints) {
             for (const [fpId, banTime] of Object.entries(adminData.banned_fingerprints)) {
                if (banTime === PERMANENT_BAN_VALUE) {
                    permanentBannedFingerprints[fpId] = banTime;
                } else if (banTime > now) {
                    temporaryBannedFingerprints[fpId] = banTime;
                }
            }
        }
        
        res.json({
            success: true,
            stats: {
                total_requests: adminData.total_requests || 0,
                total_failed_recaptcha: adminData.total_failed_recaptcha || 0,
            },
            permanent_banned_ips: permanentBannedIps,
            temporary_banned_ips: temporaryBannedIps,
            permanent_banned_fingerprints: permanentBannedFingerprints,
            temporary_banned_fingerprints: temporaryBannedFingerprints,
        });
    } catch (error) {
        console.error('Lỗi khi lấy thống kê admin:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra khi lấy dữ liệu admin.' });
    }
});


// API để ban một IP hoặc Fingerprint
app.post('/admin/ban', authenticateAdminToken, async (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    }
    const { type, value, duration } = req.body;

    if (!type || !value) {
        return res.status(400).json({ error: 'Thiếu loại hoặc giá trị để ban.' });
    }

    try {
        const adminData = await getAdminData();
        const banExpiresAt = duration === 'permanent' ? PERMANENT_BAN_VALUE : Date.now() + BAN_DURATION_MS;

        if (type === 'ip') {
            adminData.banned_ips = adminData.banned_ips || {};
            adminData.banned_ips[value] = banExpiresAt;
        } else if (type === 'fingerprint') {
            adminData.banned_fingerprints = adminData.banned_fingerprints || {};
            adminData.banned_fingerprints[value] = banExpiresAt;
        } else {
            return res.status(400).json({ error: 'Loại ban không hợp lệ.' });
        }

        await updateAdminData({
            banned_ips: adminData.banned_ips,
            banned_fingerprints: adminData.banned_fingerprints
        });
        res.json({ success: true, message: `Đã ban ${duration === 'permanent' ? 'vĩnh viễn' : 'tạm thời'} ${type}: ${value}` });
    } catch (error) {
        console.error(`Lỗi khi ban ${type}:`, error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
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
        let message = '';
        let unbanned = false;

        if (type === 'ip' && adminData.banned_ips && adminData.banned_ips[value]) {
            delete adminData.banned_ips[value];
            unbanned = true;
            message = `Đã unban thành công IP: ${value}.`;
        } else if (type === 'fingerprint' && adminData.banned_fingerprints && adminData.banned_fingerprints[value]) {
            delete adminData.banned_fingerprints[value];
            unbanned = true;
            message = `Đã unban thành công Fingerprint: ${value}.`;
        } else {
            message = `${type.charAt(0).toUpperCase() + type.slice(1)}: ${value} không có trong danh sách bị cấm.`;
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
    await initializeFirebaseAdmin();
    app.listen(PORT, () => {
        console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
        if (!firebaseAdminInitialized) {
            console.warn('CẢNH BÁO: Firestore không khả dụng. Các chức năng cần database sẽ không hoạt động.');
        }
    });
})();
