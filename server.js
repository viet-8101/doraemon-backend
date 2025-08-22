// sever.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import bcrypt from 'bcryptjs';

// Firebase Admin SDK imports
import admin from 'firebase-admin';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

dotenv.config();

// --- CÁC CƠ CHẾ BẮT LỖI TOÀN CỤC ---
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
        'http://localhost:5173', // Cho phép React dev server
        'http://127.0.0.1:5500', // Cho phép Live Server của VSCode
        'null', // Cho phép khi mở file trực tiếp
        'https://admin-dashboard-doraemon.onrender.com',
    ],
    credentials: true,
}));

app.use(express.json());
app.use(cookieParser());
app.set('trust proxy', 1);

// --- HTTP SECURITY HEADERS ---
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
    next();
});

// --- 3. BIẾN BẢO MẬT VÀ CẤU HÌNH ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_USERNAME_HASH = process.env.ADMIN_USERNAME_HASH;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const JWT_SECRET = process.env.JWT_SECRET;

// Hằng số cho việc giới hạn đăng nhập và ban IP
const ADMIN_FAILED_ATTEMPTS_THRESHOLD = 10;
const ADMIN_BLOCK_DURATION_MS = 60 * 60 * 1000;
const RECAPTCHA_FAILED_ATTEMPTS_THRESHOLD = 5;
const RECAPTCHA_BAN_DURATION_MS = 12 * 60 * 60 * 1000;
const FAILED_ATTEMPTS_RESET_MS = 30 * 60 * 1000;


if (!JWT_SECRET) {
    console.error('Lỗi: JWT_SECRET chưa được đặt trong biến môi trường! Server sẽ không khởi động.');
    process.exit(1);
}
if (!RECAPTCHA_SECRET_KEY || !ADMIN_USERNAME_HASH || !ADMIN_PASSWORD_HASH) {
    console.error('Lỗi: Thiếu các biến môi trường quan trọng (bao gồm cả HASH của admin credentials)!');
}

// --- KHỞI TẠO FIREBASE ---
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
        console.error('Firebase Init: Lỗi: FIREBASE_SERVICE_ACCOUNT_KEY chưa được đặt! Firestore sẽ không hoạt động.');
        db = null;
        return;
    }
    try {
        const serviceAccount = JSON.parse(serviceAccountKeyString);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        db = getFirestore();
        firebaseAdminInitialized = true;
        console.log('Firebase Init: Firebase Admin SDK đã được khởi tạo và kết nối với Firestore.');
    } catch (error) {
        console.error('Firebase Init: Lỗi khi khởi tạo Firebase Admin SDK:', error);
        db = null;
    }
}

const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id';

// --- TỪ ĐIỂN DORAEMON TỪ DATABASE ---
let sortedDoraemonEntries = [];
async function loadDictionaryFromFirestore() {
    if (!db) {
        console.warn('Firestore chưa sẵn sàng, không thể tải từ điển.');
        sortedDoraemonEntries = [];
        return;
    }
    try {
        const dictionarySnapshot = await db.collection('dictionary').get();
        const dictionary = {};
        dictionarySnapshot.forEach(doc => {
            const data = doc.data();
            if(data.key && data.value) dictionary[data.key] = data.value;
        });
        
        sortedDoraemonEntries = Object.entries(dictionary).sort((a, b) => b[0].length - a[0].length);
        console.log(`[Dictionary] Đã tải thành công ${sortedDoraemonEntries.length} từ khóa từ Firestore.`);
    } catch (error) {
        console.error('[Dictionary] Lỗi khi tải từ điển từ Firestore:', error);
    }
}

// --- HỖ TRỢ BẢO MẬT VÀ FIREBASE ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000;
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER;

const getAdminDataDocRef = () => {
    if (!db) return null;
    return db.collection('artifacts').doc(appId).collection('public').doc('data').collection('admin_data').doc('main_data');
};
async function getAdminData() {
    const docRef = getAdminDataDocRef();
    if (!docRef) return {};
    try {
        const docSnap = await docRef.get();
        if (docSnap.exists) return docSnap.data();
        else {
            const initialData = {
                banned_ips: {}, banned_fingerprints: {}, total_requests: 0,
                total_failed_recaptcha: 0, recaptcha_failed_attempts: {},
                admin_login_attempts: {}, tfa_secret: null,
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
    if (docRef) await docRef.update(dataToUpdate).catch(e => console.error('Lỗi khi cập nhật admin data:', e));
}
function getClientIp(req) { return (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(); }
function normalizeIp(ip) { return ip && ip.startsWith('::ffff:') ? ip.substring(7) : ip; }
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().toLowerCase().substring(0, 200).replace(/[^a-z0-9àáạảãăắằặẳẵâấầậẩẫèéẹẻẽêếềệểễìíịỉĩòóọỏõôốồộổỗơớờợởỡùúụủũưứừựửữđ\s.,!?-]/g, '');
}

async function handleFailedAttempt(ip, visitorId, type) {
    if (!db) return;
    try {
        const adminData = await getAdminData();
        const now = Date.now();
        const isRecaptcha = type === 'recaptcha';
        const attemptsKey = isRecaptcha ? 'recaptcha_failed_attempts' : 'admin_login_attempts';
        const threshold = isRecaptcha ? RECAPTCHA_FAILED_ATTEMPTS_THRESHOLD : ADMIN_FAILED_ATTEMPTS_THRESHOLD;
        const banDuration = isRecaptcha ? RECAPTCHA_BAN_DURATION_MS : ADMIN_BLOCK_DURATION_MS;
        
        adminData[attemptsKey] = adminData[attemptsKey] || {};
        const userAttempts = adminData[attemptsKey][ip] || { count: 0, expiresAt: 0 };
        if (now > userAttempts.expiresAt) userAttempts.count = 0;
        
        userAttempts.count++;
        userAttempts.expiresAt = now + FAILED_ATTEMPTS_RESET_MS;

        if (userAttempts.count >= threshold) {
            console.log(`[SECURITY-BAN] IP ${ip} đã bị ban do thất bại loại '${type}' ${userAttempts.count} lần.`);
            adminData.banned_ips = adminData.banned_ips || {};
            adminData.banned_ips[ip] = now + banDuration;
            if (isRecaptcha && visitorId) {
                adminData.banned_fingerprints = adminData.banned_fingerprints || {};
                adminData.banned_fingerprints[visitorId] = now + banDuration;
            }
            delete adminData[attemptsKey][ip];
        } else {
             adminData[attemptsKey][ip] = userAttempts;
             console.log(`[SECURITY-WARN] Ghi nhận thất bại loại '${type}' cho IP ${ip}. Lần thứ: ${userAttempts.count}/${threshold}.`);
        }
        await updateAdminData({
            [attemptsKey]: adminData[attemptsKey],
            banned_ips: adminData.banned_ips,
            banned_fingerprints: adminData.banned_fingerprints,
        });
    } catch (error) {
        console.error(`Lỗi trong handleFailedAttempt cho loại '${type}':`, error);
    }
}

async function securityMiddleware(req, res, next) { 
    const ip = normalizeIp(getClientIp(req));
    const visitorId = req.body.visitorId;
    if (!db) { console.warn('Firestore chưa được khởi tạo. Bỏ qua kiểm tra bảo mật.'); return next(); }

    try {
        const adminData = await getAdminData();
        const currentBannedIps = adminData.banned_ips || {};
        const currentBannedFingerprints = adminData.banned_fingerprints || {};

        const checkBan = (banList, key, type) => {
            const banExpiresAt = banList[key];
            if (banExpiresAt) {
                if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
                    const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
                    res.status(403).json({ error: `Truy cập của bạn (${type}) đã bị chặn ${banMessage}.` });
                    return true;
                } else if (Date.now() >= banExpiresAt) {
                    delete banList[key];
                    console.log(`[UNBAN-AUTO] ${type} ${key} đã được gỡ chặn tự động.`);
                    return 'unbanned';
                }
            }
            return false;
        };

        let updated = false;
        const ipBanned = checkBan(currentBannedIps, ip, 'IP');
        if (ipBanned === true) return;
        if (ipBanned === 'unbanned') updated = true;
        
        if(visitorId) {
            const fpBanned = checkBan(currentBannedFingerprints, visitorId, 'Fingerprint');
            if (fpBanned === true) return;
            if (fpBanned === 'unbanned') updated = true;
        }

        if (updated) await updateAdminData({ banned_ips: currentBannedIps, banned_fingerprints: currentBannedFingerprints });
    } catch (error) {
        console.error('Lỗi trong security middleware:', error);
        return res.status(500).json({ error: 'Lỗi server khi kiểm tra bảo mật.' });
    }
    next();
}

function authenticateAdminToken(req, res, next) {
    const token = req.cookies.adminToken;
    if (!token) return res.status(401).json({ error: 'Truy cập bị từ chối. Vui lòng đăng nhập.' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token không hợp lệ hoặc đã hết hạn.' });
        req.user = user;
        next();
    });
}

// --- API ENDPOINTS ---
app.get('/', (req, res) => res.status(200).send('Backend Doraemon đang chạy.'));

app.post('/giai-ma', securityMiddleware, async (req, res) => {
    if (sortedDoraemonEntries.length === 0) return res.status(503).json({ error: 'Từ điển chưa sẵn sàng, vui lòng thử lại sau.' });
    const { userInput, recaptchaToken, visitorId } = req.body;
    const ip = normalizeIp(getClientIp(req));
    if (!userInput || !recaptchaToken) return res.status(400).json({ error: 'Thiếu dữ liệu.' });
    
     try {
        const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify`;
        const params = new URLSearchParams({ secret: RECAPTCHA_SECRET_KEY, response: recaptchaToken, remoteip: ip });
        const verificationResponse = await fetch(recaptchaVerificationUrl, { method: 'POST', body: params });
        if (!verificationResponse.ok) throw new Error('Lỗi HTTP từ reCAPTCHA API');
        
        const recaptchaData = await verificationResponse.json();
        if (!recaptchaData.success) {
            await handleFailedAttempt(ip, visitorId, 'recaptcha');
            await updateAdminData({ total_failed_recaptcha: FieldValue.increment(1) });
            return res.status(401).json({ error: 'Xác thực reCAPTCHA thất bại.' });
        }
        
        await updateAdminData({ total_requests: FieldValue.increment(1) });
        
        let text = sanitizeInput(userInput);
        let replaced = false;
        for (const [k, v] of sortedDoraemonEntries) {
            const re = new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
            if (re.test(text)) {
                text = text.replace(re, v);
                replaced = true;
            }
        }
        res.json({ success: true, ketQua: replaced ? text : "Không tìm thấy từ khóa phù hợp." });
    } catch (error) {
        console.error('Lỗi /giai-ma:', error);
        res.status(500).json({ error: 'Lỗi máy chủ.' });
    }
});

// --- API ADMIN ---
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = normalizeIp(getClientIp(req));
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    if (!username || !password) return res.status(400).json({ error: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.' });

    try {
        const adminData = await getAdminData();
        const banExpiresAt = adminData.banned_ips ? adminData.banned_ips[ip] : null;
        if (banExpiresAt && Date.now() < banExpiresAt) {
            const timeLeft = Math.ceil((banExpiresAt - Date.now()) / (60 * 1000));
            return res.status(429).json({ error: `Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau ${timeLeft} phút.` });
        }

        const isUsernameMatch = await bcrypt.compare(username, ADMIN_USERNAME_HASH);
        const isPasswordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

        if (isUsernameMatch && isPasswordMatch) {
            const adminLoginAttempts = adminData.admin_login_attempts || {};
            if (adminLoginAttempts[ip]) {
                delete adminLoginAttempts[ip];
                await updateAdminData({ admin_login_attempts: adminLoginAttempts });
                console.log(`[SECURITY-RESET] Đã reset bộ đếm đăng nhập thất bại cho IP ${ip}.`);
            }
            let tfaSecret = adminData.tfa_secret;
            let qrCodeUrl = null;
            let message = 'Vui lòng nhập mã xác thực từ ứng dụng của bạn.';
            if (!tfaSecret) {
                const secret = speakeasy.generateSecret({ length: 20, name: 'DoraemonAdmin' });
                tfaSecret = secret.base32;
                await updateAdminData({ tfa_secret: tfaSecret });
                qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
                message = 'Quét mã QR bằng ứng dụng xác thực và nhập mã để hoàn tất thiết lập.';
            }
            const tfaToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '5m' });
            res.json({ success: true, message, tfaToken, qrCodeUrl });
        } else {
            await handleFailedAttempt(ip, null, 'admin_login');
            res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
        }
    } catch (error) {
        console.error('Lỗi trong quá trình đăng nhập admin:', error);
        res.status(500).json({ error: 'Lỗi server khi xử lý đăng nhập.' });
    }
});

app.post('/admin/verify-tfa', async (req, res) => {
    const { tfaToken, tfaCode } = req.body;
    if (!db || !tfaToken || !tfaCode) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    jwt.verify(tfaToken, JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Phiên đã hết hạn. Vui lòng đăng nhập lại.' });
        const adminData = await getAdminData();
        if (!adminData.tfa_secret) return res.status(403).json({ error: '2FA chưa được thiết lập.' });
        const verified = speakeasy.totp.verify({ secret: adminData.tfa_secret, encoding: 'base32', token: tfaCode, window: 1 });
        if (verified) {
            const adminToken = jwt.sign({ username: decoded.username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
            res.cookie('adminToken', adminToken, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 8 * 3600000 });
            res.json({ success: true, message: 'Đăng nhập thành công!' });
        } else {
            res.status(401).json({ error: 'Mã xác thực không chính xác.' });
        }
    });
});

app.get('/admin/verify-session', authenticateAdminToken, (req, res) => res.json({ success: true, loggedIn: true }));
app.post('/admin/logout', (req, res) => { res.clearCookie('adminToken', { httpOnly: true, secure: true, sameSite: 'none' }); res.json({ success: true }); });
app.get('/admin/dashboard-data', authenticateAdminToken, async (req, res) => { 
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    try {
        const adminData = await getAdminData();
        const now = Date.now();
        const permanent_banned_ips = {}, temporary_banned_ips = {};
        if (adminData.banned_ips) {
            for (const [ip, expiry] of Object.entries(adminData.banned_ips)) {
                if (expiry === PERMANENT_BAN_VALUE) permanent_banned_ips[ip] = expiry;
                else if (expiry > now) temporary_banned_ips[ip] = expiry;
            }
        }
        const permanent_banned_fingerprints = {}, temporary_banned_fingerprints = {};
        if (adminData.banned_fingerprints) {
             for (const [fpId, banTime] of Object.entries(adminData.banned_fingerprints)) {
                if (banTime === PERMANENT_BAN_VALUE) permanent_banned_fingerprints[fpId] = banTime;
                else if (banTime > now) temporary_banned_fingerprints[fpId] = banTime;
            }
        }
        res.json({
            success: true,
            stats: { total_requests: adminData.total_requests || 0, total_failed_recaptcha: adminData.total_failed_recaptcha || 0 },
            permanent_banned_ips, temporary_banned_ips,
            permanent_banned_fingerprints, temporary_banned_fingerprints,
        });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi lấy dữ liệu admin.' }); }
});
app.post('/admin/ban', authenticateAdminToken, async (req, res) => { 
    const { type, value, duration } = req.body;
    if (!db || !type || !value) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    try {
        const adminData = await getAdminData();
        const banExpiresAt = duration === 'permanent' ? PERMANENT_BAN_VALUE : Date.now() + BAN_DURATION_MS;
        if (type === 'ip') (adminData.banned_ips = adminData.banned_ips || {})[value] = banExpiresAt;
        else if (type === 'fingerprint') (adminData.banned_fingerprints = adminData.banned_fingerprints || {})[value] = banExpiresAt;
        else return res.status(400).json({ error: 'Loại ban không hợp lệ.' });
        await updateAdminData({ banned_ips: adminData.banned_ips, banned_fingerprints: adminData.banned_fingerprints });
        res.json({ success: true, message: `Đã cấm ${type}: ${value}` });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi cấm.' }); }
});
app.post('/admin/unban', authenticateAdminToken, async (req, res) => { 
    const { type, value } = req.body;
    if (!db || !type || !value) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    try {
        const adminData = await getAdminData();
        let unbanned = false;
        if (type === 'ip' && adminData.banned_ips?.[value]) { delete adminData.banned_ips[value]; unbanned = true; } 
        else if (type === 'fingerprint' && adminData.banned_fingerprints?.[value]) { delete adminData.banned_fingerprints[value]; unbanned = true; }
        if (unbanned) {
            await updateAdminData({ banned_ips: adminData.banned_ips, banned_fingerprints: adminData.banned_fingerprints });
            res.json({ success: true, message: `Đã gỡ cấm ${type}: ${value}` });
        } else res.status(404).json({ error: 'Không tìm thấy mục để gỡ cấm.' });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi gỡ cấm.' }); }
});

// --- API QUẢN LÝ TỪ ĐIỂN ---
app.get('/admin/dictionary', authenticateAdminToken, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    try {
        const snapshot = await db.collection('dictionary').get();
        const dictionary = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(dictionary);
    } catch (error) { res.status(500).json({ error: 'Lỗi khi lấy từ điển.' }); }
});
app.post('/admin/dictionary', authenticateAdminToken, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    try {
        const { key, value } = req.body;
        if (!key || !value) return res.status(400).json({ error: 'Thiếu key hoặc value.' });
        const docRef = await db.collection('dictionary').add({ key, value });
        await loadDictionaryFromFirestore();
        res.status(201).json({ id: docRef.id, key, value });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi thêm từ mới.' }); }
});
app.put('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    try {
        const { id } = req.params;
        const { key, value } = req.body;
        if (!key || !value) return res.status(400).json({ error: 'Thiếu key hoặc value.' });
        await db.collection('dictionary').doc(id).update({ key, value });
        await loadDictionaryFromFirestore();
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi cập nhật từ.' }); }
});
app.delete('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
    if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
    try {
        await db.collection('dictionary').doc(req.params.id).delete();
        await loadDictionaryFromFirestore();
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Lỗi khi xóa từ.' }); }
});

// Khởi động server
(async () => {
    await initializeFirebaseAdmin();
    await loadDictionaryFromFirestore();
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Server Backend Doraemon đang chạy tại cổng ${PORT}`);
        if (!firebaseAdminInitialized) console.warn('CẢNH BÁO: Firestore không khả dụng.');
    });
})();
