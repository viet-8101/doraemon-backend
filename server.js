// server.js (Node.js/Express Backend - ĐÃ FIX LỖI IP UTILS VÀ HOÀN THIỆN LOGIC)

import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import bcrypt from 'bcryptjs';

import admin from 'firebase-admin';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { RateLimiterMemory } from 'rate-limiter-flexible'; // Rate Limiter

dotenv.config();

// --- GLOBAL ERROR HANDLERS ---
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception', err && err.stack ? err.stack : err);
});

// --- APP SETUP ---
const app = express();
const PORT = process.env.PORT || 3000;

// Cấu hình CORS (Chỉ cho phép các domain Frontend đã biết)
app.use(cors({
  origin: [
    'https://viet-8101.github.io',
    'https://viet-8101.github.io/admin-dashboard-doraemon/',
    'http://localhost:5173', // Dev environment for React Admin
    process.env.FRONTEND_URL || 'https://admin-dashboard-doraemon.onrender.com', // Cấu hình linh hoạt
  ],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
// Kích hoạt trust proxy để đọc IP chính xác khi chạy sau load balancer
app.set('trust proxy', 1);

// --- CONFIG VARS & CONSTANTS ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
// ADMIN_HASHES: { username: bcrypt_hashed_password } 
const ADMIN_HASHES = process.env.ADMIN_HASHES ? JSON.parse(process.env.ADMIN_HASHES) : {}; 
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '1d';
const TOTP_SECRET = process.env.TOTP_SECRET; // Bí mật 2FA (TOTP)
const FIREBASE_ADMIN_CREDENTIALS = process.env.FIREBASE_ADMIN_CREDENTIALS;

// SỬA LỖI: Hằng số cấm vĩnh viễn (dùng max safe integer)
const PERMANENT_BAN_VALUE = 9007199254740991; 

if (!JWT_SECRET) {
  console.error("LỖI CẤU HÌNH: JWT_SECRET không được thiết lập trong biến môi trường.");
  process.exit(1);
}

// --- IP/FINGERPRINT UTILS (ĐÃ SỬA) ---

/**
 * Chuẩn hóa địa chỉ IP (xử lý IPv4-mapped IPv6)
 */
function normalizeIp(ip) {
  if (ip && ip.startsWith('::ffff:')) {
    return ip.slice(7); 
  }
  return ip;
}

/**
 * Lấy địa chỉ IP đã chuẩn hóa của client từ request (hỗ trợ trust proxy)
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
      return normalizeIp(forwarded.split(',')[0].trim());
  }
  return normalizeIp(req.ip || req.connection.remoteAddress || 'unknown');
}

// --- FIREBASE INIT, CACHE & LISTENER ---
let firebaseAdminInitialized = false;
let db;
// Cache: pIps (Permanent IPs), tIps (Temporary IPs), pFps, tFps
let BANNED_CACHE = { pIps: {}, tIps: {}, pFps: {}, tFps: {} };
let DICTIONARY_CACHE = {};

const initializeFirebase = () => {
  if (firebaseAdminInitialized) return true;
  try {
    if (!FIREBASE_ADMIN_CREDENTIALS) {
      console.error("LỖI CẤU HÌNH: FIREBASE_ADMIN_CREDENTIALS không được thiết lập.");
      return false;
    }
    const credentials = JSON.parse(FIREBASE_ADMIN_CREDENTIALS);
    if (admin.apps.length === 0) {
      admin.initializeApp({
        credential: admin.credential.cert(credentials),
      });
    }
    db = getFirestore();
    firebaseAdminInitialized = true;
    console.log("Firebase Admin đã được khởi tạo thành công.");
    return true;
  } catch (err) {
    console.error("Lỗi khi khởi tạo Firebase Admin:", err);
    return false;
  }
};

const initializeFirebaseWithRetries = async () => {
  for (let i = 0; i < 5; i++) {
    if (initializeFirebase()) return true;
    await sleep(2 ** i * 1000);
  }
  console.error("Khởi tạo Firebase thất bại sau nhiều lần thử.");
  return false;
};

// Tải lại Từ Điển từ Firestore vào Cache
const loadDictionary = async () => {
  if (!firebaseAdminInitialized) return;
  try {
    const snapshot = await db.collection('dictionary').get();
    const newDict = {};
    snapshot.forEach(doc => { newDict[doc.data().key] = doc.data().value; });
    DICTIONARY_CACHE = newDict;
    console.log(`Tải lại từ điển. Tổng cộng: ${Object.keys(DICTIONARY_CACHE).length} mục.`);
  } catch (err) { console.error("Lỗi khi tải từ điển:", err); }
};

// Tải lại dữ liệu Cấm (Bans) từ Firestore vào Cache và dọn dẹp các mục hết hạn
const loadBans = async () => {
  if (!firebaseAdminInitialized) return;
  try {
    const snapshot = await db.collection('bans').get();
    const newBans = { pIps: {}, tIps: {}, pFps: {}, tFps: {} };
    const now = Date.now();
    const batch = db.batch();
    let expiredCount = 0;

    snapshot.forEach(doc => {
      const data = doc.data();
      const id = doc.id; 
      const type = data.type === 'ip' ? 'Ip' : 'Fp';
      const isPermanent = data.expiry === PERMANENT_BAN_VALUE;

      if (!isPermanent && data.expiry < now) {
        batch.delete(db.collection('bans').doc(id));
        expiredCount++;
      } else {
        const key = `${isPermanent ? 'p' : 't'}${type}s`;
        newBans[key][data.value] = data.expiry;
      }
    });

    if (expiredCount > 0) {
      await batch.commit();
      console.log(`Đã xóa ${expiredCount} mục cấm hết hạn.`);
    }

    BANNED_CACHE = newBans;
  } catch (err) { console.error("Lỗi khi tải dữ liệu cấm:", err); }
};


// Cấu hình Rate Limiter (5 yêu cầu/60s, block 5 phút)
const rateLimiter = new RateLimiterMemory({
  points: 5, 
  duration: 60, 
  blockDuration: 300, 
});

// --- HELPER FUNCTIONS ---
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const generateAdminToken = (secret) => {
    return jwt.sign({ isAdmin: true, username: 'admin' }, secret, { expiresIn: JWT_EXPIRES_IN });
};

// --- DICTIONARY DECODER LOGIC ---
const decodeMessage = (text) => {
    if (!text) return "";
    const regex = /\[(\d{1,5})\]/g; 
    let decodedText = text;

    decodedText = decodedText.replace(regex, (match, key) => {
        const value = DICTIONARY_CACHE[key];
        return value !== undefined ? value : match; 
    });

    return decodedText.trim();
};

// --- MIDDLEWARE ---

const isBanned = (ip, fp) => {
    const now = Date.now();
    // Kiểm tra cấm IP
    if (BANNED_CACHE.pIps[ip] || (BANNED_CACHE.tIps[ip] && BANNED_CACHE.tIps[ip] > now)) return true;
    // Kiểm tra cấm Fingerprint
    if (BANNED_CACHE.pFps[fp] || (BANNED_CACHE.tFps[fp] && BANNED_CACHE.tFps[fp] > now)) return true;
    return false;
};

/**
 * Middleware bảo mật chung (Rate Limit, Ban Check, ReCaptcha check)
 */
const securityMiddleware = async (req, res, next) => {
    const clientIp = getClientIp(req);
    const clientFingerprint = req.headers['x-client-fingerprint'] || req.body.fingerprintId || 'no_fp_provided';
    const key = `${clientIp}_${clientFingerprint}`;

    // 1. Kiểm tra Cấm IP/Fingerprint
    if (isBanned(clientIp, clientFingerprint)) {
        return res.status(403).json({ error: "Địa chỉ IP hoặc Fingerprint của bạn đã bị cấm truy cập hệ thống." });
    }

    // 2. Kiểm tra Rate Limit
    try {
        await rateLimiter.consume(key);
    } catch (rateLimiterRes) {
        const seconds = Math.ceil(rateLimiterRes.msBeforeNext / 1000);
        res.setHeader('Retry-After', seconds);
        return res.status(429).json({ error: `Bạn gửi yêu cầu quá nhanh. Vui lòng thử lại sau ${seconds} giây.` });
    }

    // 3. Kiểm tra reCAPTCHA (Chỉ bắt buộc cho route giải mã)
    if (req.path === '/giai-ma') {
        const captchaToken = req.body.recaptchaToken;
        if (!captchaToken) return res.status(400).json({ error: "Thiếu reCAPTCHA token." });

        try {
            const captchaVerifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${captchaToken}&remoteip=${clientIp}`;
            const captchaResponse = await fetch(captchaVerifyUrl, { method: 'POST' });
            const captchaData = await captchaResponse.json();

            if (!captchaData.success || captchaData.score < 0.5) { 
                return res.status(403).json({ error: "Xác thực reCAPTCHA thất bại. Vui lòng thử lại hoặc đảm bảo bạn không phải là bot." });
            }
        } catch (error) {
            console.error("Lỗi xác thực reCAPTCHA:", error);
            return res.status(500).json({ error: "Lỗi nội bộ khi xác thực reCAPTCHA." });
        }
    }

    next();
};

/**
 * Middleware kiểm tra quyền Admin
 */
const requireAdmin = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(401).json({ error: 'Không có quyền truy cập. Vui lòng đăng nhập.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.isAdmin) {
            req.user = decoded;
            next();
        } else {
            return res.status(403).json({ error: 'Truy cập bị từ chối.' });
        }
    } catch (err) {
        res.clearCookie('authToken');
        return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.' });
    }
};

/**
 * Middleware kiểm tra 2FA (Nếu TOTP_SECRET được cấu hình)
 */
const require2FA = (req, res, next) => {
    if (!TOTP_SECRET) return next(); 

    const token = req.body.totpToken;
    if (!token) {
        return res.status(403).json({ error: 'Yêu cầu 2FA token.' });
    }

    const verified = speakeasy.totp.verify({
        secret: TOTP_SECRET,
        encoding: 'base32',
        token: token,
        window: 1, 
    });

    if (verified) {
        next();
    } else {
        return res.status(403).json({ error: '2FA token không hợp lệ.' });
    }
};

// --- PUBLIC ROUTES ---

/**
 * Route kiểm tra trạng thái máy chủ
 */
app.get('/check', (req, res) => {
  res.json({ 
    status: 'ok', 
    firebase: firebaseAdminInitialized ? 'ok' : 'pending',
    dictionarySize: Object.keys(DICTIONARY_CACHE).length,
    timestamp: Date.now()
  });
});

/**
 * Route Giải Mã Mật Thư (áp dụng bảo mật đầy đủ)
 */
app.post('/giai-ma', securityMiddleware, (req, res) => {
    const { encodedText } = req.body;
    
    if (!encodedText || typeof encodedText !== 'string' || encodedText.length > 5000) {
        return res.status(400).json({ error: "Nội dung mật thư không hợp lệ (tối đa 5000 ký tự)." });
    }
    
    try {
        const decodedText = decodeMessage(encodedText);
        res.json({ 
            success: true, 
            original: encodedText, 
            decoded: decodedText 
        });
    } catch (error) {
        res.status(500).json({ error: "Lỗi nội bộ khi xử lý giải mã." });
    }
});


// --- ADMIN ROUTES ---

/**
 * Admin Login (có thể yêu cầu 2FA)
 */
app.post('/admin/login', require2FA, async (req, res) => {
    const { password } = req.body;
    const adminHash = Object.values(ADMIN_HASHES)[0]; // Lấy hash admin đầu tiên

    if (!adminHash || !password) {
        return res.status(400).json({ error: "Thiếu thông tin đăng nhập." });
    }

    try {
        const isMatch = await bcrypt.compare(password, adminHash);
        
        if (isMatch) {
            const token = generateAdminToken(JWT_SECRET);
            res.cookie('authToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', 
                sameSite: 'Lax',
                maxAge: 24 * 60 * 60 * 1000 // 1 ngày
            });
            return res.json({ success: true, message: 'Đăng nhập thành công!' });
        } else {
            return res.status(401).json({ error: 'Mật khẩu không đúng.' });
        }
    } catch (err) {
        return res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});

/**
 * Admin Logout
 */
app.post('/admin/logout', (req, res) => {
    res.clearCookie('authToken');
    res.json({ success: true, message: 'Đã đăng xuất.' });
});

/**
 * Kiểm tra trạng thái admin
 */
app.get('/admin/me', requireAdmin, (req, res) => {
    res.json({ success: true, user: req.user });
});

// --- ADMIN: BAN MANAGEMENT ---

/**
 * Lấy danh sách IP/FP bị cấm
 */
app.get('/admin/banned', requireAdmin, (req, res) => {
    res.json(BANNED_CACHE);
});

/**
 * Thực hiện Cấm (Ban)
 */
app.post('/admin/ban', requireAdmin, async (req, res) => {
    const { type, value, duration } = req.body;
    if (!['ip', 'fingerprint'].includes(type) || !value || typeof value !== 'string' || !firebaseAdminInitialized) {
        return res.status(400).json({ error: 'Dữ liệu không hợp lệ hoặc database chưa sẵn sàng.' });
    }

    const docId = `${type}_${value.trim()}`;
    let expiry = PERMANENT_BAN_VALUE; 

    if (duration !== 'permanent') {
        const msDuration = parseInt(duration, 10);
        if (isNaN(msDuration) || msDuration <= 0) {
            return res.status(400).json({ error: 'Thời lượng cấm không hợp lệ.' });
        }
        expiry = Date.now() + msDuration;
    }

    try {
        await db.collection('bans').doc(docId).set({
            type: type,
            value: value.trim(),
            expiry: expiry,
            admin: req.user.username || 'admin',
            timestamp: FieldValue.serverTimestamp()
        }, { merge: true });

        await loadBans();
        res.json({ success: true, message: `Đã cấm ${type} ${value.trim()} thành công.` });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server khi thực hiện cấm.' });
    }
});

/**
 * Thực hiện Gỡ Cấm (Unban)
 */
app.post('/admin/unban', requireAdmin, async (req, res) => {
    const { type, value } = req.body;

    if (!['ip', 'fingerprint'].includes(type) || !value || typeof value !== 'string' || !firebaseAdminInitialized) {
        return res.status(400).json({ error: 'Dữ liệu không hợp lệ hoặc database chưa sẵn sàng.' });
    }

    const docId = `${type}_${value.trim()}`;

    try {
        await db.collection('bans').doc(docId).delete();

        await loadBans();
        res.json({ success: true, message: `Đã gỡ cấm ${type} ${value.trim()} thành công.` });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server khi thực hiện gỡ cấm.' });
    }
});


// --- ADMIN: DICTIONARY MANAGEMENT (CRUD) ---

/**
 * Lấy toàn bộ từ điển
 */
app.get('/admin/dictionary', requireAdmin, (req, res) => {
    res.json({ dictionary: DICTIONARY_CACHE });
});

/**
 * Thêm một mục từ điển mới
 */
app.post('/admin/dictionary', requireAdmin, async (req, res) => {
    const { key, value } = req.body;

    if (!key || typeof key !== 'string' || !value || typeof value !== 'string') {
        return res.status(400).json({ error: 'Key hoặc Value không hợp lệ.' });
    }
    if (DICTIONARY_CACHE[key]) {
        return res.status(409).json({ error: `Key "${key}" đã tồn tại.` });
    }
    if (!firebaseAdminInitialized) {
         return res.status(503).json({ error: 'Database chưa sẵn sàng.' });
    }

    try {
        await db.collection('dictionary').doc(key).set({ key, value, timestamp: FieldValue.serverTimestamp() });
        await loadDictionary(); 
        res.json({ success: true, message: 'Thêm mục từ điển thành công.' });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server khi thêm mục từ điển.' });
    }
});

/**
 * Cập nhật Value của một mục từ điển
 */
app.put('/admin/dictionary/:key', requireAdmin, async (req, res) => {
    const key = req.params.key;
    const { value } = req.body;

    if (!value || typeof value !== 'string') {
        return res.status(400).json({ error: 'Value không hợp lệ.' });
    }
    if (!DICTIONARY_CACHE[key]) {
        return res.status(404).json({ error: `Key "${key}" không tồn tại.` });
    }
    if (!firebaseAdminInitialized) {
         return res.status(503).json({ error: 'Database chưa sẵn sàng.' });
    }

    try {
        await db.collection('dictionary').doc(key).update({ value, timestamp: FieldValue.serverTimestamp() });
        await loadDictionary(); 
        res.json({ success: true, message: 'Cập nhật mục từ điển thành công.' });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server khi cập nhật mục từ điển.' });
    }
});

/**
 * Xóa một mục từ điển
 */
app.delete('/admin/dictionary/:key', requireAdmin, async (req, res) => {
    const key = req.params.key;

    if (!DICTIONARY_CACHE[key]) {
        return res.status(404).json({ error: `Key "${key}" không tồn tại.` });
    }
    if (!firebaseAdminInitialized) {
         return res.status(503).json({ error: 'Database chưa sẵn sàng.' });
    }

    try {
        await db.collection('dictionary').doc(key).delete();
        await loadDictionary(); 
        res.json({ success: true, message: 'Xóa mục từ điển thành công.' });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server khi xóa mục từ điển.' });
    }
});

// --- BOOTSTRAP ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
  if (!firebaseAdminInitialized) console.warn('CẢNH BÁO: Firestore chưa được khởi tạo (đang chờ).');
});

// Khởi tạo firebase và tải cache ban đầu
(async () => {
  const ok = await initializeFirebaseWithRetries();
  if (ok && firebaseAdminInitialized) {
    await loadDictionary();
    await loadBans();
    
    // Đặt lịch tải lại cache định kỳ
    setInterval(loadDictionary, 5 * 60 * 1000); // 5 phút
    setInterval(loadBans, 1 * 60 * 1000); // 1 phút
  }
})();
