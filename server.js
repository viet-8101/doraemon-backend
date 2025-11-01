// server.js
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

app.use(cors({
  origin: [
    'https://viet-8101.github.io',
    'https://viet-8101.github.io/admin-dashboard-doraemon/',
    'http://localhost:5173',
    'https://admin-dashboard-doraemon.onrender.com',
  ],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.set('trust proxy', 1);

// security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
  next();
});

// --- CONFIG VARS ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_USERNAME_HASH = process.env.ADMIN_USERNAME_HASH;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const JWT_SECRET = process.env.JWT_SECRET;
const DICTIONARY_MAX_LENGTH = 500; 
const RECAPTCHA_SCORE_THRESHOLD = 0.75; 
const RECAPTCHA_EXPECTED_ACTION = 'giai_ma'; 
const RECAPTCHA_FAIL_THRESHOLD = 10; // Ngưỡng thất bại reCAPTCHA liên tiếp

if (!JWT_SECRET) {
  console.error('Lỗi: JWT_SECRET chưa được đặt trong biến môi trường! Server sẽ không khởi động.');
  process.exit(1);
}
if (!RECAPTCHA_SECRET_KEY || !ADMIN_USERNAME_HASH || !ADMIN_PASSWORD_HASH) {
  console.warn('Cảnh báo: Thiếu một số biến môi trường (RECAPTCHA/ADMIN hashes) — một vài chức năng admin/captcha có thể bị giới hạn.');
}

const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id';

// --- FIREBASE INIT (NON-BLOCKING, WITH RETRY) ---
let db = null;
let firebaseAdminInitialized = false;

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function tryInitializeFirebaseOnce() {
  if (admin.apps.length > 0) {
    try {
      db = getFirestore();
      firebaseAdminInitialized = true;
      console.log('[Firebase] already initialized (reused).');
      return true;
    } catch (e) {
      console.error('[Firebase] reuse error:', e);
    }
  }

  const serviceAccountKeyString = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (!serviceAccountKeyString) {
    console.warn('[Firebase] FIREBASE_SERVICE_ACCOUNT_KEY chưa được đặt. Firestore sẽ không hoạt động.');
    firebaseAdminInitialized = false;
    db = null;
    return false;
  }

  try {
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(serviceAccountKeyString);
    } catch (parseErr) {
      console.error('[Firebase] FIREBASE_SERVICE_ACCOUNT_KEY JSON.parse error:', parseErr);
      firebaseAdminInitialized = false;
      db = null;
      return false;
    }

    try {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      db = getFirestore();
      firebaseAdminInitialized = true;
      console.log('[Firebase] initialized and ready.');
      return true;
    } catch (initErr) {
      console.error('[Firebase] initializeApp error:', initErr);
      firebaseAdminInitialized = false;
      db = null;
      return false;
    }
  } catch (err) {
    console.error('[Firebase] unexpected error during init:', err);
    firebaseAdminInitialized = false;
    db = null;
    return false;
  }
}

async function initializeFirebaseWithRetries(maxAttempts = 6, baseDelay = 1000) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const ok = await tryInitializeFirebaseOnce();
      if (ok) return true;
    } catch (e) {
      console.error('[Firebase] attempt error:', e);
    }
    const delay = Math.min(baseDelay * Math.pow(2, attempt - 1), 10000);
    console.log(`[Firebase] Khởi tạo thất bại hoặc chưa sẵn sàng, sẽ thử lại sau ${delay}ms (attempt ${attempt}/${maxAttempts})`);
    await sleep(delay);
  }
  console.warn('[Firebase] Không thể khởi tạo Firebase sau nhiều lần thử. Tiếp tục chạy server nhưng Firestore sẽ không sẵn sàng.');
  return false;
}

// --- DICTIONARY CACHE (PRECOMPILED REGEX) ---
let sortedDoraemonEntries = []; // { id, key, value, regex }

function escapeRegExpString(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildRegexForKeySafe(key) {
  const keyStr = String(key);
  if (keyStr.length > DICTIONARY_MAX_LENGTH) {
    console.warn('[Regex] Key quá dài, bỏ qua tạo regex:', keyStr.length);
    throw new Error('Key length exceeds safety limit.');
  }

  const escaped = escapeRegExpString(keyStr);
  try {
    // Sử dụng boundary word: (?<![\p{L}\p{N}])${escaped}(?![\p{L}\p{N}])
    // Đảm bảo chỉ match toàn bộ từ
    return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, 'giu');
  } catch (e) {
    console.warn('[Regex] lookbehind/unicode failed for key, falling back to simple match:', keyStr.slice(0, 60));
    return new RegExp(escaped, 'gi');
  }
}

async function listenForDictionaryChanges() {
  if (!db) {
    console.warn('[Cache] Firestore chưa sẵn sàng, không thể khởi tạo cache từ điển.');
    return;
  }

  console.log('[Cache] Bắt đầu tải từ điển (initial .get()) ...');
  try {
    const oneShot = await db.collection('dictionary').get();
    const initialEntries = [];
    oneShot.forEach(doc => {
      const data = doc.data() || {};
      if (data.key && data.value) {
        try {
          const keyStr = String(data.key);
          const valueStr = String(data.value);
          const regex = buildRegexForKeySafe(keyStr);
          initialEntries.push({ id: doc.id, key: keyStr, value: valueStr, regex });
        } catch (e) {
          console.warn(`[Cache] Bỏ qua doc ${doc.id} do lỗi tạo regex:`, e && e.message ? e.message : e);
        }
      }
    });
    initialEntries.sort((a, b) => b.key.length - a.key.length);
    sortedDoraemonEntries = initialEntries;
    console.log(`[Cache] Initial load hoàn tất. items=${sortedDoraemonEntries.length}`);
  } catch (err) {
    console.warn('[Cache] Lỗi khi load initial dictionary (.get()):', err && err.message ? err.message : err);
  }

  console.log('[Cache] Đăng ký onSnapshot để nghe thay đổi (không dùng .select()) ...');
  try {
    db.collection('dictionary').onSnapshot(snapshot => {
      console.log(`[Cache] onSnapshot được gọi. snapshot.size = ${snapshot.size}`);
      const dictionaryEntries = [];
      snapshot.forEach(doc => {
        const data = doc.data() || {};
        if (data.key && data.value) {
          try {
            const keyStr = String(data.key);
            const valueStr = String(data.value);
            const regex = buildRegexForKeySafe(keyStr);
            dictionaryEntries.push({ id: doc.id, key: keyStr, value: valueStr, regex });
          } catch (e) {
            console.warn(`[Cache] Bỏ qua doc ${doc.id} do lỗi tạo regex cho key:`, data.key, e && e.message ? e.message : e);
          }
        } else {
          console.warn(`[Cache] Bỏ qua doc ${doc.id} do thiếu key hoặc value`, Object.keys(data));
        }
      });
      dictionaryEntries.sort((a, b) => b.key.length - a.key.length);
      if (dictionaryEntries.length > 0) {
        sortedDoraemonEntries = dictionaryEntries;
        console.log(`[Cache] Cache từ điển đã được cập nhật. Tổng số mục: ${sortedDoraemonEntries.length}`);
      } else {
        console.warn('[Cache] onSnapshot produced 0 valid entries; keeping previous cache.');
      }
    }, err => {
      console.error('[Cache] onSnapshot error:', err && err.message ? err.message : err);
    });
  } catch (err) {
    console.error('[Cache] Không thể đăng ký onSnapshot:', err && err.message ? err.message : err);
  }
}

// --- ADMIN DATA HELPERS ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000;
const LOGIN_BAN_DURATION_MS = 60 * 60 * 1000;
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER;
const LOGIN_ATTEMPTS_THRESHOLD = 10;

const getAdminDataDocRef = () => {
  if (!db) return null;
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
        banned_ips: {}, banned_fingerprints: {}, total_requests: 0,
        total_failed_recaptcha: 0, failedAttempts: {}, tfa_secret: null,
      };
      await docRef.set(initialData);
      return initialData;
    }
  } catch (error) {
    console.error('Lỗi khi lấy admin data từ Firestore:', error && error.message ? error.message : error);
    return {};
  }
}

async function updateAdminData(dataToUpdate) {
  const docRef = getAdminDataDocRef();
  if (docRef) await docRef.update(dataToUpdate).catch(e => console.error('Lỗi khi cập nhật admin data:', e && e.message ? e.message : e));
}

// --- UTIL ---
function getClientIp(req) { return (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(); }
function normalizeIp(ip) { return ip && ip.startsWith('::ffff:') ? ip.substring(7) : ip; }

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  let sanitized = input.trim().toLowerCase().substring(0, 200);
  return sanitized.replace(/[^\p{L}\p{N}\s\-,.?!]/gu, '');
}

// --- MIDDLEWARES ---
async function securityMiddleware(req, res, next) {
  const clientIpRaw = getClientIp(req);
  const ip = normalizeIp(clientIpRaw);
  const visitorId = req.body.visitorId;

  if (!db) return next();

  try {
    const adminData = await getAdminData();
    const currentBannedIps = adminData.banned_ips || {};
    const currentBannedFingerprints = adminData.banned_fingerprints || {};

    if (visitorId && currentBannedFingerprints[visitorId]) {
      const banExpiresAt = currentBannedFingerprints[visitorId];
      if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
        const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
        return res.status(403).json({ error: `Truy cập của bạn đã bị chặn ${banMessage}.` });
      } else {
        // Gỡ ban hết hạn
        delete currentBannedFingerprints[visitorId];
        await updateAdminData({ banned_fingerprints: currentBannedFingerprints });
      }
    }

    const banExpiresAt = currentBannedIps[ip];
    if (banExpiresAt) {
      if (banExpiresAt === PERMANENT_BAN_VALUE || Date.now() < banExpiresAt) {
        const banMessage = banExpiresAt === PERMANENT_BAN_VALUE ? 'vĩnh viễn' : `tạm thời. Vui lòng thử lại sau: ${new Date(banExpiresAt).toLocaleString('vi-VN')}`;
        return res.status(403).json({ error: `IP của bạn đang bị chặn ${banMessage}.` });
      } else {
        // Gỡ ban hết hạn
        delete currentBannedIps[ip];
        await updateAdminData({ banned_ips: currentBannedIps });
      }
    }
  } catch (error) {
    console.error('Lỗi trong security middleware:', error && error.message ? error.message : error);
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

// --- reCAPTCHA verify utility (timeout + retry + safe logging + V3 logic) ---
async function verifyRecaptcha(recaptchaToken, remoteIp, attempts = 2, timeoutMs = 5000) {
  const url = 'https://www.google.com/recaptcha/api/siteverify';
  for (let i = 0; i < attempts; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const params = new URLSearchParams({ secret: RECAPTCHA_SECRET_KEY || '', response: recaptchaToken, remoteip: remoteIp });
      const resp = await fetch(url, { method: 'POST', body: params, signal: controller.signal });
      clearTimeout(timer);
      if (!resp.ok) {
        const text = await resp.text().catch(() => '<no-body>');
        console.error('[reCAPTCHA] HTTP error', resp.status, text);
        if (resp.status >= 500 && i < attempts - 1) { await sleep(500 * (i + 1)); continue; }
        return { ok: false, error: 'http-error', status: resp.status, body: text };
      }
      const data = await resp.json();
      
      const isScoreAcceptable = typeof data.score === 'number' && data.score >= RECAPTCHA_SCORE_THRESHOLD;
      const isActionCorrect = data.action === RECAPTCHA_EXPECTED_ACTION;

      const isSuccessful = !!data.success && isScoreAcceptable && isActionCorrect;

      const ipLog = remoteIp || '<no-ip>';
      console.log(`${ipLog} - reCAPTCHA success: ${!!data.success}, score: ${data.score || 0}, action: ${data.action}, accepted: ${isSuccessful}`);
      
      return { ok: isSuccessful, data, score: data.score, action: data.action };
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        console.error('[reCAPTCHA] request timed out (attempt', i + 1, ')');
      } else {
        console.error('[reCAPTCHA] verify error (attempt', i + 1, '):', err && err.message ? err.message : err);
      }
      if (i < attempts - 1) await sleep(500 * (i + 1));
      else return { ok: false, error: 'network-or-timeout', err };
    }
  }
  return { ok: false, error: 'unknown' };
}

// --- ENDPOINTS ---
app.get('/', (req, res) => res.status(200).send('Backend Doraemon đang chạy.'));
app.get('/health', (req, res) => {
  res.status(200).json({ healthy: true, firebaseReady: !!firebaseAdminInitialized, dictionaryCount: sortedDoraemonEntries.length });
});

// giai-ma (main endpoint) - uses verifyRecaptcha
app.post('/giai-ma', securityMiddleware, async (req, res) => {
  if (!sortedDoraemonEntries || sortedDoraemonEntries.length === 0) return res.status(503).json({ error: 'Từ điển chưa sẵn sàng.' });
  const { userInput, recaptchaToken } = req.body;
  const ip = normalizeIp(getClientIp(req));
  if (!userInput || !recaptchaToken) return res.status(400).json({ error: 'Thiếu dữ liệu.' });

  const recaptchaResult = await verifyRecaptcha(recaptchaToken, ip, 2, 5000);
  
  // --- LỚP PHÒNG THỦ 2: BẮT LỖI reCAPTCHA VÀ BAN IP TỰ ĐỘNG ---
  if (!recaptchaResult.ok) {
    const adminData = await getAdminData();
    const failedAttempts = adminData.failedAttempts || {};
    
    await updateAdminData({ total_failed_recaptcha: FieldValue.increment(1) });

    // Kích hoạt logic CẤM IP cho thất bại reCAPTCHA
    if (!failedAttempts[ip]) failedAttempts[ip] = {};
    const currentFails = (failedAttempts[ip].recaptcha_fail_count || 0) + 1;
    failedAttempts[ip].recaptcha_fail_count = currentFails;

    if (currentFails >= RECAPTCHA_FAIL_THRESHOLD) {
      const banExpiresAt = Date.now() + BAN_DURATION_MS;
      const currentBannedIps = adminData.banned_ips || {};
      currentBannedIps[ip] = banExpiresAt;

      // Xóa bộ đếm thất bại sau khi cấm
      delete failedAttempts[ip].recaptcha_fail_count;
      
      // Xóa IP entry nếu không còn thuộc tính nào (ví dụ: chỉ còn lock-out login)
      if (Object.keys(failedAttempts[ip]).length === 0) {
        delete failedAttempts[ip];
      }
      
      console.log(`[BAN-AUTODEFENSE] IP ${ip} đã bị cấm 12 giờ do ${currentFails} lần thất bại reCAPTCHA liên tiếp.`);

      await updateAdminData({ 
          failedAttempts: failedAttempts, 
          banned_ips: currentBannedIps
      });

      return res.status(429).json({ error: `Hệ thống phát hiện hoạt động bất thường. IP của bạn đã bị tạm khóa 12 giờ.` });
    } else {
        // Chỉ cập nhật bộ đếm nếu chưa đạt ngưỡng cấm
        await updateAdminData({ failedAttempts });
    }
    
    // Xử lý lỗi reCAPTCHA thông thường (sau khi đã xử lý logic cấm IP)
    let errorMessage = 'Xác thực reCAPTCHA thất bại.';
    if (recaptchaResult.score !== undefined && recaptchaResult.score < RECAPTCHA_SCORE_THRESHOLD) {
        errorMessage = `Xác thực reCAPTCHA thất bại (Điểm ${recaptchaResult.score} quá thấp).`;
    } else if (recaptchaResult.action && recaptchaResult.action !== RECAPTCHA_EXPECTED_ACTION) {
        errorMessage = `Xác thực reCAPTCHA thất bại (Action ${recaptchaResult.action} không khớp).`;
    } else if (recaptchaResult.error === 'network-or-timeout' || recaptchaResult.error === 'http-error') {
        return res.status(500).json({ error: 'Lỗi khi xác thực reCAPTCHA.' });
    }
    
    return res.status(401).json({ error: errorMessage });
  }

  // --- NẾU reCAPTCHA THÀNH CÔNG: XÓA BỘ ĐẾM THẤT BẠI ---
  if (recaptchaResult.ok) {
    const adminData = await getAdminData();
    const failedAttempts = adminData.failedAttempts || {};
    if (failedAttempts[ip]?.recaptcha_fail_count) {
      delete failedAttempts[ip].recaptcha_fail_count;
      // Xóa IP entry nếu không còn thuộc tính nào
      if (Object.keys(failedAttempts[ip]).length === 0) {
        delete failedAttempts[ip];
      }
      await updateAdminData({ failedAttempts });
    }
  }

  // --- XỬ LÝ YÊU CẦU BÌNH THƯỜNG ---
  try {
    await updateAdminData({ total_requests: FieldValue.increment(1) });
    let text = sanitizeInput(userInput);
    let replaced = false;
    for (const entry of sortedDoraemonEntries) {
      try {
        const newText = text.replace(entry.regex, entry.value);
        if (newText !== text) {
          text = newText;
          replaced = true;
        }
      } catch (e) {
        console.warn('[giai-ma] skip regex for entry', entry.id, e && e.message ? e.message : e);
      }
    }
    res.json({ success: true, ketQua: replaced ? text : 'Không tìm thấy từ khóa phù hợp.' });
  } catch (e) {
    console.error('Lỗi /giai-ma:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Lỗi máy chủ.' });
  }
});

// --- ADMIN APIs ---
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = normalizeIp(getClientIp(req));

  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  if (!username || !password) return res.status(400).json({ error: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.' });

  try {
    const adminData = await getAdminData();
    const failedAttempts = adminData.failedAttempts || {};

    if (failedAttempts[ip]?.lockoutUntil && Date.now() < failedAttempts[ip].lockoutUntil) {
      const timeLeft = Math.ceil((failedAttempts[ip].lockoutUntil - Date.now()) / 60000);
      return res.status(429).json({ error: `Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau ${timeLeft} phút.` });
    }

    const isUsernameMatch = await bcrypt.compare(username, ADMIN_USERNAME_HASH);
    const isPasswordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

    if (isUsernameMatch && isPasswordMatch) {
      // Clear login failed counter on success
      if (failedAttempts[ip]?.login) {
        delete failedAttempts[ip].login;
        // Xóa IP entry nếu không còn thuộc tính nào
        if (Object.keys(failedAttempts[ip]).length === 0) {
            delete failedAttempts[ip];
        }
        await updateAdminData({ failedAttempts });
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
      if (!failedAttempts[ip]) failedAttempts[ip] = {};
      const currentFails = (failedAttempts[ip].login || 0) + 1;
      failedAttempts[ip].login = currentFails;
      failedAttempts[ip].lastAttempt = Date.now();

      if (currentFails >= LOGIN_ATTEMPTS_THRESHOLD) {
        failedAttempts[ip].lockoutUntil = Date.now() + LOGIN_BAN_DURATION_MS;
        console.log(`[LOGIN-LOCKOUT] IP ${ip} đã bị khóa đăng nhập trong 1 giờ.`);
        await updateAdminData({ failedAttempts });
        return res.status(429).json({ error: 'Bạn đã nhập sai quá nhiều lần. IP của bạn đã bị tạm khóa trong 1 giờ.' });
      }

      await updateAdminData({ failedAttempts });
      const attemptsLeft = LOGIN_ATTEMPTS_THRESHOLD - currentFails;
      res.status(401).json({ error: `Tên đăng nhập hoặc mật khẩu không đúng. Còn ${attemptsLeft} lần thử.` });
    }
  } catch (error) {
    console.error('Lỗi trong quá trình đăng nhập admin:', error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi xử lý đăng nhập.' });
  }
});

app.post('/admin/verify-tfa', async (req, res) => {
  const { code, tfaToken } = req.body;
  const tfaCode = code || req.body.tfaCode; 
  if (!tfaCode || !tfaToken) return res.status(400).json({ error: 'Thiếu mã xác thực hoặc token.' });

  jwt.verify(tfaToken, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: 'Phiên xác thực 2FA đã hết hạn.' });

    try {
      const adminData = await getAdminData();
      const tfaSecret = adminData.tfa_secret;

      if (!tfaSecret) return res.status(500).json({ error: 'Lỗi server: Chưa có Secret 2FA.' });

      const verified = speakeasy.totp.verify({
        secret: tfaSecret,
        encoding: 'base32',
        token: tfaCode,
        window: 1,
      });

      if (verified) {
        const token = jwt.sign({ username: user.username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
        res.cookie('adminToken', token, {
          httpOnly: true,
          secure: true,
          sameSite: 'Lax', 
          maxAge: 12 * 60 * 60 * 1000,
        }).json({ success: true, message: 'Đăng nhập thành công.' });
      } else {
        res.status(401).json({ error: 'Mã xác thực 2FA không đúng.' });
      }
    } catch (error) {
      console.error('Lỗi khi xử lý 2FA:', error && error.message ? error.message : error);
      res.status(500).json({ error: 'Lỗi server khi xác thực 2FA.' });
    }
  });
});

app.get('/admin/verify-session', authenticateAdminToken, (req, res) => {
  res.json({ success: true, message: 'Phiên hợp lệ.', username: req.user.username });
});

app.post('/admin/logout', (req, res) => {
  res.clearCookie('adminToken', { httpOnly: true, secure: true, sameSite: 'Lax' }) 
     .json({ success: true, message: 'Đã đăng xuất.' });
});

// Cập nhật để trả về 4 Object dữ liệu cấm (tương thích Dashboard)
app.get('/admin/dashboard-data', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  try {
    const adminData = await getAdminData();
    const now = Date.now();

    // Hàm làm sạch và lọc ban hết hạn
    const cleanBans = (bans) => {
      let activeBans = {};
      let expiredCount = 0;
      for (const [key, expiresAt] of Object.entries(bans || {})) {
        // PERMANENT_BAN_VALUE hoặc chưa hết hạn
        if (expiresAt === PERMANENT_BAN_VALUE || now < expiresAt) { 
          activeBans[key] = expiresAt;
        } else {
          expiredCount++;
        }
      }
      return { activeBans, expiredCount };
    };

    const { activeBans: activeIps, expiredCount: expiredIps } = cleanBans(adminData.banned_ips);
    const { activeBans: activeFp, expiredCount: expiredFp } = cleanBans(adminData.banned_fingerprints);
    
    // Cập nhật lại Firestore sau khi dọn dẹp (non-blocking)
    if (expiredIps > 0 || expiredFp > 0) {
      updateAdminData({ banned_ips: activeIps, banned_fingerprints: activeFp }).catch(e => {});
    }

    // LOGIC TÁCH DỮ LIỆU CẤM SANG 4 OBJECT THEO YÊU CẦU CỦA CLIENT
    const permanent_banned_ips = {};
    const temporary_banned_ips = {};
    const permanent_banned_fingerprints = {};
    const temporary_banned_fingerprints = {};

    for (const [ip, expiry] of Object.entries(activeIps)) {
        if (expiry === PERMANENT_BAN_VALUE) {
            permanent_banned_ips[ip] = expiry;
        } else {
            temporary_banned_ips[ip] = expiry;
        }
    }

    for (const [fp, expiry] of Object.entries(activeFp)) {
        if (expiry === PERMANENT_BAN_VALUE) {
            permanent_banned_fingerprints[fp] = expiry;
        } else {
            temporary_banned_fingerprints[fp] = expiry;
        }
    }

    res.json({
      success: true,
      stats: {
        total_requests: adminData.total_requests || 0,
        total_failed_recaptcha: adminData.total_failed_recaptcha || 0,
      },
      permanent_banned_ips,
      temporary_banned_ips,
      permanent_banned_fingerprints,
      temporary_banned_fingerprints,
    });
  } catch (error) {
    console.error('Lỗi khi lấy dashboard data:', error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi lấy dữ liệu.' });
  }
});

// ĐÃ FIX: Sử dụng type.toLowerCase()
app.post('/admin/ban', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  const { type, value, duration } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'Thiếu thông tin.' });

  try {
    const expiresAt = duration === 'permanent' ? PERMANENT_BAN_VALUE : Date.now() + BAN_DURATION_MS;
    
    // Đảm bảo type là chữ thường để so sánh (khắc phục lỗi case-sensitivity)
    const lowerCaseType = type.toLowerCase(); 

    const adminData = await getAdminData();
    let updated = false;

    if (lowerCaseType === 'ip') {
      (adminData.banned_ips = adminData.banned_ips || {})[value] = expiresAt;
      updated = true;
    } else if (lowerCaseType === 'fingerprint') {
      (adminData.banned_fingerprints = adminData.banned_fingerprints || {})[value] = expiresAt;
      updated = true;
    } else {
      return res.status(400).json({ error: 'Loại ban không hợp lệ.' });
    }

    if (updated) {
        await updateAdminData({ banned_ips: adminData.banned_ips, banned_fingerprints: adminData.banned_fingerprints });
        res.json({ success: true, message: `${type} ${value} đã bị cấm thành công.` });
    } else {
        res.status(500).json({ error: 'Lỗi logic khi ban.' });
    }
  } catch (error) {
    console.error('Lỗi khi cấm:', error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi cấm.' });
  }
});

// ĐÃ FIX: Sử dụng type.toLowerCase()
app.post('/admin/unban', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  const { type, value } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'Thiếu thông tin.' });

  try {
    const adminData = await getAdminData();
    let unbanned = false;
    
    // Đảm bảo type là chữ thường để so sánh (KHẮC PHỤC LỖI BẠN BÁO CÁO TRƯỚC)
    const lowerCaseType = type.toLowerCase(); 

    if (lowerCaseType === 'ip' && adminData.banned_ips?.[value]) {
      delete adminData.banned_ips[value];
      unbanned = true;
    } else if (lowerCaseType === 'fingerprint' && adminData.banned_fingerprints?.[value]) {
      delete adminData.banned_fingerprints[value];
      unbanned = true;
    }

    if (unbanned) {
      await updateAdminData({ banned_ips: adminData.banned_ips, banned_fingerprints: adminData.banned_fingerprints });
      res.json({ success: true, message: `${type} ${value} đã được gỡ cấm thành công.` });
    } else {
      // Sửa lỗi: Trả về lỗi nếu không tìm thấy
      res.status(404).json({ error: `${type} ${value} không nằm trong danh sách cấm.` });
    }
  } catch (error) {
    console.error('Lỗi khi gỡ cấm:', error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi gỡ cấm.' });
  }
});

// --- DICTIONARY ADMIN APIs ---
// ĐÃ FIX: Đảm bảo phản hồi luôn chứa dictionary: [] trong trường hợp lỗi (Khắc phục lỗi f.map is not a function)
app.get('/admin/dictionary', authenticateAdminToken, async (req, res) => {
  // KHẮC PHỤC 1: Nếu Firestore không sẵn sàng, trả về 503 kèm dictionary: []
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.', dictionary: [] });
  try {
    const snapshot = await db.collection('dictionary').get();
    
    // Đảm bảo dữ liệu là mảng hợp lệ
    const dictionary = snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(item => typeof item === 'object' && item !== null); 

    res.json({ success: true, dictionary: dictionary || [] });
  } catch (error) {
    console.error('Lỗi khi lấy dictionary:', error && error.message ? error.message : error);
    // KHẮC PHỤC 2: Nếu có lỗi server, trả về 500 kèm dictionary: []
    res.status(500).json({ error: 'Lỗi server khi lấy dictionary.', dictionary: [] });
  }
});

app.post('/admin/dictionary', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  const { key, value } = req.body;
  
  if (!key || !value) return res.status(400).json({ error: 'Key và Value không được để trống.' });

  try {
    const docRef = await db.collection('dictionary').add({ key, value, createdAt: FieldValue.serverTimestamp() });
    res.json({ success: true, id: docRef.id, key, value });
  } catch (error) {
    console.error('Lỗi khi thêm dictionary:', error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi thêm dictionary.' });
  }
});

app.put('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  const { id } = req.params;
  const { key, value } = req.body;

  if (!key || !value) return res.status(400).json({ error: 'Key và Value không được để trống.' });

  try {
    await db.collection('dictionary').doc(id).update({ key, value, updatedAt: FieldValue.serverTimestamp() });
    res.json({ success: true, message: 'Cập nhật thành công.' });
  } catch (error) {
    console.error(`Lỗi khi cập nhật dictionary id ${id}:`, error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi cập nhật dictionary.' });
  }
});

app.delete('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  const { id } = req.params;

  try {
    await db.collection('dictionary').doc(id).delete();
    res.json({ success: true, message: 'Xóa thành công.' });
  } catch (error) {
    console.error(`Lỗi khi xóa dictionary id ${id}:`, error && error.message ? error.message : error);
    res.status(500).json({ error: 'Lỗi server khi xóa dictionary.' });
  }
});

app.post('/admin/migrate-dictionary', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Dịch vụ Firestore chưa sẵn sàng.' });
  try {
    const snapshot = await db.collection('dictionary').get();
    let updated = 0;
    let removed = 0;
    let processed = 0;

    for (const doc of snapshot.docs) {
      processed++;
      const data = doc.data() || {};
      const update = {};

      const hasKey = typeof data.key === 'string' && data.key.trim().length > 0;
      const hasValue = typeof data.value === 'string' && data.value.trim().length > 0;

      if (!hasKey || !hasValue) {
        // Xóa các mục rỗng hoặc thiếu dữ liệu
        await db.collection('dictionary').doc(doc.id).delete();
        removed++;
        continue;
      }
      
      const currentKey = data.key;
      const currentValue = data.value;

      // Sanitize key/value trước khi cập nhật
      const sanitizedKey = currentKey.trim().substring(0, DICTIONARY_MAX_LENGTH);
      const sanitizedValue = currentValue.trim().substring(0, DICTIONARY_MAX_LENGTH);

      if (sanitizedKey !== currentKey) {
          update.key = sanitizedKey;
      }
      if (sanitizedValue !== currentValue) {
          update.value = sanitizedValue;
      }
      
      if (Object.keys(update).length > 0) {
        await db.collection('dictionary').doc(doc.id).update(update);
        updated++;
      }

      if (processed % 200 === 0) await sleep(300);
    }
    return res.json({ success: true, updated, removed, totalProcessed: processed });
  } catch (err) {
    console.error('/admin/migrate-dictionary error', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'Lỗi khi migrate dictionary.' });
  }
});


// --- BOOTSTRAP ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
  if (!firebaseAdminInitialized) console.warn('CẢNH BÁO: Firestore chưa được khởi tạo (đang chờ).');
});

// init firebase & start listener in background
(async () => {
  const ok = await initializeFirebaseWithRetries();
  if (ok && firebaseAdminInitialized) {
    try {
      await listenForDictionaryChanges();
    } catch (err) {
      console.error('Lỗi khi bật listener từ điển:', err && err.message ? err.message : err);
    }
  } else {
    console.warn('[Bootstrap] Firebase không sẵn sàng — bạn có thể kiểm tra FIREBASE_SERVICE_ACCOUNT_KEY trong env.');
  }
})();
