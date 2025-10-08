// server.js
// Robust stable server with improved reCAPTCHA verify (timeout + retry + logging).
// Paste this file over your current server.js and redeploy. After deploy, call /giai-ma
// and share the logs lines starting with "[reCAPTCHA]" if verification still fails.

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

// --- Global error handlers ---
process.on('unhandledRejection', (reason, promise) => console.error('Unhandled Rejection', reason));
process.on('uncaughtException', err => console.error('Uncaught Exception', err && err.stack ? err.stack : err));

// --- App setup ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: [
    'https://viet-8101.github.io',
    'https://viet-8101.github.io/admin-dashboard-doraemon/',
    'http://localhost:5173',
    'https://admin-dashboard-doraemon.onrender.com'
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.set('trust proxy', 1);

// Security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
  next();
});

// --- Config ---
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_USERNAME_HASH = process.env.ADMIN_USERNAME_HASH;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const JWT_SECRET = process.env.JWT_SECRET;
const appId = process.env.RENDER_SERVICE_ID || 'default-render-app-id';

if (!JWT_SECRET) {
  console.error('JWT_SECRET missing');
  process.exit(1);
}

// --- Firebase init with backoff ---
let db = null;
let firebaseAdminInitialized = false;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function tryInitFirebase() {
  if (admin.apps.length > 0) {
    db = getFirestore();
    firebaseAdminInitialized = true;
    return true;
  }
  const keyStr = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (!keyStr) return false;
  try {
    const serviceAccount = JSON.parse(keyStr);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db = getFirestore();
    firebaseAdminInitialized = true;
    console.log('[Firebase] initialized');
    return true;
  } catch (e) {
    console.error('[Firebase] init error', e && e.message ? e.message : e);
    db = null;
    firebaseAdminInitialized = false;
    return false;
  }
}

async function initFirebaseWithBackoff(maxAttempts = 6) {
  for (let i = 1; i <= maxAttempts; i++) {
    const ok = await tryInitFirebase();
    if (ok) return true;
    const delay = Math.min(1000 * Math.pow(2, i - 1), 10000);
    console.log(`[Firebase] retry in ${delay}ms (attempt ${i})`);
    await sleep(delay);
  }
  console.warn('[Firebase] init failed after retries');
  return false;
}

// --- Dictionary cache ---
let sortedDoraemonEntries = []; // {id,key,value,regex}

function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\\\]\\]/g, '\\$&'); }

function buildRegexForKeySafe(key) {
  const escaped = escapeRegExp(key);
  try {
    return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, 'giu');
  } catch (e) {
    console.warn('[Regex] fallback for key (lookbehind failed)', key && String(key).slice(0, 60));
    return new RegExp(escaped, 'gi');
  }
}

async function listenForDictionaryChanges() {
  if (!db) return;
  try {
    const one = await db.collection('dictionary').get();
    const entries = [];
    one.forEach(doc => {
      const d = doc.data() || {};
      const key = d.key !== undefined ? String(d.key) : null;
      const value = d.value !== undefined ? String(d.value) : '';
      if (key) {
        entries.push({ id: doc.id, key, value, regex: buildRegexForKeySafe(key) });
      }
    });
    entries.sort((a, b) => b.key.length - a.key.length);
    sortedDoraemonEntries = entries;
    console.log('[Cache] initial loaded', entries.length);
  } catch (e) {
    console.error('[Cache] initial load error', e && e.message ? e.message : e);
  }

  try {
    db.collection('dictionary').onSnapshot(snapshot => {
      const entries = [];
      snapshot.forEach(doc => {
        const d = doc.data() || {};
        const key = d.key !== undefined ? String(d.key) : null;
        const value = d.value !== undefined ? String(d.value) : '';
        if (key) {
          try { entries.push({ id: doc.id, key, value, regex: buildRegexForKeySafe(key) }); } catch (e) { /* skip */ }
        }
      });
      entries.sort((a, b) => b.key.length - a.key.length);
      if (entries.length > 0) {
        sortedDoraemonEntries = entries;
        console.log('[Cache] onSnapshot updated', entries.length);
      } else {
        console.warn('[Cache] onSnapshot produced 0 entries; keeping previous cache');
      }
    }, err => console.error('[Cache] onSnapshot error', err && err.message ? err.message : err));
  } catch (e) {
    console.error('[Cache] subscribe error', e && e.message ? e.message : e);
  }
}

// --- Admin data helpers ---
const BAN_DURATION_MS = 12 * 60 * 60 * 1000;
const LOGIN_BAN_DURATION_MS = 60 * 60 * 1000;
const PERMANENT_BAN_VALUE = Number.MAX_SAFE_INTEGER;
const FAILED_ATTEMPTS_THRESHOLD = 5;
const LOGIN_ATTEMPTS_THRESHOLD = 10;

const getAdminDataDocRef = () => db ? db.collection('artifacts').doc(appId).collection('public').doc('data').collection('admin_data').doc('main_data') : null;
async function getAdminData() {
  const ref = getAdminDataDocRef();
  if (!ref) return {};
  try {
    const s = await ref.get();
    if (s.exists) return s.data();
    const initial = { banned_ips: {}, banned_fingerprints: {}, total_requests: 0, total_failed_recaptcha: 0, failedAttempts: {}, tfa_secret: null };
    await ref.set(initial);
    return initial;
  } catch (e) {
    console.error('getAdminData', e && e.message ? e.message : e);
    return {};
  }
}
async function updateAdminData(u) { const ref = getAdminDataDocRef(); if (ref) await ref.update(u).catch(e => console.error('updateAdminData', e && e.message ? e.message : e)); }

function getClientIp(req) { return (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(); }
function normalizeIp(ip) { return ip && ip.startsWith('::ffff:') ? ip.substring(7) : ip; }
function sanitizeInput(input) { if (typeof input !== 'string') return ''; let s = input.trim().toLowerCase().substring(0, 200); return s.replace(/[^\p{L}\p{N}\s\-,.?!]/gu, ''); }

// --- Security middleware & auth ---
async function securityMiddleware(req, res, next) {
  const ip = normalizeIp(getClientIp(req));
  if (!db) return next();
  try {
    const adminData = await getAdminData();
    const banned = adminData.banned_ips || {};
    if (banned[ip]) {
      const exp = banned[ip];
      if (exp === PERMANENT_BAN_VALUE || Date.now() < exp) return res.status(403).json({ error: 'IP bị chặn' });
      else { delete banned[ip]; await updateAdminData({ banned_ips: banned }); }
    }
  } catch (e) { console.error('securityMiddleware', e && e.message ? e.message : e); return res.status(500).json({ error: 'Lỗi server' }); }
  next();
}

function authenticateAdminToken(req, res, next) {
  const token = req.cookies.adminToken;
  if (!token) return res.status(401).json({ error: 'Truy cập bị từ chối.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token không hợp lệ.' });
    req.user = user;
    next();
  });
}

// --- reCAPTCHA verify utility (timeout + retry + safe logging) ---
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
      console.log('[reCAPTCHA] verify result', { success: data.success, score: data.score, action: data.action, hostname: data.hostname, errors: data['error-codes'] });
      return { ok: !!data.success, data };
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
}

// --- Endpoints ---
app.get('/', (req, res) => res.status(200).send('Backend Doraemon đang chạy.'));
app.get('/health', (req, res) => res.json({ healthy: true, firebaseReady: !!firebaseAdminInitialized, dictionaryCount: sortedDoraemonEntries.length }));

// giai-ma (main endpoint) - uses verifyRecaptcha
app.post('/giai-ma', securityMiddleware, async (req, res) => {
  if (!sortedDoraemonEntries || sortedDoraemonEntries.length === 0) return res.status(503).json({ error: 'Từ điển chưa sẵn sàng.' });
  const { userInput, recaptchaToken } = req.body;
  const ip = normalizeIp(getClientIp(req));
  if (!userInput || !recaptchaToken) return res.status(400).json({ error: 'Thiếu dữ liệu.' });

  // verify recaptcha
  const recaptchaResult = await verifyRecaptcha(recaptchaToken, ip, 2, 5000);
  if (!recaptchaResult.ok) {
    if (recaptchaResult.data && recaptchaResult.data['error-codes']) {
      const codes = recaptchaResult.data['error-codes'];
      if (codes.includes('invalid-input-secret')) {
        console.error('[reCAPTCHA] invalid secret (check env)');
        return res.status(500).json({ error: 'Lỗi server khi xác thực reCAPTCHA.' });
      }
      if (codes.includes('invalid-input-response') || codes.includes('timeout-or-duplicate') || codes.includes('missing-input-response')) {
        await updateAdminData({ total_failed_recaptcha: FieldValue.increment(1) });
        return res.status(401).json({ error: 'Xác thực reCAPTCHA thất bại.' });
      }
      await updateAdminData({ total_failed_recaptcha: FieldValue.increment(1) });
      return res.status(401).json({ error: 'Xác thực reCAPTCHA thất bại.' });
    }
    if (recaptchaResult.error === 'network-or-timeout' || recaptchaResult.error === 'http-error') {
      console.error('[reCAPTCHA] transient verify failure:', recaptchaResult);
      return res.status(500).json({ error: 'Lỗi khi xác thực reCAPTCHA.' });
    }
  }

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
        console.warn('giai-ma skip', entry.id, e && e.message ? e.message : e);
      }
    }
    res.json({ success: true, ketQua: replaced ? text : 'Không tìm thấy từ khóa phù hợp.' });
  } catch (e) {
    console.error('giai-ma error', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Lỗi máy chủ.' });
  }
});

// Admin login, verify-tfa, dashboard-data, dictionary management (preserve behavior)
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body; const ip = normalizeIp(getClientIp(req));
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' }); if (!username || !password) return res.status(400).json({ error: 'Thiếu thông tin.' });
  try {
    const adminData = await getAdminData(); const failedAttempts = adminData.failedAttempts || {};
    if (failedAttempts[ip]?.lockoutUntil && Date.now() < failedAttempts[ip].lockoutUntil) { const left = Math.ceil((failedAttempts[ip].lockoutUntil - Date.now()) / 60000); return res.status(429).json({ error: `Vui lòng thử lại sau ${left} phút.` }); }
    const isU = await bcrypt.compare(username, ADMIN_USERNAME_HASH); const isP = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (isU && isP) {
      if (failedAttempts[ip]) { delete failedAttempts[ip]; await updateAdminData({ failedAttempts }); }
      let tfaSecret = adminData.tfa_secret; let qr = null; let message = 'Vui lòng nhập mã xác thực.';
      if (!tfaSecret) { const secret = speakeasy.generateSecret({ length: 20, name: 'DoraemonAdmin' }); tfaSecret = secret.base32; await updateAdminData({ tfa_secret: tfaSecret }); qr = await qrcode.toDataURL(secret.otpauth_url); message = 'Quét mã QR...'; }
      const tfaToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '5m' }); res.json({ success: true, message, tfaToken, qrCodeUrl: qr });
    } else {
      if (!failedAttempts[ip]) failedAttempts[ip] = {}; const cur = (failedAttempts[ip].login || 0) + 1; failedAttempts[ip].login = cur; failedAttempts[ip].lastAttempt = Date.now();
      if (cur >= LOGIN_ATTEMPTS_THRESHOLD) { failedAttempts[ip].lockoutUntil = Date.now() + LOGIN_BAN_DURATION_MS; await updateAdminData({ failedAttempts }); return res.status(429).json({ error: 'IP bị khóa.' }); }
      await updateAdminData({ failedAttempts }); res.status(401).json({ error: 'Sai thông tin.' });
    }
  } catch (e) { console.error('admin login error', e && e.message ? e.message : e); res.status(500).json({ error: 'Lỗi server.' }); }
});

app.post('/admin/verify-tfa', async (req, res) => {
  const { tfaToken, tfaCode } = req.body; if (!db || !tfaToken || !tfaCode) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
  jwt.verify(tfaToken, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Phiên hết hạn.' });
    const adminData = await getAdminData();
    if (!adminData.tfa_secret) return res.status(403).json({ error: '2FA chưa thiết lập.' });
    const verified = speakeasy.totp.verify({ secret: adminData.tfa_secret, encoding: 'base32', token: tfaCode, window: 1 });
    if (verified) {
      const adminToken = jwt.sign({ username: decoded.username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
      res.cookie('adminToken', adminToken, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 8 * 3600000 });
      res.json({ success: true, message: 'Đăng nhập thành công!' });
    } else res.status(401).json({ error: 'Mã không chính xác.' });
  });
});

app.get('/admin/verify-session', authenticateAdminToken, (req, res) => res.json({ success: true, loggedIn: true }));
app.post('/admin/logout', (req, res) => { res.clearCookie('adminToken', { httpOnly: true, secure: true, sameSite: 'none' }); res.json({ success: true }); });

app.get('/admin/dashboard-data', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  try {
    const adminData = await getAdminData(); const now = Date.now(); const perm = {}, temp = {};
    if (adminData.banned_ips) { for (const [ip, expiry] of Object.entries(adminData.banned_ips)) { if (expiry === PERMANENT_BAN_VALUE) perm[ip] = expiry; else if (expiry > now) temp[ip] = expiry; } }
    res.json({ success: true, stats: { total_requests: adminData.total_requests || 0, total_failed_recaptcha: adminData.total_failed_recaptcha || 0 }, permanent_banned_ips: perm, temporary_banned_ips: temp });
  } catch (e) { res.status(500).json({ error: 'Lỗi khi lấy dữ liệu admin.' }); }
});

// dictionary admin endpoints
app.get('/admin/dictionary', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  try { const snap = await db.collection('dictionary').get(); const dictionary = snap.docs.map(d => ({ id: d.id, ...d.data() })); res.json(dictionary); } catch (e) { res.status(500).json({ error: 'Lỗi khi lấy từ điển.' }); }
});
app.post('/admin/dictionary', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  try { const { key, value } = req.body; if (!key || !value) return res.status(400).json({ error: 'Thiếu key/value' }); const docRef = await db.collection('dictionary').add({ key, value }); res.status(201).json({ id: docRef.id, key, value }); } catch (e) { res.status(500).json({ error: 'Lỗi khi thêm từ mới.' }); }
});
app.put('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  try { const { id } = req.params; const { key, value } = req.body; if (!key || !value) return res.status(400).json({ error: 'Thiếu key/value' }); await db.collection('dictionary').doc(id).update({ key, value }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: 'Lỗi khi cập nhật từ.' }); }
});
app.delete('/admin/dictionary/:id', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  try { await db.collection('dictionary').doc(req.params.id).delete(); res.json({ success: true }); } catch (e) { res.status(500).json({ error: 'Lỗi khi xóa từ.' }); }
});

// Optional admin migration endpoint to normalize dictionary docs (convert non-strings to strings)
// POST /admin/migrate-dictionary { action: 'convert-only' | 'delete-empty' }
app.post('/admin/migrate-dictionary', authenticateAdminToken, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Firestore chưa sẵn sàng.' });
  const action = (req.body && req.body.action) || 'convert-only';
  try {
    const snap = await db.collection('dictionary').get();
    let updated = 0, removed = 0, processed = 0;
    for (const doc of snap.docs) {
      processed++;
      const data = doc.data() || {};
      const hasKey = Object.prototype.hasOwnProperty.call(data, 'key');
      const hasValue = Object.prototype.hasOwnProperty.call(data, 'value');
      if (!hasKey && !hasValue) {
        if (action === 'delete-empty') { await db.collection('dictionary').doc(doc.id).delete(); removed++; }
        continue;
      }
      const update = {};
      if (!hasKey) update.key = String(doc.id);
      else if (typeof data.key !== 'string') update.key = typeof data.key === 'object' ? JSON.stringify(data.key) : String(data.key);
      if (!hasValue) update.value = '';
      else if (typeof data.value !== 'string') update.value = typeof data.value === 'object' ? JSON.stringify(data.value) : String(data.value);
      if (Object.keys(update).length > 0) { await db.collection('dictionary').doc(doc.id).update(update); updated++; }
      if (processed % 200 === 0) await sleep(300);
    }
    return res.json({ success: true, updated, removed, totalProcessed: processed });
  } catch (err) {
    console.error('/admin/migrate-dictionary error', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'Lỗi khi migrate dictionary.' });
  }
});

// --- Bootstrap ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
  if (!firebaseAdminInitialized) console.warn('Firestore chưa được khởi tạo (đang chờ).');
});

(async () => {
  const ok = await initFirebaseWithBackoff();
  if (ok) { await listenForDictionaryChanges(); } else { console.warn('[Bootstrap] Firebase not ready; dictionary listener skipped.'); }
})();
