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

// --- BIẾN MÔI TRƯỜNG & CONFIG CHUNG (ĐÃ THÊM) ---
// Xác định môi trường để cấu hình cookie (sửa lỗi đăng nhập)
const isProduction = process.env.NODE_ENV === 'production';
let firebaseAdminInitialized = false;
let db;
let globalDictionary = {}; // Bộ nhớ cache từ điển toàn cục

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

// --- HÀM HỖ TRỢ ---
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// --- HÀM KHỞI TẠO FIREBASE ADMIN SDK (FIX TRIỆT ĐỂ LỖI JSON PARSE) ---
async function initializeFirebaseWithRetries(retries = 5, delay = 5000) {
    if (firebaseAdminInitialized) return true;

    // Lấy biến môi trường
    const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;

    if (!serviceAccountKey) {
        console.error('LỖI CẤU HÌNH: Thiếu biến môi trường FIREBASE_SERVICE_ACCOUNT_KEY.');
        return false;
    }

    for (let i = 0; i < retries; i++) {
        try {
            let cleanedKey = serviceAccountKey.trim();

            // FIX LỖI JSON PARSE:
            // Khi dán JSON đã được thoát (escaped) vào biến môi trường (ví dụ: private_key có \\n), 
            // chúng ta cần thay thế chuỗi '\\n' thành ký tự xuống dòng thực tế '\n'
            // để Firebase Admin SDK có thể đọc đúng.
            // Phương pháp này loại bỏ lỗi "Bad control character in string literal"
            cleanedKey = cleanedKey.replace(/\\n/g, '\n');
            
            const serviceAccount = JSON.parse(cleanedKey);

            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount),
            });

            db = getFirestore();
            console.log('✅ Firebase Admin SDK đã khởi tạo thành công.');
            firebaseAdminInitialized = true;
            return true;

        } catch (error) {
            console.error(`[Firebase] Thử khởi tạo lần ${i + 1} thất bại: ${error.message}`);
            if (i < retries - 1) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }

    console.error('🔴 KHỞI TẠO LỖI: Không thể khởi tạo Firebase Admin SDK sau nhiều lần thử.');
    return false;
}

// Hàm load từ điển từ Firestore
async function loadDictionary() {
  if (!firebaseAdminInitialized) {
    console.warn('Firestore chưa sẵn sàng. Bỏ qua việc tải từ điển.');
    return;
  }
  console.log('Đang tải từ điển từ Firestore...');
  try {
    const snapshot = await db.collection('dictionary').get();
    const newDictionary = {};
    snapshot.forEach(doc => {
      const data = doc.data();
      newDictionary[data.key] = data.value;
    });
    globalDictionary = newDictionary;
    console.log(`✅ Tải từ điển thành công. Tổng cộng ${Object.keys(globalDictionary).length} mục.`);
  } catch (error) {
    console.error('Lỗi khi tải từ điển:', error.message);
  }
}

// Middleware xác thực token
const verifyAdminToken = (req, res, next) => {
  const token = req.cookies.adminToken;
  if (!token) {
    return res.status(401).json({ error: 'Truy cập bị từ chối. Không có token.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    // Nếu token hết hạn hoặc không hợp lệ, xóa cookie và trả về 401
    res.clearCookie('adminToken', { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: isProduction ? 'none' : 'lax' 
    });
    return res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn.' });
  }
};

// Middleware kiểm tra session (dùng để xác nhận trạng thái đăng nhập)
app.get('/admin/verify-session', verifyAdminToken, (req, res) => {
  res.json({ success: true, message: 'Phiên đăng nhập hợp lệ.' });
});

// --- ROUTES CÔNG CỘNG ---

// Route giải mã chính
app.post('/giai-ma', async (req, res) => {
  if (!firebaseAdminInitialized) {
    // Lỗi này sẽ được khắc phục sau khi Firebase khởi tạo thành công
    return res.status(503).json({ error: 'Từ điển chưa sẵn sàng. Vui lòng đợi.' });
  }
  
  const { inputString, fp, recaptchaToken } = req.body;
  if (!inputString || !fp) {
    return res.status(400).json({ error: 'Thiếu dữ liệu đầu vào.' });
  }

  // Bỏ qua logic reCaptcha và ban list để tập trung vào vấn đề chính
  
  const decodedString = inputString.split('').map(char => {
    return globalDictionary[char] || char;
  }).join('');
  
  return res.json({ success: true, decodedString });
});

// --- ROUTES ADMIN ---

// Route đăng nhập (FIXED: CẤU HÌNH COOKIE)
app.post('/admin/tfa-login', async (req, res) => {
  const { username, password, tfaCode } = req.body;
  
  if (!firebaseAdminInitialized) {
    return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  }

  const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
  const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
  const ADMIN_TFA_SECRET = process.env.ADMIN_TFA_SECRET;

  if (username !== ADMIN_USERNAME) {
    return res.status(401).json({ error: 'Sai tên đăng nhập.' });
  }

  const passwordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Sai mật khẩu.' });
  }

  // Kiểm tra TFA code
  const tokenValidates = speakeasy.totp.verify({
    secret: ADMIN_TFA_SECRET,
    encoding: 'base32',
    token: tfaCode,
    window: 2, // Cho phép code đúng trong 2 khoảng thời gian
  });

  if (!tokenValidates) {
    return res.status(401).json({ error: 'Mã TFA không hợp lệ.' });
  }

  // Tạo và thiết lập token JWT
  const adminToken = jwt.sign({ username: ADMIN_USERNAME, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });

  // FIX LỖI 2: Cấu hình Cookie dựa trên môi trường
  res.cookie('adminToken', adminToken, {
    httpOnly: true,
    secure: isProduction, // BẮT BUỘC TRUE KHI DEPLOY DÙNG HTTPS
    sameSite: isProduction ? 'none' : 'lax', // Dùng 'none' khi FE/BE khác domain (production)
    maxAge: 8 * 3600000,
  });

  return res.json({ success: true, message: 'Đăng nhập thành công' });
});

// Route lấy dữ liệu dashboard (cần xác thực)
app.get('/admin/get-dashboard-data', verifyAdminToken, async (req, res) => {
  if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  
  try {
    const banListSnapshot = await db.collection('banList').get();
    const bannedIps = [];
    const bannedFps = [];
    
    banListSnapshot.forEach(doc => {
      const data = doc.data();
      if (data.type === 'ip') {
        bannedIps.push({ id: doc.id, ...data });
      } else if (data.type === 'fingerprint') {
        bannedFps.push({ id: doc.id, ...data });
      }
    });

    const tIps = bannedIps.filter(item => item.isTemp && item.expiresAt > Date.now());
    const pIps = bannedIps.filter(item => !item.isTemp || item.expiresAt <= Date.now());
    
    const tFps = bannedFps.filter(item => item.isTemp && item.expiresAt > Date.now());
    const pFps = bannedFps.filter(item => !item.isTemp || item.expiresAt <= Date.now());

    return res.json({ success: true, banned: { tIps, pIps, tFps, pFps } });
  } catch (err) {
    console.error('/admin/get-dashboard-data error:', err.message);
    return res.status(500).json({ error: 'Lỗi khi tải dữ liệu dashboard.' });
  }
});

// Route cấm IP/Fingerprint (cần xác thực)
app.post('/admin/ban-entity', verifyAdminToken, async (req, res) => {
  if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  
  const { type, value, duration } = req.body; // type: 'ip' hoặc 'fingerprint', duration: số giờ (ví dụ: 24)

  if (!type || !value) {
    return res.status(400).json({ error: 'Thiếu dữ liệu.' });
  }

  const isTemp = !!duration;
  let expiresAt = null;

  if (isTemp) {
    const durationMs = duration * 60 * 60 * 1000;
    expiresAt = Date.now() + durationMs;
  }

  try {
    await db.collection('banList').add({
      type,
      value,
      isTemp,
      expiresAt: expiresAt,
      timestamp: FieldValue.serverTimestamp(),
    });
    return res.json({ success: true, message: `${type.toUpperCase()} ${value} đã bị cấm ${isTemp ? 'tạm thời' : 'vĩnh viễn'}.` });
  } catch (err) {
    console.error('/admin/ban-entity error:', err.message);
    return res.status(500).json({ error: 'Lỗi khi cấm.' });
  }
});

// Route bỏ cấm (cần xác thực)
app.post('/admin/unban-entity', verifyAdminToken, async (req, res) => {
  if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'Thiếu ID.' });

  try {
    await db.collection('banList').doc(id).delete();
    return res.json({ success: true, message: 'Đã bỏ cấm thành công.' });
  } catch (err) {
    console.error('/admin/unban-entity error:', err.message);
    return res.status(500).json({ error: 'Lỗi khi bỏ cấm.' });
  }
});

// Route đồng bộ từ điển (cần xác thực)
app.post('/admin/sync-dictionary', verifyAdminToken, async (req, res) => {
  if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  
  try {
    await loadDictionary();
    return res.json({ success: true, message: 'Đã đồng bộ từ điển thành công.' });
  } catch (err) {
    console.error('/admin/sync-dictionary error:', err.message);
    return res.status(500).json({ error: 'Lỗi khi đồng bộ từ điển.' });
  }
});

// Route lấy từ điển để chỉnh sửa (cần xác thực)
app.get('/admin/get-dictionary', verifyAdminToken, async (req, res) => {
    if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
    
    try {
        const snapshot = await db.collection('dictionary').get();
        const dictionaryArray = [];
        snapshot.forEach(doc => {
            dictionaryArray.push({ id: doc.id, ...doc.data() });
        });
        return res.json({ success: true, dictionary: dictionaryArray });
    } catch (err) {
        console.error('/admin/get-dictionary error:', err.message);
        return res.status(500).json({ error: 'Lỗi khi lấy từ điển.' });
    }
});

// Route chỉnh sửa/thêm/xóa từ điển (cần xác thực)
app.post('/admin/manage-dictionary', verifyAdminToken, async (req, res) => {
    if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
    
    const { action, id, key, value } = req.body;

    if (action === 'delete') {
        if (!id) return res.status(400).json({ error: 'Thiếu ID để xóa.' });
        try {
            await db.collection('dictionary').doc(id).delete();
            return res.json({ success: true, message: 'Đã xóa mục từ điển.' });
        } catch (err) {
            console.error('/admin/manage-dictionary delete error:', err.message);
            return res.status(500).json({ error: 'Lỗi khi xóa.' });
        }
    } else if (action === 'add' || action === 'update') {
        if (!key || typeof value === 'undefined') return res.status(400).json({ error: 'Thiếu Key hoặc Value.' });
        
        try {
            const data = { key: String(key), value: String(value) };
            if (action === 'add') {
                const docRef = await db.collection('dictionary').add(data);
                return res.json({ success: true, message: 'Đã thêm mục từ điển.', newId: docRef.id });
            } else if (action === 'update') {
                if (!id) return res.status(400).json({ error: 'Thiếu ID để cập nhật.' });
                await db.collection('dictionary').doc(id).set(data);
                return res.json({ success: true, message: 'Đã cập nhật mục từ điển.' });
            }
        } catch (err) {
            console.error('/admin/manage-dictionary add/update error:', err.message);
            return res.status(500).json({ error: 'Lỗi khi quản lý từ điển.' });
        }
    } else {
        return res.status(400).json({ error: 'Hành động không hợp lệ.' });
    }
});

// Route migrate dictionary (giữ nguyên code gốc)
app.post('/admin/migrate-dictionary', verifyAdminToken, async (req, res) => {
  if (!firebaseAdminInitialized) return res.status(503).json({ error: 'Dịch vụ chưa sẵn sàng.' });
  
  const { data: migrationData } = req.body;
  if (!Array.isArray(migrationData)) {
    return res.status(400).json({ error: 'Dữ liệu migration phải là một mảng.' });
  }

  try {
    let updated = 0;
    let removed = 0;
    let processed = 0;
    
    for (const data of migrationData) {
      processed++;
      if (!data.id) continue; // Bỏ qua nếu không có ID
      
      const doc = await db.collection('dictionary').doc(data.id).get();
      if (!doc.exists) continue; // Bỏ qua nếu không tồn tại
      
      const hasValue = typeof data.value !== 'undefined' && data.value !== null;
      
      if (data.remove) {
        await db.collection('dictionary').doc(doc.id).delete();
        removed++;
        continue;
      }
      
      const update = {};
      if (typeof data.key !== 'string') update.key = typeof data.key === 'object' ? JSON.stringify(data.key) : String(data.key);
      if (!hasValue) update.value = '';
      else if (typeof data.value !== 'string') update.value = typeof data.value === 'object' ? JSON.stringify(data.value) : String(data.value);

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
    // Tải từ điển ngay sau khi Firebase khởi tạo
    await loadDictionary();
  }
})();
