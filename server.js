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

// --- HÀM KHỞI TẠO FIREBASE ADMIN SDK (FIXED) ---
async function initializeFirebaseWithRetries(retries = 5, delay = 5000) {
    if (firebaseAdminInitialized) return true;

    // Lấy biến môi trường. Đảm bảo tên biến này khớp với tên bạn đặt trên Render/Deploy.
    const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;

    if (!serviceAccountKey) {
        console.error('LỖI CẤU HÌNH: Thiếu biến môi trường FIREBASE_SERVICE_ACCOUNT_KEY.');
        return false;
    }

    for (let i = 0; i < retries; i++) {
        try {
            // FIX LỖI 1: Xử lý ký tự xuống dòng (\n) và khoảng trắng thừa, giúp parse JSON ổn định
            const cleanedKey = serviceAccountKey.replace(/\\n/g, '\n').trim();
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

// Route đăng nhập (ĐÃ FIX LỖI 2: CẤU HÌNH COOKIE)
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

// ... (Các route /admin/get-dashboard-data, /admin/ban-ip, v.v. giữ nguyên) ...

// --- BOOTSTRAP ---\r\n
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
