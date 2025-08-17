// server.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import crypto from 'crypto'; // Thêm import này

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
        'http://localhost:5173'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// --- 3. BIẾN MÔI TRƯỜNG ---
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// --- 4. KHỞI TẠO VÀ KẾT NỐI VỚI FIREBASE ---
let db;
let firebaseAdminInitialized = false;

async function initializeFirebaseAdmin() {
    try {
        const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT;
        if (!serviceAccountString) {
            throw new Error('Biến môi trường FIREBASE_SERVICE_ACCOUNT không tồn tại.');
        }

        const serviceAccount = JSON.parse(serviceAccountString);

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

// --- 5. MIDDLEWARE XÁC THỰC TOKEN ---
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.warn('Truy cập bị từ chối: Không tìm thấy token.');
        return res.status(401).json({ error: 'Truy cập bị từ chối. Token không được cung cấp.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.warn('Truy cập bị từ chối: Token không hợp lệ.', err);
            return res.status(403).json({ error: 'Token không hợp lệ.' });
        }
        req.user = user;
        next();
    });
};

// --- 6. API ROUTES ---

// Endpoint bước 1: Đăng nhập và tạo mã 2FA
app.post('/admin/login-step1', async (req, res) => {
    const { username, password } = req.body;

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
    }

    if (!db) {
        return res.status(503).json({ error: 'Cơ sở dữ liệu chưa sẵn sàng.' });
    }

    try {
        const otpCode = crypto.randomBytes(6).toString('hex');
        const sessionRef = db.collection('login_sessions').doc(username);

        await sessionRef.set({
            code: otpCode,
            expires: Date.now() + 300000,
            createdAt: FieldValue.serverTimestamp()
        });

        console.log(`[LOGIN 2FA] Mã xác minh cho ${username} là: ${otpCode}`);

        res.json({ success: true, message: 'Vui lòng nhập mã xác minh từ server log.' });

    } catch (error) {
        console.error('Lỗi khi khởi tạo phiên xác minh:', error);
        res.status(500).json({ error: 'Lỗi server khi khởi tạo xác minh 2 bước.' });
    }
});

// Endpoint bước 2: Xác minh mã 2FA và hoàn tất đăng nhập
app.post('/admin/login-step2', async (req, res) => {
    const { username, otpCode } = req.body;

    if (!db) {
        return res.status(503).json({ error: 'Cơ sở dữ liệu chưa sẵn sàng.' });
    }

    try {
        const sessionRef = db.collection('login_sessions').doc(username);
        const sessionSnap = await sessionRef.get();

        if (!sessionSnap.exists) {
            return res.status(401).json({ error: 'Mã xác minh không hợp lệ hoặc đã hết hạn.' });
        }

        const storedSession = sessionSnap.data();
        const now = Date.now();

        if (storedSession.code === otpCode && storedSession.expires > now) {
            const token = jwt.sign({ username: ADMIN_USERNAME, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
            await sessionRef.delete();
            return res.json({ success: true, token });
        } else {
            return res.status(401).json({ error: 'Mã xác minh không hợp lệ hoặc đã hết hạn.' });
        }

    } catch (error) {
        console.error('Lỗi khi xác minh mã OTP:', error);
        return res.status(500).json({ error: 'Lỗi server khi xác minh mã.' });
    }
});

// Các endpoint API khác (bạn giữ lại các endpoint ban, unban, get-banned-ips, get-banned-fingerprints...)
// ...

app.get('/admin/banned-ips', authenticateAdmin, async (req, res) => {
    try {
        const adminData = await getAdminData();
        res.json(adminData.banned_ips || {});
    } catch (error) {
        console.error('Lỗi khi lấy danh sách IP bị cấm:', error);
        res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});

// ... (các endpoint khác)

// Khởi động server
(async () => {
    await initializeFirebaseAdmin();

    app.listen(PORT, () => {
        console.log(`Server Backend Doraemon đang chạy tại cổng ${PORT}`);
        if (!firebaseAdminInitialized) {
            console.error('Cảnh báo: Firebase Admin SDK không được khởi tạo thành công. Các chức năng phụ thuộc vào database sẽ không hoạt động.');
        }
    });
})();

// Hàm trợ giúp để lấy và cập nhật dữ liệu admin
async function getAdminData() {
    if (!db) return { banned_ips: {}, banned_fingerprints: {} };
    const docRef = db.collection('admin').doc('data');
    const doc = await docRef.get();
    return doc.exists ? doc.data() : { banned_ips: {}, banned_fingerprints: {} };
}

async function updateAdminData(data) {
    if (!db) return;
    const docRef = db.collection('admin').doc('data');
    await docRef.set(data);
}
