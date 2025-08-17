// server.js
// --- 1. IMPORT CÁC THƯ VIỆN ---
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'; // Để tạo và xác minh token admin
import crypto from 'crypto'; // Cần cho crypto.randomBytes nếu JWT_SECRET không có trong ENV
import bcrypt from 'bcrypt'; // Thêm bcrypt để mã hóa mật khẩu

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
        'https://viet-8101.github.io/admin-dashboard-doraemon/',
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Middleware để phân tích body của request JSON

// Khởi tạo các biến global
let db;
let firebaseAdminInitialized = false;

// --- 3. KHỞI TẠO FIREBASE ADMIN SDK ---
const initializeFirebaseAdmin = async () => {
    try {
        const serviceAccountJson = process.env.FIREBASE_ADMIN_SERVICE_ACCOUNT;
        if (!serviceAccountJson) {
            console.error('FIREBASE_ADMIN_SERVICE_ACCOUNT môi trường biến không được thiết lập. Vui lòng thiết lập nó để kết nối tới Firebase Admin.');
            return;
        }

        const serviceAccount = JSON.parse(Buffer.from(serviceAccountJson, 'base64').toString('ascii'));
        if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
            firebaseAdminInitialized = true;
            db = getFirestore();
            console.log('Đã kết nối Firebase Admin SDK.');
        } else {
            firebaseAdminInitialized = true;
            db = getFirestore();
            console.log('Firebase Admin SDK đã được khởi tạo.');
        }
    } catch (error) {
        console.error('Lỗi khi khởi tạo Firebase Admin SDK:', error);
        firebaseAdminInitialized = false;
        // Ghi chú: `db` sẽ là `undefined` nếu khởi tạo thất bại.
    }
};

// --- 4. CÁC HÀM XỬ LÝ DATABASE ---
const ADMIN_COLLECTION = 'admin';
const ADMIN_DOC_ID = 'data';

const getAdminData = async () => {
    if (!firebaseAdminInitialized) {
        throw new Error('Firebase Admin không được khởi tạo.');
    }
    const docRef = db.collection(ADMIN_COLLECTION).doc(ADMIN_DOC_ID);
    const docSnap = await docRef.get();
    if (docSnap.exists) {
        return docSnap.data();
    } else {
        // Tạo tài liệu admin nếu không tồn tại
        const initialData = {
            banned_ips: {},
            banned_fingerprints: {},
            last_updated: FieldValue.serverTimestamp()
        };
        await docRef.set(initialData);
        return initialData;
    }
};

const updateAdminData = async (data) => {
    if (!firebaseAdminInitialized) {
        throw new Error('Firebase Admin không được khởi tạo.');
    }
    const docRef = db.collection(ADMIN_COLLECTION).doc(ADMIN_DOC_ID);
    await docRef.update({
        ...data,
        last_updated: FieldValue.serverTimestamp()
    });
};

// Middleware xác thực token admin
const authenticateAdminToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: 'Không có token.' });
    }

    try {
        // Đảm bảo JWT_SECRET được thiết lập
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            throw new Error('JWT_SECRET không được thiết lập.');
        }

        const user = jwt.verify(token, jwtSecret);
        req.user = user;
        next();
    } catch (error) {
        console.error('Lỗi xác thực token:', error);
        return res.status(403).json({ error: 'Token không hợp lệ.' });
    }
};

// --- 5. CÁC ROUTE API ---

// Route đăng nhập (bị thiếu trong mã ban đầu)
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    const adminUser = process.env.ADMIN_USER;
    const adminPassHash = process.env.ADMIN_PASS_HASH;

    if (!adminUser || !adminPassHash) {
        return res.status(500).json({ error: 'Cấu hình server không đầy đủ.' });
    }

    try {
        const isMatch = await bcrypt.compare(password, adminPassHash);
        
        if (username === adminUser && isMatch) {
            const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
            const token = jwt.sign({ username: adminUser }, jwtSecret, { expiresIn: '1h' });
            return res.json({ success: true, token });
        } else {
            return res.status(401).json({ error: 'Tên người dùng hoặc mật khẩu không đúng.' });
        }
    } catch (error) {
        console.error('Lỗi khi đăng nhập:', error);
        return res.status(500).json({ error: 'Đã có lỗi xảy ra ở phía máy chủ.' });
    }
});

// Route để lấy dữ liệu admin
app.get('/admin/data', authenticateAdminToken, async (req, res) => {
    try {
        const adminData = await getAdminData();
        res.json({ success: true, data: adminData });
    } catch (error) {
        console.error('Lỗi khi lấy dữ liệu admin:', error);
        res.status(500).json({ error: error.message });
    }
});

// Route để unban IP hoặc Fingerprint
app.post('/admin/unban', authenticateAdminToken, async (req, res) => {
    const { type, value } = req.body;
    let unbanned = false;
    let message = '';

    try {
        const adminData = await getAdminData();

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
            console.warn('Cảnh báo: Firebase Admin SDK không được khởi tạo. Các chức năng database sẽ không hoạt động.');
        }
    });
})();
