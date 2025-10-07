// debug_start.js
// Minimal debug server: in báo trạng thái env (presence) và start nhanh,
// dùng để kiểm tra lý do deploy timeout (crash/exit trước khi listen).

import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

function envStatus(name) {
  const v = process.env[name];
  return { present: !!v, length: v ? String(v).length : 0 };
}

console.log('=== DEBUG STARTUP ===');
console.log('Node version:', process.version);
console.log('JWT_SECRET:', envStatus('JWT_SECRET'));
console.log('RECAPTCHA_SECRET_KEY:', envStatus('RECAPTCHA_SECRET_KEY'));
console.log('FIREBASE_SERVICE_ACCOUNT_KEY present:', !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
console.log('ADMIN_USERNAME_HASH present:', !!process.env.ADMIN_USERNAME_HASH);
console.log('ADMIN_PASSWORD_HASH present:', !!process.env.ADMIN_PASSWORD_HASH);
console.log('--- env variables listed (values hidden) ---');

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});

app.get('/', (req, res) => res.send('Debug minimal server OK'));
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    jwtSecret: !!process.env.JWT_SECRET,
    recaptcha: !!process.env.RECAPTCHA_SECRET_KEY,
    firebaseKey: !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
    timestamp: Date.now()
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Debug minimal server listening on ${PORT}`);
});
