// server.js
// Minimal safe server — start ngay, init Firebase bất đồng bộ, lỗi được bắt tránh crash
import express from 'express';
import dotenv from 'dotenv';
import admin from 'firebase-admin';
import { getFirestore } from 'firebase-admin/firestore';

dotenv.config();

console.log('STARTUP: server.js running');
console.log('STARTUP: Node version =', process.version);
console.log('STARTUP: PORT =', process.env.PORT || '<none>');
console.log('STARTUP: JWT_SECRET present =', !!process.env.JWT_SECRET);
console.log('STARTUP: FIREBASE_SERVICE_ACCOUNT_KEY present =', !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY);

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;

let db = null;
let firebaseReady = false;

// Non-blocking Firebase init with safe JSON.parse and catch-all errors
async function initializeFirebase() {
  if (admin.apps.length > 0) {
    try {
      db = getFirestore();
      firebaseReady = true;
      console.log('[Firebase] already initialized (reused).');
      return;
    } catch (e) {
      console.error('[Firebase] reuse error:', e);
    }
  }

  const keyStr = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (!keyStr) {
    console.warn('[Firebase] FIREBASE_SERVICE_ACCOUNT_KEY not set — skipping Firebase init.');
    return;
  }

  try {
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(keyStr);
    } catch (parseErr) {
      console.error('[Firebase] FIREBASE_SERVICE_ACCOUNT_KEY JSON.parse error:', parseErr);
      return;
    }

    try {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      db = getFirestore();
      firebaseReady = true;
      console.log('[Firebase] initialized and ready.');
    } catch (initErr) {
      console.error('[Firebase] initializeApp error:', initErr);
    }
  } catch (err) {
    console.error('[Firebase] unexpected error during init:', err);
  }
}

// Start initialization in background but DO NOT await — server will start immediately
initializeFirebase().catch(e => console.error('[Firebase] init promise rejected:', e));

// Simple health endpoint
app.get('/health', (req, res) => {
  res.json({ ok: true, firebaseReady, dictCount: Array.isArray(app.locals.dictionary) ? app.locals.dictionary.length : 0 });
});

// Minimal /giai-ma endpoint that returns helpful messages and avoids heavy regex
app.post('/giai-ma', async (req, res) => {
  if (!firebaseReady) return res.status(503).json({ error: 'Service chưa sẵn sàng (Firestore chưa kết nối).' });
  const { userInput } = req.body;
  if (!userInput) return res.status(400).json({ error: 'Thiếu userInput' });

  try {
    const dict = app.locals.dictionary || [];
    let text = String(userInput);
    let replaced = false;
    // simple exact replacement (case-insensitive)
    for (const e of dict) {
      try {
        const key = String(e.key);
        const value = String(e.value);
        const re = new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        const newText = text.replace(re, value);
        if (newText !== text) {
          text = newText;
          replaced = true;
        }
      } catch (err) {
        // skip bad entry
        console.warn('[giai-ma] skip entry due to regex error', e && e.id, err && err.message);
      }
    }
    return res.json({ success: true, ketQua: replaced ? text : 'Không tìm thấy từ khóa phù hợp.' });
  } catch (err) {
    console.error('[giai-ma] unexpected error:', err);
    return res.status(500).json({ error: 'Lỗi máy chủ.' });
  }
});

// Load dictionary from Firestore with safe guards and update app.locals.dictionary
function listenDictionary() {
  if (!firebaseReady || !db) {
    console.warn('[Cache] Firestore chưa sẵn sàng, không thể listen dictionary.');
    return;
  }
  try {
    const col = db.collection('dictionary');
    const unsubscribe = col.onSnapshot(snapshot => {
      const arr = [];
      snapshot.forEach(doc => {
        const d = doc.data() || {};
        if (d.key && d.value) arr.push({ id: doc.id, key: d.key, value: d.value });
      });
      // sort by length desc (optional)
      arr.sort((a, b) => (b.key ? b.key.length : 0) - (a.key ? a.key.length : 0));
      app.locals.dictionary = arr;
      console.log(`[Cache] loaded dictionary. items=${arr.length}`);
    }, err => {
      console.error('[Cache] onSnapshot error:', err);
    });
    // store unsubscribe if needed later
    app.locals._dictUnsubscribe = unsubscribe;
  } catch (err) {
    console.error('[Cache] listenDictionary error:', err);
  }
}

// When firebase becomes ready, start listening
// We poll a few times to detect firebaseReady since init runs in background
const maxChecks = 10;
let checkCount = 0;
const checkInterval = setInterval(() => {
  checkCount++;
  if (firebaseReady && db) {
    console.log('[Startup] Firebase ready — starting dictionary listener.');
    listenDictionary();
    clearInterval(checkInterval);
  } else {
    console.log(`[Startup] waiting for Firebase... attempt ${checkCount}/${maxChecks}`);
    if (checkCount >= maxChecks) {
      console.warn('[Startup] Firebase not ready after checks — continuing without dictionary listener.');
      clearInterval(checkInterval);
    }
  }
}, 800);

// Global error handlers to avoid crashes
process.on('uncaughtException', err => {
  console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', reason => {
  console.error('UNHANDLED REJECTION:', reason);
});

// Start server immediately
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on ${PORT} (started immediately, Firebase init runs in background)`);
});
