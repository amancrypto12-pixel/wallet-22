const { getAdmin } = require('../_firebaseAdmin');
const {
  MAX_ATTEMPTS,
  hashOtp,
  json,
  normalizeEmail,
  otpDocId,
  rejectNonPost,
} = require('../_otp');

module.exports = async function handler(req, res) {
  if (rejectNonPost(req, res)) {
    return;
  }

  try {
    const admin = getAdmin();
    const email = normalizeEmail(req.body && req.body.email);
    const code = String((req.body && req.body.code) || '').trim();

    if (!email || !/^\d{6}$/.test(code)) {
      json(res, 400, { error: 'Invalid code' });
      return;
    }

    const db = admin.firestore();
    const ref = db.collection('login_otps').doc(otpDocId(email));
    const snapshot = await ref.get();
    if (!snapshot.exists) {
      json(res, 401, { error: 'Invalid code' });
      return;
    }

    const data = snapshot.data();
    const now = Date.now();
    if (!data.expiresAt || data.expiresAt.toMillis() <= now) {
      await ref.delete();
      json(res, 410, { error: 'Code expired' });
      return;
    }

    const attempts = Number(data.attempts || 0);
    if (attempts >= MAX_ATTEMPTS) {
      json(res, 429, { error: 'Too many attempts' });
      return;
    }

    if (data.otpHash !== hashOtp(email, code)) {
      const nextAttempts = attempts + 1;
      await ref.update({
        attempts: nextAttempts,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      json(res, nextAttempts >= MAX_ATTEMPTS ? 429 : 401, {
        error: nextAttempts >= MAX_ATTEMPTS ? 'Too many attempts' : 'Invalid code',
      });
      return;
    }

    await ref.delete();
    json(res, 200, { ok: true });
  } catch (error) {
    console.error('verify-login-otp failed', error);
    json(res, 500, { error: 'Unable to verify login code.' });
  }
};
