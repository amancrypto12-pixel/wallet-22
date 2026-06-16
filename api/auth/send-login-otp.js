const { getAdmin } = require('../_firebaseAdmin');
const {
  OTP_TTL_MS,
  RESEND_COOLDOWN_MS,
  generateOtp,
  hashOtp,
  json,
  normalizeEmail,
  otpDocId,
  rejectNonPost,
} = require('../_otp');

const REQUIRED_ENV_VARS = [
  'FIREBASE_SERVICE_ACCOUNT_KEY',
  'OTP_HASH_SECRET',
  'RESEND_API_KEY',
  'OTP_FROM_EMAIL',
];

class EmailProviderError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EmailProviderError';
  }
}

function missingRequiredEnvVars() {
  return REQUIRED_ENV_VARS.filter((key) => !process.env[key]);
}

async function sendEmail(email, code) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.OTP_FROM_EMAIL,
      to: email,
      subject: 'DPN Network Login Verification',
      text: `Your DPN Network login code is: ${code}`,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new EmailProviderError(`Resend failed: ${body}`);
  }
}

module.exports = async function handler(req, res) {
  if (rejectNonPost(req, res)) {
    return;
  }

  try {
    const missingEnv = missingRequiredEnvVars();
    if (missingEnv.length > 0) {
      console.error('send-login-otp config missing', {
        missingEnv,
      });
      json(res, 500, { error: 'OTP service not configured.' });
      return;
    }

    const admin = getAdmin();
    const email = normalizeEmail(req.body && req.body.email);
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : '';

    if (!email || !idToken) {
      json(res, 400, { error: 'Email and login token are required.' });
      return;
    }

    const decoded = await admin.auth().verifyIdToken(idToken);
    if (normalizeEmail(decoded.email) !== email) {
      json(res, 403, { error: 'Login token does not match this email.' });
      return;
    }

    const db = admin.firestore();
    const ref = db.collection('login_otps').doc(otpDocId(email));
    const existing = await ref.get();
    const now = Date.now();
    const existingData = existing.exists ? existing.data() : null;
    const resendAfter = existingData && existingData.resendAfter;

    if (resendAfter && resendAfter.toMillis() > now) {
      json(res, 429, { error: 'Please wait before requesting a new code.' });
      return;
    }

    const code = generateOtp();
    await sendEmail(email, code);

    await ref.set({
      email,
      otpHash: hashOtp(email, code),
      expiresAt: admin.firestore.Timestamp.fromMillis(now + OTP_TTL_MS),
      resendAfter: admin.firestore.Timestamp.fromMillis(
        now + RESEND_COOLDOWN_MS,
      ),
      attempts: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    json(res, 200, { ok: true });
  } catch (error) {
    console.error('send-login-otp failed', {
      name: error && error.name,
      message: error && error.message,
      stack: error && error.stack,
    });
    if (error instanceof EmailProviderError) {
      json(res, 502, { error: 'Email provider failed.' });
      return;
    }
    json(res, 500, { error: 'OTP service not configured.' });
  }
};
