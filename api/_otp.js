const crypto = require('crypto');

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 3;

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function otpDocId(email) {
  return crypto.createHash('sha256').update(normalizeEmail(email)).digest('hex');
}

function otpSecret() {
  const secret =
    process.env.OTP_HASH_SECRET ||
    process.env.FIREBASE_PRIVATE_KEY ||
    process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (!secret) {
    throw new Error('OTP_HASH_SECRET is not configured.');
  }
  return secret;
}

function hashOtp(email, code) {
  return crypto
    .createHmac('sha256', otpSecret())
    .update(`${normalizeEmail(email)}:${String(code).trim()}`)
    .digest('hex');
}

function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function json(res, status, body) {
  res.status(status).json(body);
}

function rejectNonPost(req, res) {
  if (req.method === 'POST') {
    return false;
  }
  res.setHeader('Allow', 'POST');
  json(res, 405, { error: 'Method not allowed' });
  return true;
}

module.exports = {
  MAX_ATTEMPTS,
  OTP_TTL_MS,
  RESEND_COOLDOWN_MS,
  generateOtp,
  hashOtp,
  json,
  normalizeEmail,
  otpDocId,
  rejectNonPost,
};
