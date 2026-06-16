const REQUIRED_ENV_VARS = [
  'FIREBASE_SERVICE_ACCOUNT_KEY',
  'OTP_HASH_SECRET',
  'RESEND_API_KEY',
  'OTP_FROM_EMAIL',
];

module.exports = function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const status = Object.fromEntries(
    REQUIRED_ENV_VARS.map((key) => [key, Boolean(process.env[key])]),
  );
  const missing = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

  res.status(200).json({
    ok: missing.length === 0,
    service: 'DPN Network OTP',
    status,
    missing,
    message:
      missing.length === 0
        ? 'OTP service configured.'
        : 'OTP service not configured.',
  });
};
