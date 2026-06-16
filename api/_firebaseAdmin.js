const admin = require('firebase-admin');

function normalizePrivateKey(value) {
  return value ? value.replace(/\\n/g, '\n') : value;
}

function credentialFromEnv() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    return admin.credential.cert(
      JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY),
    );
  }

  if (
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_CLIENT_EMAIL &&
    process.env.FIREBASE_PRIVATE_KEY
  ) {
    return admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY),
    });
  }

  return admin.credential.applicationDefault();
}

function getAdmin() {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: credentialFromEnv(),
      projectId: process.env.FIREBASE_PROJECT_ID,
    });
  }
  return admin;
}

module.exports = { getAdmin };
