// api/confirmReset.js
import admin from 'firebase-admin';
import crypto from 'crypto';

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CREDS)),
  });
}

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;

function isRateLimited(uid) {
  const now = Date.now();
  const requests = rateLimitMap.get(uid) || [];
  const recentRequests = requests.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  recentRequests.push(now);
  rateLimitMap.set(uid, recentRequests);
  return recentRequests.length > MAX_REQUESTS_PER_WINDOW;
}

setInterval(() => {
  const now = Date.now();
  for (const [uid, timestamps] of rateLimitMap.entries()) {
    const active = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    if (active.length > 0) rateLimitMap.set(uid, active);
    else rateLimitMap.delete(uid);
  }
}, RATE_LIMIT_WINDOW_MS);

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST')
      return res.status(405).json({ error: 'Method Not Allowed' });

    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword || newPassword.length < 8)
      return res.status(400).json({ error: 'Invalid parameters' });

    // Find user doc
    const snapshot = await admin
      .firestore()
      .collection('User')
      .where('Email', '==', email)
      .limit(1)
      .get();

    if (snapshot.empty)
      return res.status(404).json({ error: 'User not found' });

    const doc = snapshot.docs[0];
    const data = doc.data();

    // Check OTP expiry
    if (!data.otpExpiresAt || data.otpExpiresAt.toMillis() < Date.now()) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    // Hash incoming OTP and compare
    const hashedInput = crypto.createHash('sha256').update(otp).digest('hex');
    if (hashedInput !== data.otpHash) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Get Firebase Auth user and update password
    const userRecord = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });

    // Revoke all sessions
    await admin.auth().revokeRefreshTokens(userRecord.uid);

    // Clear OTP fields
    await doc.ref.update({
      otpHash: admin.firestore.FieldValue.delete(),
      otpCreatedAt: admin.firestore.FieldValue.delete(),
      otpExpiresAt: admin.firestore.FieldValue.delete(),
      newOTP: false,
    });

    return res.status(200).json({ status: 'Password reset successful' });
  } catch (err) {
    console.error('confirmReset error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
