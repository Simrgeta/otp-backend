// api/requestReset.js
import admin from 'firebase-admin';
import crypto from 'crypto';

// Initialize Admin SDK once
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CREDS)),
  });
}

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 5;
const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

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

    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;
    if (!idToken) return res.status(401).json({ error: 'Missing token' });

    const decoded = await admin.auth().verifyIdToken(idToken).catch(() => null);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });
    const uid = decoded.uid;

    if (isRateLimited(uid))
      return res.status(429).json({ error: 'Too many requests' });

    const { email } = req.body;
    if (
      !email ||
      typeof email !== 'string' ||
      !email.includes('@')
    )
      return res.status(400).json({ error: 'Invalid email' });

    // Look up user document
    const snapshot = await admin
      .firestore()
      .collection('User')
      .where('Email', '==', email)
      .limit(1)
      .get();

    if (snapshot.empty)
      return res.status(404).json({ error: 'User not found' });

    const docRef = snapshot.docs[0].ref;
    const username = snapshot.docs[0].data().Username || '';

    // Generate OTP & hash it
    const otp = crypto.randomInt(100000, 999999).toString();
    const hashedOtp = crypto
      .createHash('sha256')
      .update(otp)
      .digest('hex');

    // Store hashed OTP with expiry
    await docRef.update({
      otpHash: hashedOtp,
      otpCreatedAt: admin.firestore.Timestamp.now(),
      otpExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + OTP_EXPIRY_MS),
      newOTP: true,
    });

    // Send email via Brevo
    const emailHtml = `
      <html>
        <body style="font-family:sans-serif;color:#111">
          <p>Hello ${username ? `<b>${username}</b>` : ''},</p>
          <p>Your One-Time Password (OTP) is:</p>
          <h2 style="color:#007BFF">${otp}</h2>
          <p>This code is valid for ${OTP_EXPIRY_MS / 60000} minutes. If you didn't request it, ignore this message.</p>
        </body>
      </html>
    `;

    const mailResp = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: 'Abebe Getachew OTP', email: 'awashsimrgeta123@gmail.com' },
        to: [{ email, name: username }],
        subject: 'Your OTP Code',
        htmlContent: emailHtml,
      }),
    });

    if (!mailResp.ok) {
      const t = await mailResp.text();
      console.error('Mail error', mailResp.status, t);
      return res.status(500).json({ error: 'Failed to send email' });
    }

    return res.status(200).json({ status: 'OTP sent', email });
  } catch (err) {
    console.error('requestReset error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
