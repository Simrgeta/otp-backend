import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';
import crypto from 'crypto';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 min
const MAX_REQUESTS_PER_WINDOW = 5;

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // 🧹 Cleanup old rate limit entries
    const now = Date.now();
    for (const [key, value] of rateLimitMap.entries()) {
      if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.delete(key);
      }
    }

    // 🔑 Extract & verify token
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) {
      return res.status(401).json({ error: 'Missing token' });
    }

    const verifyResp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );

    const verifyData = await verifyResp.json();
    if (!verifyData.users || !verifyData.users[0]) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const uid = verifyData.users[0].localId;

    // 🚦 Rate limit check
    const userLimit = rateLimitMap.get(uid);
    if (userLimit && now - userLimit.startTime < RATE_LIMIT_WINDOW_MS) {
      if (userLimit.count >= MAX_REQUESTS_PER_WINDOW) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
      }
      userLimit.count++;
    } else {
      rateLimitMap.set(uid, { count: 1, startTime: now });
    }

    // 📩 Validate body
    const { email, username } = req.body;
    if (!email || !username) {
      return res.status(400).json({ error: 'Missing email or username' });
    }

    // 🔐 Generate secure OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // 🔑 Get Firestore access
    const auth = new GoogleAuth({
      credentials: JSON.parse(process.env.FIREBASE_CREDS),
      scopes: ['https://www.googleapis.com/auth/datastore'],
    });

    const client = await auth.getClient();
    const token = await client.getAccessToken();
    if (!token.token) {
      return res.status(500).json({ error: 'Failed to get Firestore access token' });
    }

    // 📝 Update Firestore document
    const encodedEmail = encodeURIComponent(email);
    const patchRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT_ID}/databases/(default)/documents/TempUser/${encodedEmail}?updateMask.fieldPaths=Code&updateMask.fieldPaths=is_paid&updateMask.fieldPaths=newOTP&updateMask.fieldPaths=timestamp`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fields: {
            Code: { stringValue: otp },
            is_paid: { booleanValue: true },
            newOTP: { booleanValue: true },
            timestamp: { timestampValue: new Date().toISOString() },
          },
        }),
      }
    );

    if (!patchRes.ok) {
      const errText = await patchRes.text();
      console.error('Firestore update failed:', errText);
      return res.status(500).json({ error: 'Failed to update Firestore' });
    }

    // 📧 Send email via Brevo
    const emailRes = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: 'Abebe Getachew OTP', email: 'awashsimrgeta123@gmail.com' },
        to: [{ email, name: username }],
        subject: 'Your OTP Code',
        htmlContent: `
          <html>
            <body style="color:#000; background-color:#fff; font-family:sans-serif;">
              <p>Hello <b>${username}</b>,</p>
              <p>We received a request to verify your email address (<b>${email}</b>).</p>
              <p>Your One-Time Password (OTP) is:</p>
              <h2 style="color:#007BFF; font-size:22px; font-weight:bold;">${otp}</h2>
              <p>Please enter this code within the next <b>5 minutes</b> to complete your verification.</p>
              <p>If you did not request this, please ignore this message or contact our support team immediately.</p>
              <p>Thank you for trusting us with your security!</p>
              <p>Best regards,<br>Simrgeta Awash, Author and CEO</p>
            </body>
          </html>
        `,
      }),
    });

    if (!emailRes.ok) {
      const errText = await emailRes.text();
      console.error('Email sending failed:', errText);
      return res.status(500).json({ error: 'Failed to send OTP email' });
    }

    return res.status(200).json({ status: 'OTP sent', email });
  } catch (err) {
    console.error('Error in OTP handler:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
