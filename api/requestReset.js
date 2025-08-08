import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';
import crypto from 'crypto';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
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
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Missing token' });

    // Verify token
    const verifyResp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) }
    );
    const verifyData = await verifyResp.json();
    if (!verifyData.users || !verifyData.users[0]) return res.status(401).json({ error: 'Invalid token' });
    const uid = verifyData.users[0].localId;

    if (isRateLimited(uid)) return res.status(429).json({ error: 'Too many requests. Try later.' });

    const { email } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });

    // generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // GoogleAuth for Firestore REST
    const auth = new GoogleAuth({
      credentials: JSON.parse(process.env.FIREBASE_CREDS),
      scopes: ['https://www.googleapis.com/auth/datastore'],
    });
    const client = await auth.getClient();
    const token = await client.getAccessToken();
    if (!token.token) return res.status(500).json({ error: 'Failed to get Firestore access token' });

    // Query User collection by Email
    const queryURL = `https://firestore.googleapis.com/v1/projects/${process.env.YOUR_PROJECT_ID}/databases/(default)/documents:runQuery`;
    const queryBody = {
      structuredQuery: {
        from: [{ collectionId: 'User' }],
        where: {
          fieldFilter: {
            field: { fieldPath: 'Email' },
            op: 'EQUAL',
            value: { stringValue: email },
          },
        },
        limit: 1,
      },
    };

    const queryRes = await fetch(queryURL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(queryBody),
    });
    const queryJson = await queryRes.json();

    if (!Array.isArray(queryJson) || !queryJson[0]?.document) {
      return res.status(404).json({ error: 'User not found with that email' });
    }

    const doc = queryJson[0].document;
    const docName = doc.name; // full resource name: projects/.../documents/User/{docId}
    const username = doc.fields?.Username?.stringValue || '';

    // Patch document: Code, newOTP, timestamp
    const patchURL = `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=Code&updateMask.fieldPaths=newOTP&updateMask.fieldPaths=timestamp`;
    const patchBody = {
      fields: {
        Code: { stringValue: otp },
        newOTP: { booleanValue: true },
        timestamp: { timestampValue: new Date().toISOString() },
      },
    };

    const patchRes = await fetch(patchURL, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(patchBody),
    });

    if (!patchRes.ok) {
      const errText = await patchRes.text();
      console.error('Patch failed:', patchRes.status, errText);
      return res.status(500).json({ error: 'Failed to write OTP' });
    }

    // Build deep link for in-app handling (if desired)
    const deepLinkBase = process.env.FRONTEND_DEEP_LINK_SCHEME || '';
    const deepLink = deepLinkBase ? `${deepLinkBase}?oobCode=${encodeURIComponent(otp)}&mode=otp` : null;
    // NOTE: We're sending OTP (numeric) via email and storing it in DB. 
    // If you prefer oobCode flow, use admin.generatePasswordResetLink instead.

    // Send Email via Brevo
    const emailHtml = `
      <html>
        <body style="font-family:sans-serif;color:#111">
          <p>Hello ${username ? `<b>${username}</b>` : ''},</p>
          <p>Your One-Time Password (OTP) is:</p>
          <h2 style="color:#007BFF">${otp}</h2>
          <p>This code is valid for a short time. If you didn't request it, ignore this message.</p>
        </body>
      </html>
    `;

    const mailResp = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' },
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
