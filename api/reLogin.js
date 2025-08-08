import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';
import crypto from 'crypto';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 5;

function isRateLimited(uid) {
  const now = Date.now();
  const requests = rateLimitMap.get(uid) || [];

  // Remove old requests
  const recentRequests = requests.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  recentRequests.push(now);

  rateLimitMap.set(uid, recentRequests);

  return recentRequests.length > MAX_REQUESTS_PER_WINDOW;
}

// Periodic cleanup to avoid memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [uid, timestamps] of rateLimitMap.entries()) {
    const active = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    if (active.length > 0) {
      rateLimitMap.set(uid, active);
    } else {
      rateLimitMap.delete(uid);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) {
      return res.status(401).json({ error: 'Missing token' });
    }

    // Verify Firebase ID token
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

    // Check rate limit
    if (isRateLimited(uid)) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }

    const { email } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Invalid or missing email' });
    }

    // Secure OTP generation
    const otp = crypto.randomInt(100000, 999999).toString();

    // Authenticate with Google
    const auth = new GoogleAuth({
      credentials: JSON.parse(process.env.FIREBASE_CREDS),
      scopes: ['https://www.googleapis.com/auth/datastore'],
    });

    const client = await auth.getClient();
    const token = await client.getAccessToken();
    if (!token.token) {
      return res.status(500).json({ error: 'Failed to get Firestore access token' });
    }

    // Step 1: Query document by email
    const queryRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${process.env.YOUR_PROJECT_ID}/databases/(default)/documents:runQuery`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
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
        }),
      }
    );

    const queryJson = await queryRes.json();
    if (!queryJson[0] || !queryJson[0].document) {
      return res.status(404).json({ error: 'User not found with that email' });
    }

    const doc = queryJson[0].document;
    const docName = doc.name;
    const username = doc.fields.Username?.stringValue || 'User';

    // Step 2: Patch document
    await fetch(
      `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=Code&updateMask.fieldPaths=newOTP&updateMask.fieldPaths=timestamp`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fields: {
            Code: { stringValue: otp },
            newOTP: { booleanValue: true },
            timestamp: { timestampValue: new Date().toISOString() },
          },
        }),
      }
    );

    // Step 3: Send Email
    await fetch('https://api.brevo.com/v3/smtp/email', {
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

    return res.status(200).json({ status: 'OTP sent', email });
  } catch (err) {
    console.error('Error sending OTP:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
