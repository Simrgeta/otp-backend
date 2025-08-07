import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  // Rate limiter cleanup
  const cleanRateLimits = () => {
    const now = Date.now();
    for (const [key, value] of rateLimitMap.entries()) {
      if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.delete(key);
      }
    }
  };

  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!idToken) return res.status(401).json({ error: 'Missing token' });

  const verifyResp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });

  const verifyData = await verifyResp.json();
  if (!verifyData.users || !verifyData.users[0]) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const uid = verifyData.users[0].localId;

  cleanRateLimits();
  const now = Date.now();
  const userLimit = rateLimitMap.get(uid);
  if (userLimit && now - userLimit.startTime < RATE_LIMIT_WINDOW_MS) {
    if (userLimit.count >= MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    userLimit.count++;
  } else {
    rateLimitMap.set(uid, { count: 1, startTime: now });
  }

  const { email, username } = req.body;
  if (!email || !username) {
    return res.status(400).json({ error: 'Missing email or username' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_CREDS),
    scopes: ['https://www.googleapis.com/auth/datastore']
  });

  const client = await auth.getClient();
  const token = await client.getAccessToken();

  await fetch(`https://firestore.googleapis.com/v1/projects/abebe-15ab9/databases/(default)/documents/TempUser/${encodeURIComponent(email)}?updateMask.fieldPaths=Code&updateMask.fieldPaths=is_paid&updateMask.fieldPaths=newOTP&updateMask.fieldPaths=timestamp`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      fields: {
        Code: { stringValue: otp },
        is_paid: { booleanValue: true },
        newOTP: { booleanValue: true },
        timestamp: { timestampValue: new Date().toISOString() }
      }
    })
  });

  await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'Abebe Getachew OTP', email: 'awashsimrgeta123@gmail.com' },
      to: [{ email, name: username }],
      subject: 'Your OTP Code',
      htmlContent: `
        <html>
  <head>
    <style>
      body {
        color: #000;
        background-color: #fff;
        color-scheme: light dark;
      }
      @media (prefers-color-scheme: dark) {
        body {
          color: #fff;
          background-color: #000;
        }
      }
    </style>
  </head>
  <body>
    <p>Hello <b>${username}</b>,</p>
    <p>We received a request to verify your email address (<b>${email}</b>).</p>
    <p>Your One-Time Password (OTP) is:</p>
    <h2 style='color:#007BFF;'>${otp}</h2>
    <p>Please enter this code within the next <b>5 minutes</b> to complete your verification.</p>
    <p>If you did not request this, please ignore this message or contact our support team immediately.</p>
    <p>Thank you for trusting us with your security!</p>
    <p>Best regards,<br>Simrgeta Awash, Author and CEO</p>
  </body>
</html>
        
      `
    })
  });

  return res.status(200).json({ status: 'OTP sent', email, otp });
}
