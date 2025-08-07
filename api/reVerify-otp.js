import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';
import crypto from 'crypto';

const HMAC_SECRET = process.env.HMAC_SECRET;
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;
const FIREBASE_PROJECT_ID = process.env.YOUR_PROJECT_ID;

const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_REQUESTS_PER_WINDOW = 5;
const rateLimitMap = new Map();

// 🔐 Signature check (only deviceId)
function verifyHmac(deviceId, signature) {
  const hmac = crypto.createHmac('sha256', HMAC_SECRET);
  hmac.update(deviceId);
  const digest = hmac.digest('hex');
  return digest === signature;
}

function cleanRateLimits() {
  const now = Date.now();
  for (const [key, value] of rateLimitMap.entries()) {
    if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(key);
    }
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!idToken) return res.status(401).json({ error: 'Missing token' });

  // 🔐 Verify Firebase ID token
  const verifyResp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_WEB_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken }),
  });

  const verifyData = await verifyResp.json();
  const firebaseUser = verifyData.users?.[0];
  if (!firebaseUser) {
    return res.status(401).json({ error: 'Invalid Firebase ID token' });
  }

  const uid = firebaseUser.localId;

  // 📥 Extract request fields
  const { email, enteredOtp, deviceId, signature, timestamp } = req.body || {};
  
  if (!email || !enteredOtp || !deviceId || !signature || !timestamp) {
    return res.status(400).json({ error: 'Missing required fields' });
  }


  // 🕓 Timestamp replay protection (rate-limit related)
  const now = Date.now();
  if (Math.abs(now - timestamp) > RATE_LIMIT_WINDOW_MS) {
    return res.status(400).json({ error: 'Timestamp expired or too far in the future' });
  }

  // 🔐 Verify signature (based only on deviceId)
  if (!verifyHmac(deviceId, signature)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }

  // 🚫 Rate limiting
  cleanRateLimits();
  const userRate = rateLimitMap.get(uid);
  if (userRate && now - userRate.startTime < RATE_LIMIT_WINDOW_MS) {
    if (userRate.count >= MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    userRate.count++;
  } else {
    rateLimitMap.set(uid, { count: 1, startTime: now });
  }

  // 🔑 Firestore access token
  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_CREDS),
    scopes: ['https://www.googleapis.com/auth/datastore'],
  });

  const client = await auth.getClient();
  const tokenResponse = await client.getAccessToken();
  const firestoreToken = tokenResponse.token;

  // 🔍 Query user by email
  const queryRes = await fetch(`https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${firestoreToken}`,
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
  });

  const queryJson = await queryRes.json();
  const document = queryJson[0]?.document;
  if (!document) {
    return res.status(404).json({ error: 'User not found' });
  }

  const storedOtp = document.fields?.Code?.stringValue;
  const docName = document.name;

  // 🔢 OTP validation
  if (enteredOtp !== storedOtp) {
    return res.status(403).json({ error: 'Incorrect OTP' });
  }

  // 📦 Update deviceId and signature in Firestore
  await fetch(`https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=deviceId&updateMask.fieldPaths=signature`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${firestoreToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        deviceId: { stringValue: deviceId },
        signature: { stringValue: signature },
      },
    }),
  });

  return res.status(200).json({ success: true, message: 'OTP verified and device info updated' });
}
