import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';
import crypto from 'crypto';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  // ✅ Step 1: Authorization header check
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!idToken) return res.status(401).json({ allow: false, message: 'Missing token' });

  // ✅ Step 2: Verify Firebase ID token
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
    return res.status(401).json({ allow: false, message: 'Invalid token' });
  }

  const uid = verifyData.users[0].localId;

  // ✅ Step 3: Rate limiting
  const now = Date.now();
  for (const [key, info] of rateLimitMap.entries()) {
    if (now - info.startTime > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(key);
  }
  const userInfo = rateLimitMap.get(uid);
  if (userInfo && now - userInfo.startTime < RATE_LIMIT_WINDOW_MS) {
    if (userInfo.count >= MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({ allow: false, message: 'Rate limit exceeded' });
    }
    userInfo.count++;
  } else {
    rateLimitMap.set(uid, { count: 1, startTime: now });
  }

  // ✅ Step 4: Validate body fields
  const { email, deviceId, signature } = req.body;
  if (!email || !deviceId || !signature) {
    return res.status(400).json({ allow: false, message: 'Missing required fields' });
  }

  // ✅ Step 5: Setup Firestore access
  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_CREDS),
    scopes: ['https://www.googleapis.com/auth/datastore'],
  });
  const client = await auth.getClient();
  const token = await client.getAccessToken();

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

  const firestoreResp = await fetch(queryURL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token.token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(queryBody),
  });

  const queryResult = await firestoreResp.json();

  if (!Array.isArray(queryResult) || !queryResult[0]?.document) {
    return res.status(200).json({ allow: false, message: 'No user found with this email' });
  }

  const userFields = queryResult[0].document.fields;
  const numberOfDevices = parseInt(userFields?.numberOfDevices?.integerValue || '0');
  const existingDeviceId = userFields?.deviceId?.stringValue || '';
  const existingSignature = userFields?.signature?.stringValue || '';

  // ✅ Step 6: Login logic
  if (numberOfDevices > 1) {
    return res.status(200).json({ allow: false, message: 'Device limit exceeded' });
  }

  if (deviceId !== existingDeviceId || signature !== existingSignature) {
    return res.status(200).json({ allow: false, message: 'Login denied: unauthorized device' });
  }

  return res.status(200).json({ allow: true });
}
