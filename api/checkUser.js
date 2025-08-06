import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!idToken) return res.status(401).json({ allow: false, message: 'Missing token' });

  // ✅ Verify Firebase ID token
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

  // ✅ Basic rate limiting per user
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

  // ✅ Required: email only
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ allow: false, message: 'Missing email field' });
  }

  // ✅ Set up Firestore client
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

  // ✅ Query Firestore for the email
  const firestoreResp = await fetch(queryURL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token.token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(queryBody),
  });

  const queryResult = await firestoreResp.json();

  // ✅ Decision based on existence
  if (!Array.isArray(queryResult) || !queryResult[0]?.document) {
    return res.status(200).json({ allow: true }); // Email does not exist, allow
  }

  return res.status(200).json({ allow: false, message: 'User with the same email exists!' });
}
