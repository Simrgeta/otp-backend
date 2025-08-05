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

  const verifyResp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });

  const verifyData = await verifyResp.json();
  if (!verifyData.users || !verifyData.users[0]) {
    return res.status(401).json({ allow: false, message: 'Invalid token' });
  }

  const uid = verifyData.users[0].localId;

  // Rate limiting
  const now = Date.now();
  const cleanRateLimits = () => {
    for (const [key, value] of rateLimitMap.entries()) {
      if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.delete(key);
      }
    }
  };
  cleanRateLimits();
  const userLimit = rateLimitMap.get(uid);
  if (userLimit && now - userLimit.startTime < RATE_LIMIT_WINDOW_MS) {
    if (userLimit.count >= MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({ allow: false, message: 'Rate limit exceeded' });
    }
    userLimit.count++;
  } else {
    rateLimitMap.set(uid, { count: 1, startTime: now });
  }

  const { email, deviceId, signature } = req.body;
  if (!email || !deviceId || !signature) {
    return res.status(400).json({ allow: false, message: 'Missing required fields' });
  }

  // Authenticate to Firestore
  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_CREDS),
    scopes: ['https://www.googleapis.com/auth/datastore']
  });

  const client = await auth.getClient();
  const token = await client.getAccessToken();

  const firestoreURL = `https://firestore.googleapis.com/v1/projects/${process.env.YOUR_PROJECT_ID}/databases/(default)/documents/User/${encodeURIComponent(email)}`;

  const firestoreResp = await fetch(firestoreURL, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token.token}`
    }
  });

  if (firestoreResp.status === 404) {
    return res.status(200).json({ allow: true });
  }

  if (!firestoreResp.ok) {
    return res.status(500).json({ allow: false, message: 'Firestore fetch failed' });
  }

  const doc = await firestoreResp.json();
  const fields = doc.fields || {};

  const numberOfDevices = parseInt(fields.numberOfDevices?.integerValue || '0', 10);
  const devices = fields.devices?.arrayValue?.values || [];

  const deviceAlreadyExists = devices.some((d) => {
    const dev = d.mapValue.fields;
    return (
      dev.deviceId?.stringValue === deviceId ||
      dev.signature?.stringValue === signature
    );
  });

  if (deviceAlreadyExists) {
    return res.status(200).json({ allow: false, message: 'Device already registered for this user' });
  }

  if (numberOfDevices >= 1) {
    return res.status(200).json({ allow: false, message: 'Device limit reached for this account' });
  }

  return res.status(200).json({ allow: true });
}
