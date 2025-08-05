import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes window
const MAX_REQUESTS_PER_WINDOW = 5;

const HMAC_SECRET = process.env.HMAC_SECRET;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;

function verifyHmac(deviceId, timestamp, signature) {
  const crypto = require('crypto');
  const data = deviceId + ":" + timestamp;
  const hmac = crypto.createHmac("sha256", HMAC_SECRET);
  hmac.update(data);
  const digest = hmac.digest("base64");
  return digest === signature;
}

const cleanRateLimits = () => {
  const now = Date.now();
  for (const [key, value] of rateLimitMap.entries()) {
    if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(key);
    }
  }
};

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!idToken) return res.status(401).json({ error: 'Missing token' });

  // Verify Firebase ID token via REST API
  const verifyResp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_WEB_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });

  const verifyData = await verifyResp.json();
  if (!verifyData.users || !verifyData.users[0]) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const uid = verifyData.users[0].localId;
  const emailFromToken = verifyData.users[0].email;

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

  // Extract data from request body
  const { email, uid: uidFromClient, profileUri, deviceId, timestamp, signature } = req.body;

  if (!email || !uidFromClient || !deviceId || !timestamp || !signature || !profileUri) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Ensure uid from client matches token's uid for security
  if (uidFromClient !== uid) {
    return res.status(403).json({ error: 'UID mismatch' });
  }

  // Replay protection
  if (Math.abs(now - timestamp) > RATE_LIMIT_WINDOW_MS) {
    return res.status(400).json({ error: 'Timestamp invalid or expired' });
  }

  // Verify HMAC signature
  if (!verifyHmac(deviceId, timestamp, signature)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }

  // Authenticate with Google API to get access token for Firestore REST calls
  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT),
    scopes: ['https://www.googleapis.com/auth/datastore']
  });

  const client = await auth.getClient();
  const tokenResponse = await client.getAccessToken();
  const token = tokenResponse.token;

  if (!token) {
    return res.status(500).json({ error: 'Failed to get access token' });
  }

  try {
    // Fetch TempUser data from Firestore
    const tempUserUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/TempUser/${encodeURIComponent(email)}`;
    const tempUserResp = await fetch(tempUserUrl, { headers: { Authorization: `Bearer ${token}` } });
    if (!tempUserResp.ok) {
      return res.status(404).json({ error: 'TempUser not found' });
    }
    const tempUserDoc = await tempUserResp.json();
    if (!tempUserDoc.fields) {
      return res.status(404).json({ error: 'Invalid TempUser document' });
    }

    // Prepare User document fields
    const userData = { ...tempUserDoc.fields };
    userData.Profile = { stringValue: profileUri };
    userData.deviceId = { stringValue: deviceId };
    userData.signature = { stringValue: signature };
    userData.numberOfDevices = { integerValue: "1" };

    // Write User doc with UID as document ID
    const userDocUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/User/${uid}`;

    const writeResp = await fetch(userDocUrl, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: userData })
    });

    if (!writeResp.ok) {
      const errorText = await writeResp.text();
      console.error('Error writing User doc:', errorText);
      return res.status(500).json({ error: 'Failed to write User document' });
    }

    // Delete TempUser doc
    const deleteResp = await fetch(tempUserUrl, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!deleteResp.ok) {
      console.warn('Failed to delete TempUser document. Manual cleanup recommended.');
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('Unexpected error:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
