import fetch from 'node-fetch';
import { GoogleAuth } from 'google-auth-library';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
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

    // verify caller
    const verifyResp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) }
    );
    const verifyData = await verifyResp.json();
    if (!verifyData.users || !verifyData.users[0]) return res.status(401).json({ error: 'Invalid token' });
    const uid = verifyData.users[0].localId;
    if (isRateLimited(uid)) return res.status(429).json({ error: 'Too many requests' });

    const { oobCode, newPassword } = req.body;
    if (!oobCode || !newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({ error: 'Missing or invalid parameters' });
    }

    // Call Identity Toolkit to confirm reset
    const resp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=${process.env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ oobCode, newPassword }),
      }
    );

    const json = await resp.json();
    if (!resp.ok) {
      console.error('confirmReset failed', resp.status, json);
      return res.status(400).json({ error: json?.error?.message || 'Reset failed' });
    }

    // Optionally revoke sessions for the user (safety); json.localId contains uid after reset
    // If you have admin creds, you can call admin.auth().revokeRefreshTokens(json.localId)

    return res.status(200).json({ status: 'OK' });
  } catch (err) {
    console.error('confirmReset error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
