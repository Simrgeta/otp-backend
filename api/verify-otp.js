import { GoogleAuth } from 'google-auth-library';
import fetch from 'node-fetch';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

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

  const { email, enteredOtp } = req.body || {};
  if (!email || !enteredOtp) {
    return res.status(400).json({ error: 'Missing email or OTP' });
  }

  const auth = new GoogleAuth({
    credentials: JSON.parse(process.env.FIREBASE_CREDS),
    scopes: ['https://www.googleapis.com/auth/datastore']
  });

  const client = await auth.getClient();
  const token = await client.getAccessToken();

  const response = await fetch(`https://firestore.googleapis.com/v1/projects/abebe-15ab9/databases/(default)/documents/TempUser/${encodeURIComponent(email)}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token.token}`,
      'Content-Type': 'application/json'
    }
  });

  const data = await response.json();
  const storedOtp = data.fields?.Code?.stringValue;

  if (enteredOtp === storedOtp) {
    return res.status(200).json({ success: true, message: 'OTP verified' });
  }

  return res.status(403).json({ success: false, error: 'Incorrect OTP' });
}
