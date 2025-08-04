// server.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import { GoogleAuth } from 'google-auth-library';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 5;

function cleanRateLimits() {
  const now = Date.now();
  for (const [key, value] of rateLimitMap.entries()) {
    if (now - value.startTime > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(key);
    }
  }
}

app.post('/send-otp', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!idToken) return res.status(401).json({ error: 'Unauthorized: missing token' });

    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      }
    );
    const verifyData = await verifyResponse.json();

    if (!verifyData.users || verifyData.users.length === 0) {
      return res.status(401).json({ error: 'Unauthorized: invalid token' });
    }

    const uid = verifyData.users[0].localId;
    cleanRateLimits();
    const now = Date.now();

    if (!rateLimitMap.has(uid)) {
      rateLimitMap.set(uid, { count: 1, startTime: now });
    } else {
      const data = rateLimitMap.get(uid);
      if (now - data.startTime < RATE_LIMIT_WINDOW_MS) {
        if (data.count >= MAX_REQUESTS_PER_WINDOW) {
          return res.status(429).json({ error: 'Rate limit exceeded. Try again later.' });
        }
        data.count++;
      } else {
        rateLimitMap.set(uid, { count: 1, startTime: now });
      }
    }

    const { email, username } = req.body;
    if (!email || !username) return res.status(400).json({ error: 'Missing email or username' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const auth = new GoogleAuth({
      credentials: JSON.parse(process.env.FIREBASE_CREDS),
      scopes: ['https://www.googleapis.com/auth/datastore']
    });
    const client = await auth.getClient();
    const authToken = await client.getAccessToken();

    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/abebe-15ab9/databases/(default)/documents/TempUser/${encodeURIComponent(email)}?updateMask.fieldPaths=Code&updateMask.fieldPaths=is_paid&updateMask.fieldPaths=newOTP&updateMask.fieldPaths=timestamp`;
    await fetch(firestoreUrl, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${authToken.token}`,
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

    const emailResponse = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'Abebe Getachew OTP', email: 'awashsimrgeta123@gmail.com' },
        to: [{ email, name: username }],
        subject: 'Your OTP Code',
        htmlContent: `<p>Hello <b>${username}</b>,<br>Your OTP is: <h2>${otp}</h2><br>Please verify within 5 minutes.</p>`
      })
    });

    if (!emailResponse.ok) {
      const error = await emailResponse.text();
      throw new Error(`Email send error: ${error}`);
    }

    res.status(200).json({ status: 'OTP sent', email, otp });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/verify-otp', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Unauthorized: missing token' });

    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      }
    );
    const verifyData = await verifyResponse.json();
    if (!verifyData.users || verifyData.users.length === 0) {
      return res.status(401).json({ error: 'Unauthorized: invalid token' });
    }

    const { email, enteredOtp } = req.body;
    if (!email || !enteredOtp) return res.status(400).json({ error: 'Missing email or OTP code' });

    const auth = new GoogleAuth({
      credentials: JSON.parse(process.env.FIREBASE_CREDS),
      scopes: ['https://www.googleapis.com/auth/datastore']
    });
    const client = await auth.getClient();
    const authToken = await client.getAccessToken();

    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/abebe-15ab9/databases/(default)/documents/TempUser/${encodeURIComponent(email)}`;
    const response = await fetch(firestoreUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${authToken.token}`,
        'Content-Type': 'application/json'
      }
    });

    const firestoreData = await response.json();
    const storedOtp = firestoreData.fields?.Code?.stringValue;

    if (!storedOtp) return res.status(404).json({ error: 'OTP not found for user' });

    if (enteredOtp === storedOtp) {
      return res.status(200).json({ success: true, message: 'OTP verified' });
    } else {
      return res.status(403).json({ success: false, error: 'Incorrect OTP' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
