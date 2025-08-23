import fetch from 'node-fetch';
import { GoogleAuth } from 'google-auth-library';
import crypto from 'crypto';

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

  // ✅ Rate limiting per user
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

  // ✅ Extract publicId from request body
  const { publicId } = req.body;
  if (!publicId) {
    return res.status(400).json({ allow: false, message: 'Missing publicId field' });
  }

  try {
    // ✅ Generate signature for Cloudinary deletion
    const timestamp = Math.floor(Date.now() / 1000);
    const paramsToSign = `public_id=${publicId}&timestamp=${timestamp}${process.env.CLOUDINARY_API_SECRET}`;
    const signature = crypto.createHash('sha1').update(paramsToSign).digest('hex');

    // ✅ Call Cloudinary delete endpoint
    const cloudinaryResp = await fetch(
      `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/image/destroy`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          public_id: publicId,
          api_key: process.env.CLOUDINARY_API_KEY,
          timestamp: timestamp.toString(),
          signature: signature,
        }),
      }
    );

    const cloudinaryData = await cloudinaryResp.json();

    if (cloudinaryData.result === 'ok') {
      return res.status(200).json({ allow: true, message: 'Image deleted successfully' });
    } else {
      return res.status(500).json({ allow: false, message: 'Failed to delete image', details: cloudinaryData });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ allow: false, message: 'Server error' });
  }
}
