import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
  const API_KEY = process.env.CLOUDINARY_API_KEY;
  const API_SECRET = process.env.CLOUDINARY_API_SECRET;

  if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
    console.error('❌ Missing Cloudinary env vars');
    return res.status(500).json({ error: 'Cloudinary env vars not set' });
  }

  const publicId = req.body?.publicId || 'e6y8vdaxztkrvmdm2nci';

  try {
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto
      .createHash('sha1')
      .update(`public_id=${publicId}&timestamp=${timestamp}${API_SECRET}`)
      .digest('hex');

    const url = `https://api.cloudinary.com/v1_1/${CLOUD_NAME}/image/destroy`;

    const body = new URLSearchParams({
      public_id: publicId,
      api_key: API_KEY,
      timestamp: timestamp.toString(),
      signature,
    });

    // Call Cloudinary
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    const data = await resp.json();

    console.log('Cloudinary response:', data);
    return res.status(200).json({ cloudinary: data });

  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ error: 'Server error', details: err.message });
  }
}
