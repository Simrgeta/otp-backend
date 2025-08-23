import fetch from 'node-fetch';
import crypto from 'crypto';

// Load environment variables
const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const API_KEY = process.env.CLOUDINARY_API_KEY;
const API_SECRET = process.env.CLOUDINARY_API_SECRET;

// Replace this with a sample publicId from your URL (remove folders & extension)
const publicId = 'e6y8vdaxztkrvmdm2nci';

async function testCloudinaryDelete() {
  if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
    console.error('❌ One or more Cloudinary env vars are missing!');
    return;
  }

  try {
    const timestamp = Math.floor(Date.now() / 1000);
    const paramsToSign = `public_id=${publicId}&timestamp=${timestamp}${API_SECRET}`;
    const signature = crypto.createHash('sha1').update(paramsToSign).digest('hex');

    console.log('✔ Env vars loaded successfully');
    console.log('Generated signature:', signature);

    // Test request (without actually deleting)
    const url = `https://api.cloudinary.com/v1_1/${CLOUD_NAME}/image/destroy`;
    const body = new URLSearchParams({
      public_id: publicId,
      api_key: API_KEY,
      timestamp: timestamp.toString(),
      signature,
    });

    console.log('POST URL:', url);
    console.log('POST body:', body.toString());

    // Optional: Actually call Cloudinary to see response
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await resp.json();
    console.log('Cloudinary response:', data);

  } catch (err) {
    console.error('Error testing Cloudinary:', err);
  }
}

testCloudinaryDelete();
