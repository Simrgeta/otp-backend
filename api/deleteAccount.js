import admin from "firebase-admin";
import crypto from "crypto";

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CREDS)),
  });
}

// Shared secret (must match the one in SessionManager)
const HMAC_SECRET = process.env.HMAC_SECRET || "a3f5c7e2d9a1b478e4f62d1349b8c51f3a7c45b6d29e8f7c8b9a1d2e3f4b5678";

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ success: false, message: "Method Not Allowed" });

  try {
    const authHeader = req.headers["x-signature"] || "";
    const { email, deviceId } = req.body;

    if (!email || !deviceId)
      return res.status(400).json({ success: false, message: "Missing fields" });

    // ✅ Verify HMAC signature (email + deviceId)
    const expectedSig = crypto
      .createHmac("sha256", HMAC_SECRET)
      .update(email + deviceId)
      .digest("hex");

    if (authHeader !== expectedSig) {
      return res.status(401).json({ success: false, message: "Invalid signature" });
    }

    // ✅ Find user in Firestore by email
    const userSnap = await admin.firestore()
      .collection("User")
      .where("Email", "==", email)
      .limit(1)
      .get();

    if (userSnap.empty) {
      return res.status(404).json({ success: false, message: "No account found" });
    }

    const userDoc = userSnap.docs[0];
    const uid = userDoc.id;

    // ✅ Delete Firestore user doc
    await admin.firestore().collection("User").doc(uid).delete();

    // ✅ Delete FirebaseAuth account (if exists)
    try {
      await admin.auth().deleteUser(uid);
    } catch (e) {
      // ignore if already deleted
    }

    return res.status(200).json({ success: true, message: "Account deleted" });
  } catch (err) {
    console.error("Delete error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
}
