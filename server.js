require("dotenv").config();
const express = require("express");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.post("/send-otp", async (req, res) => {
  const { to, otp } = req.body;

  if (!to || !otp) {
    return res.status(400).json({ error: "Missing 'to' or 'otp'" });
  }

  try {
    const response = await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          name: process.env.FROM_NAME,
          email: process.env.FROM_EMAIL,
        },
        to: [{ email: to }],
        subject: "Your OTP Code",
        htmlContent: `<h1>Your OTP: ${otp}</h1>`,
      },
      {
        headers: {
          "api-key": process.env.BREVO_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    res.status(200).json({ success: true, message: "Email sent!" });
  } catch (err) {
    console.error("Failed to send email:", err?.response?.data || err.message);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

app.get("/", (req, res) => res.send("OTP Server is running"));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
