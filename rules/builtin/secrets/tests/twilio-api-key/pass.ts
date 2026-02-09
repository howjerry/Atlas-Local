// 不應該被偵測：使用環境變數或 placeholder

const twilioApiKey = process.env.TWILIO_API_KEY;

const twilioConfig = {
  apiKey: process.env.TWILIO_API_KEY || "",
};

const client = require('twilio')(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_API_KEY
);

const example = "SK00000000000000000000000000000000";
