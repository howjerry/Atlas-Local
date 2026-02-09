// 應該被偵測：包含 Twilio API Key 的字串
// NOTE: 這些是 SAST 測試用假 token，不是真實 key

const twilioApiKey = "SK00000000000000000000000000000000";

const twilioConfig = {
  apiKey: "SK11111111111111111111111111111111",
};

const client = require('twilio')("ACxxx", "SK22222222222222222222222222222222");
