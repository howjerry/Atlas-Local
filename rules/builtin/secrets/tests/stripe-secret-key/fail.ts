// 應該被偵測：包含 Stripe Secret Key 的字串
// NOTE: 這些是 SAST 測試用假 token，不是真實 key

const stripeKey = "sk_test_00000000000000000000000000000000000000000000";

const stripeConfig = {
  secretKey: "sk_test_00000000000000000000000000",
};

const stripe = require('stripe')("sk_test_00000000000000000000000000000000000000");

const apiKey = "sk_test_00000000000000000000000000";
