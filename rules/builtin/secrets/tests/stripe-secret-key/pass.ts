// 不應該被偵測：使用環境變數或 placeholder

const stripeKey = process.env.STRIPE_SECRET_KEY;

const stripeConfig = {
  secretKey: process.env.STRIPE_API_KEY || "",
};

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const apiKey = "sk_live_YOUR_KEY_HERE";
const testKey = "sk_test_xxxx";
