// Insecure Random: should NOT trigger the rule
// Uses cryptographically secure alternatives

import { randomBytes, randomUUID } from "crypto";

// 使用 crypto 模組產生安全的 token
const token = randomBytes(32).toString("hex");

// 使用 randomUUID
const sessionId = randomUUID();

// 使用 Web Crypto API
const buffer = new Uint8Array(32);
crypto.getRandomValues(buffer);

// 安全的 OTP 產生
function generateOTP(): string {
  const bytes = randomBytes(4);
  const num = bytes.readUInt32BE(0) % 1000000;
  return num.toString().padStart(6, "0");
}
