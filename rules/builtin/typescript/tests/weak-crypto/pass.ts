// Weak Crypto: should NOT trigger the rule
// Uses strong hash algorithms

import crypto from "crypto";
import bcrypt from "bcrypt";

// 使用 SHA-256 計算雜湊
const sha256Hash = crypto.createHash("sha256").update(data).digest("hex");

// 使用 SHA-512 計算雜湊
const sha512Hash = crypto.createHash("sha512").update(payload).digest("hex");

// 使用 bcrypt 進行密碼雜湊
const passwordHash = await bcrypt.hash(password, 12);
