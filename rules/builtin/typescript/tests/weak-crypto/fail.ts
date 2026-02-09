// Weak Crypto: SHOULD trigger the rule
// Pattern: createHash() with weak algorithm (md4, md5, sha1)

import crypto from "crypto";

// 使用 MD5 計算雜湊
const md5Hash = crypto.createHash("md5").update(data).digest("hex");

// 使用 SHA-1 計算雜湊
const sha1Hash = crypto.createHash("sha1").update(password).digest("hex");

// 使用 MD4 計算雜湊
const md4Hash = crypto.createHash("md4").update(payload).digest("hex");
