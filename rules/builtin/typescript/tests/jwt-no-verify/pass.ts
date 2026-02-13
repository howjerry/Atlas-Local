// JWT No Verify: should NOT trigger the rule
// 使用 jwt.verify() 驗證簽章

import jwt from "jsonwebtoken";

const token = req.headers.authorization?.split(" ")[1];

// 安全：使用 verify 驗證簽章
const payload1 = jwt.verify(token, process.env.JWT_SECRET!);

// 安全：使用非對稱金鑰驗證
const payload2 = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

// 安全：使用 sign 產生 token
const newToken = jwt.sign({ userId: 123 }, secretKey, { expiresIn: "1h" });

// 安全：TextDecoder.decode() 非 JWT 操作（回歸測試）
const decoder = new TextDecoder();
const text = decoder.decode(new Uint8Array([72, 101]));

