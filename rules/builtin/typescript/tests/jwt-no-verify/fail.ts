// JWT No Verify: SHOULD trigger the rule
// Pattern: jwt.decode() 不驗證簽章即使用 token
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import jwt from "jsonwebtoken";

const token = req.headers.authorization?.split(" ")[1];

// 不安全：直接 decode 不驗證簽章
const payload1 = jwt.decode(token);

// 不安全：decode 後取得使用者資訊
const user = jwt.decode(req.body.token);

// 不安全：搭配選項但仍不驗證
const data = jwt.decode(token, { complete: true });

