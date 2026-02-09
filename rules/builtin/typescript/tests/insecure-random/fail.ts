// Insecure Random: SHOULD trigger the rule
// Pattern: Math.random() calls used for security-sensitive values

// 產生 token 時使用不安全的亂數
const token = Math.random().toString(36).substring(2);

// 產生 session ID
const sessionId = Math.random().toString(16).slice(2);

// 產生驗證碼
function generateOTP(): string {
  return String(Math.random()).substring(2, 8);
}

// 用於密碼重設 token
const resetToken = Math.random().toString(36) + Math.random().toString(36);
