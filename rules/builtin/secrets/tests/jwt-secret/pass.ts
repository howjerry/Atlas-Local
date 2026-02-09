// 不應該被偵測：使用環境變數或動態載入

const jwt_secret = process.env.JWT_SECRET;

const jwtSecret = process.env.TOKEN_SECRET || "";

const TOKEN_SECRET = process.env.JWT_SECRET_KEY;

const config = {
  jwt_secret: process.env.JWT_SECRET,
};

let tokenSecret = loadSecretFromVault();

// 其他變數名稱不會觸發
const apiKey = "some-api-key";
const password = "some-password";
