// 不應該被偵測：使用環境變數或 placeholder

const npmToken = process.env.NPM_TOKEN;

const registryConfig = {
  token: process.env.NPM_AUTH_TOKEN || "",
};

const authHeader = `Bearer ${process.env.NPM_TOKEN}`;

const example = "npm_YOUR_TOKEN_HERE";
