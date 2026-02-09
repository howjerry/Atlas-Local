// Hardcoded Secret: should NOT trigger the rule
// Uses environment variables or external secret management

// 從環境變數取得密碼
const dbPassword = process.env.DB_PASSWORD;

// 從環境變數取得 API 金鑰
const stripeKey = process.env.STRIPE_API_KEY;

// 從 secrets manager 取得
import { SecretsManager } from "aws-sdk";
const client = new SecretsManager();
const secretValue = await client.getSecretValue({ SecretId: "myapp/prod" }).promise();

// 使用 config 模組
import config from "config";
const jwtSecret = config.get<string>("jwt.secret");

// 非機密的一般字串變數
const username = "admin";
const greeting = "Hello, world!";
