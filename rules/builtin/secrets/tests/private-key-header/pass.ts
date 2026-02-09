// 不應該被偵測：從檔案或環境變數載入

import fs from 'fs';

const rsaKey = fs.readFileSync('/path/to/private.key', 'utf8');

const ecKey = process.env.EC_PRIVATE_KEY;

const opensshKey = await loadKeyFromVault();

const keyPath = './keys/private.pem';
const privateKey = fs.readFileSync(keyPath);

// Public keys are OK
const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----`;
