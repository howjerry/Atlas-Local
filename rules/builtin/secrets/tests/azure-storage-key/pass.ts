// 不應該被偵測：使用環境變數或 placeholder

const azureConnection = process.env.AZURE_STORAGE_CONNECTION_STRING;

const storageConfig = {
  connectionString: process.env.AZURE_CONNECTION_STRING || "",
};

const config = "AccountKey=<your-account-key-here>";
const example = "AccountKey=PLACEHOLDER";
