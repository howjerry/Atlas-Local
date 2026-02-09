// 應該被偵測：包含 NPM Access Token 的字串
// NOTE: 這些是 SAST 測試用假 token，不是真實 key

const npmToken = "npm_000000000000000000000000000000000000";

const registryConfig = {
  token: "npm_111111111111111111111111111111111111111111",
};

const authHeader = `Bearer npm_222222222222222222222222222222222222`;
