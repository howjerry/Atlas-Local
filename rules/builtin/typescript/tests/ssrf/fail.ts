// SSRF: SHOULD trigger the rule
// Pattern: fetch() with dynamic URL (template string or variable)

const userUrl = req.query.url as string;

// 使用使用者輸入的 URL
const response1 = await fetch(userUrl);

// 使用 template string 組合 URL
const response2 = await fetch(`${baseUrl}/api/data`);

// 從變數取得 URL
const endpoint = getApiEndpoint();
const response3 = await fetch(endpoint);
