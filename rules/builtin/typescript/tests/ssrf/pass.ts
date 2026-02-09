// SSRF: should NOT trigger the rule
// Uses hardcoded URLs

// 使用硬編碼的 URL 字串
const response1 = await fetch("https://api.example.com/data");

// 使用硬編碼的 URL
const response2 = await fetch("https://api.example.com/users/list");

// 使用 axios（非 fetch）
import axios from "axios";
const response3 = await axios.get("https://api.example.com/health");
