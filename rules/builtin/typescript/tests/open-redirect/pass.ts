// Open Redirect: should NOT trigger the rule
// Uses validated/hardcoded redirect URLs

// 使用硬編碼的相對路徑
const dashboardPath = "/dashboard";

// 使用 router 導航（不是 location API）
import { useNavigate } from "react-router-dom";
const navigate = useNavigate();
navigate("/home");

// 使用 allowlist 驗證後設定 href（非 assign/replace）
const allowedDomains = ["example.com", "app.example.com"];
function safeRedirect(url: string): void {
  const parsed = new URL(url);
  if (allowedDomains.includes(parsed.hostname)) {
    window.location.href = url;
  }
}
