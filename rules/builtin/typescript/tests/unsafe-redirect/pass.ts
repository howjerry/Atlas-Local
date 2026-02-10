// Unsafe Redirect: should NOT trigger the rule
// 使用硬編碼路徑或驗證後的 URL

import { Request, Response } from "express";

function handleLogin(req: Request, res: Response) {
  // 安全：硬編碼的路徑
  res.redirect("/dashboard");

  // 安全：使用硬編碼的完整 URL
  res.redirect("https://app.example.com/home");

  // 安全：使用 status code + 硬編碼路徑
  res.redirect(301, "/new-location");
}

