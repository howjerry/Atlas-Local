// Insecure Cookie: should NOT trigger the rule
// Cookie 安全屬性正確設定

import { Request, Response } from "express";

function setCookie(req: Request, res: Response) {
  // 安全：所有安全屬性設為 true
  res.cookie("session", token, {
    secure: true,
    httpOnly: true,
    sameSite: "strict"
  });

  // 安全：使用安全的預設值
  res.cookie("preferences", prefs, {
    secure: true,
    httpOnly: true,
    maxAge: 3600000
  });
}

