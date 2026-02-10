// Unsafe Redirect: SHOULD trigger the rule
// Pattern: Express res.redirect() 使用變數或模板字串
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import { Request, Response } from "express";

function handleLogin(req: Request, res: Response) {
  const returnUrl = req.query.returnUrl as string;

  // 不安全：直接使用使用者輸入
  res.redirect(returnUrl);

  // 不安全：使用模板字串組合
  res.redirect(`${req.body.redirectTo}/callback`);

  // 不安全：使用變數
  const target = req.headers.referer;
  res.redirect(target);
}

