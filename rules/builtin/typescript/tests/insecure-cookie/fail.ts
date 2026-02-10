// Insecure Cookie: SHOULD trigger the rule
// Pattern: Cookie 安全屬性被設為 false
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import { Request, Response } from "express";

function setCookie(req: Request, res: Response) {
  // 不安全：secure 設為 false
  res.cookie("session", token, { secure: false });

  // 不安全：httpOnly 設為 false
  res.cookie("auth", jwt, { httpOnly: false });

  // 不安全：多個屬性設為 false
  res.cookie("user", data, {
    secure: false,
    httpOnly: false,
    sameSite: "none"
  });
}

