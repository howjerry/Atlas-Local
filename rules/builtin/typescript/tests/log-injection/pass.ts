// Log Injection: should NOT trigger the rule
// 使用結構化日誌或硬編碼訊息

import { logger } from "./logger";

function handleLogin(username: string) {
  // 安全：使用結構化日誌參數
  logger.info("User login attempt", { username });

  // 安全：使用硬編碼訊息
  logger.error("Authentication failed");

  // 安全：使用物件參數
  logger.warn("Suspicious activity", { ip: req.ip, action: "login" });

  // 安全：硬編碼的字串
  logger.debug("Request processing started");
}

