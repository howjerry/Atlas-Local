// Log Injection: SHOULD trigger the rule
// Pattern: logger 方法使用模板字串
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import { logger } from "./logger";

function handleLogin(username: string) {
  // 不安全：使用模板字串記錄使用者輸入
  logger.info(`User login attempt: ${username}`);

  // 不安全：error 使用模板字串
  logger.error(`Authentication failed for user: ${username}`);

  // 不安全：warn 使用模板字串
  logger.warn(`Suspicious activity from IP: ${req.ip}`);

  // 不安全：debug 使用模板字串
  logger.debug(`Request body: ${JSON.stringify(req.body)}`);
}

