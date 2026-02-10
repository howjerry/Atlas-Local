# Log Injection: SHOULD trigger the rule
# Pattern: Logger 方法使用字串格式化
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import logging

logger = logging.getLogger(__name__)

def unsafe_logging(username, ip):
    # 不安全：使用 % 格式化
    logger.info("User login: " + username)

    # 不安全：使用字串串接
    logger.error("Failed login from: " + ip)

    # 不安全：使用 % 運算子
    logger.warning("Suspicious activity: " + username + " from " + ip)

