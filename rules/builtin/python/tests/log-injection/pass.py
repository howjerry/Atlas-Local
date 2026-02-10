# Log Injection: should NOT trigger the rule
# 使用參數化日誌

import logging

logger = logging.getLogger(__name__)

def safe_logging(username, ip):
    # 安全：使用參數化 placeholder
    logger.info("User login: %s", username)

    # 安全：硬編碼訊息
    logger.error("Authentication service unavailable")

    # 安全：使用參數化格式
    logger.warning("Suspicious activity from %s at %s", username, ip)

