// Log Injection: should NOT trigger the rule
// 使用參數化日誌或硬編碼訊息

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogInjectionPass {
    private static final Logger logger = LoggerFactory.getLogger(LogInjectionPass.class);

    public void safeLogging(String username) {
        // 安全：使用參數化 placeholder
        logger.info("User login attempt: {}", username);

        // 安全：硬編碼訊息
        logger.error("Authentication service unavailable");

        // 安全：使用參數化格式
        logger.warn("Suspicious activity detected for user: {}", username);

        // 安全：使用 key-value 結構
        logger.debug("Processing request for endpoint: {}", "/api/users");
    }
}

