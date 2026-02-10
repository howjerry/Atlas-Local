// Log Injection: SHOULD trigger the rule
// Pattern: Logger 方法使用字串串接
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogInjectionFail {
    private static final Logger logger = LoggerFactory.getLogger(LogInjectionFail.class);

    public void unsafeLogging(String username, String ip) {
        // 不安全：info 使用字串串接
        logger.info("User login attempt: " + username);

        // 不安全：error 使用字串串接
        logger.error("Authentication failed for: " + username);

        // 不安全：warn 使用字串串接
        logger.warn("Suspicious activity from IP: " + ip);

        // 不安全：debug 使用字串串接
        logger.debug("Request payload: " + requestBody);
    }
}

