import org.slf4j.LoggerFactory

// Log Injection: SHOULD trigger the rule
// Pattern: Logger 使用字串模板記錄未清理的輸入

val logger = LoggerFactory.getLogger("App")

fun logUserAction(username: String) {
    // 不安全：使用字串模板
    logger.info("User login: $username")

    // 不安全：error 等級使用字串模板
    logger.error("Failed auth for ${request.remoteAddr}")
}

