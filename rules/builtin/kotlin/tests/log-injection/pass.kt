import org.slf4j.LoggerFactory

// Log Injection: should NOT trigger the rule
// 使用 SLF4J 參數化日誌

val logger = LoggerFactory.getLogger("App")

fun logUserAction(username: String) {
    // 安全：使用 SLF4J 參數化日誌
    logger.info("User login: {}", username)

    // 安全：使用硬編碼字串
    logger.info("Application started")
}

