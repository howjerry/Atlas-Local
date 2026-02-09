import java.util.logging.Logger

val logger = Logger.getLogger("App")

fun riskyOperation() {
    try {
        val result = dangerousCall()
    } catch (e: Exception) {
        // 好：適當處理例外
        logger.severe("Operation failed: ${e.message}")
        throw RuntimeException("Wrapped exception", e)
    }
}
