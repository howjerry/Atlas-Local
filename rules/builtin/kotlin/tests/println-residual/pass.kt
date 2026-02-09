import org.slf4j.LoggerFactory

val logger = LoggerFactory.getLogger("App")

fun processData(data: List<String>) {
    // 好：使用日誌框架
    logger.debug("Processing data...")
    for (item in data) {
        logger.info("Item: {}", item)
    }
    logger.debug("Done")
}
