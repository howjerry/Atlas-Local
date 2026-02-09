companion object {
    private const val ONE_HOUR_MS = 3600000L
    private const val MAX_ITEMS = 42
    private const val MAX_RETRIES = 5
}

fun processItems(items: List<String>) {
    // 好：使用命名常數
    Thread.sleep(ONE_HOUR_MS)
    val subList = items.take(MAX_ITEMS)
    setRetryCount(MAX_RETRIES)

    // 0 和 1 通常可接受
    val index = items.indexOf("target")
    if (index >= 0) {
        process(items[0])
    }
}
