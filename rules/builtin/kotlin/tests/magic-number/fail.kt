fun processItems(items: List<String>) {
    // 不好：使用魔法數字
    Thread.sleep(3600000)
    val subList = items.take(42)
    setRetryCount(5)
}
