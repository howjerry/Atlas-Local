fun buildReport(items: List<String>): String {
    // 好：使用 buildString
    val result = buildString {
        for (item in items) {
            append(item)
        }
    }

    // 好：使用 joinToString
    val csv = items.joinToString(",")

    // 好：使用 StringBuilder
    val sb = StringBuilder()
    for (item in items) {
        sb.append(item)
    }

    return result
}
