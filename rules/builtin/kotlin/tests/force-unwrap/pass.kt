fun processNullable(text: String?) {
    // 好：使用安全呼叫和 elvis 運算子
    val length = text?.length ?: 0
    val trimmed = text?.trim() ?: ""

    // 好：使用明確的 null 檢查
    if (text != null) {
        val upper = text.uppercase()
    }
}
