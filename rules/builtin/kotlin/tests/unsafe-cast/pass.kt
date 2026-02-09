fun processInput(obj: Any) {
    // 好：使用安全的型別轉換
    val str = obj as? String ?: "default"
    val num = obj as? Int ?: 0

    // 好：使用型別檢查
    if (obj is String) {
        val length = obj.length
    }
}
