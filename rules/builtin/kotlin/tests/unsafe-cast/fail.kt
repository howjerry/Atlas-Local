fun processInput(obj: Any) {
    // 不好：不安全的型別轉換
    val str = obj as String
    val num = obj as Int
    val list = obj as List<String>
}
