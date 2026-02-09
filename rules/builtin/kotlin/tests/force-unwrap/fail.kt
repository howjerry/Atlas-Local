fun processNullable(text: String?) {
    // 不好：使用 !! 非空斷言運算子
    val length = text!!.length
    val trimmed = text!!.trim()
    val upper = text!!.uppercase()
}
