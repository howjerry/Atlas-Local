fun riskyOperation() {
    try {
        val result = dangerousCall()
    } catch (e: Exception) {
        // 不好：空的 catch 區塊，會隱藏錯誤
    }
}

fun anotherRisky() {
    try {
        parseData()
    } catch (e: IllegalArgumentException) {
    }
}
