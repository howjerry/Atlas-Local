fun isAdult(age: Int): Boolean {
    // 不好：多餘的布林回傳
    if (age >= 18) {
        return true
    } else {
        return false
    }
}

fun isValid(input: String): Boolean {
    if (input.isNotEmpty()) {
        return true
    }
    return false
}
