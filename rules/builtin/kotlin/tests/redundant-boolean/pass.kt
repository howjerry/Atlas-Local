fun isAdult(age: Int): Boolean {
    // 好：直接回傳布林運算式
    return age >= 18
}

fun isValid(input: String): Boolean {
    return input.isNotEmpty()
}

fun classify(score: Int): String {
    // 好：if 用於回傳非布林值
    return if (score >= 60) {
        "pass"
    } else {
        "fail"
    }
}
