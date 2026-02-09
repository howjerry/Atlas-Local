data class UserInfo(
    val name: String,
    val email: String,
    val phone: String,
    val address: String,
    val city: String,
    val zipCode: String
)

// 好：使用資料類別封裝參數
fun createUser(info: UserInfo) {
    // 建立使用者
}

// 好：參數數量在合理範圍內
fun calculate(a: Int, b: Int, c: Int): Int {
    return a + b + c
}
