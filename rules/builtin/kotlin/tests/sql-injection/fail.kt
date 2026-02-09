import java.sql.Connection

fun getUserById(conn: Connection, userId: String) {
    val stmt = conn.createStatement()
    // 不安全：SQL 查詢中使用字串模板
    val result = stmt.executeQuery("SELECT * FROM users WHERE id = $userId")

    // 不安全：rawQuery 中使用字串模板
    db.rawQuery("SELECT name FROM users WHERE email = $email", null)
}
