import java.sql.Connection

fun getUserById(conn: Connection, userId: String) {
    // 安全：使用 PreparedStatement 參數化查詢
    val ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    ps.setString(1, userId)
    val result = ps.executeQuery()

    // 安全：rawQuery 使用 selectionArgs
    db.rawQuery("SELECT name FROM users WHERE email = ?", arrayOf(email))
}
