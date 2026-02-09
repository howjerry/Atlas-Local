class DatabaseConfig {
    // 安全：從環境變數讀取密碼
    val password = System.getenv("DB_PASSWORD")
    val apiKey = System.getenv("API_KEY")

    // 安全：非敏感的普通變數名稱
    val username = "admin"
    val host = "localhost"
    val port = 5432
}
