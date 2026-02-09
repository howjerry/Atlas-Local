fun safeOperation() {
    // 安全：使用白名單驗證的固定命令
    val allowedCommands = setOf("ls", "whoami")
    val command = "ls"
    if (command in allowedCommands) {
        val result = "safe operation"
    }

    // 安全：使用 Kotlin 標準庫而非系統命令
    val files = java.io.File("/tmp").listFiles()
}
