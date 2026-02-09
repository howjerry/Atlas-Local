fun executeCommand(userInput: String) {
    // 不安全：使用 Runtime.getRuntime().exec 執行系統命令
    val process = Runtime.getRuntime().exec(userInput)

    // 不安全：使用 ProcessBuilder
    val pb = ProcessBuilder("sh", "-c", userInput)
}
