fun readUserFile(userPath: String) {
    // 不安全：直接使用使用者輸入建構檔案路徑
    val file = File(userPath)
    val fis = FileInputStream(userPath)
    val fos = FileOutputStream(userPath)
}
