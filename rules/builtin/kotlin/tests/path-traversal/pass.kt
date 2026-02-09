import java.io.File

fun readSafeFile() {
    // 安全：使用經過驗證的基礎目錄
    val baseDir = File("/app/data")
    val resolved = baseDir.resolve("config.txt").canonicalFile
    require(resolved.startsWith(baseDir.canonicalFile)) { "Path traversal detected" }
    val content = resolved.readText()
}
