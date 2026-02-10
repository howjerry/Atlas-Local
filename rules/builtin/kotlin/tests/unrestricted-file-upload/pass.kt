import org.springframework.web.multipart.MultipartFile

// Unrestricted File Upload: should NOT trigger the rule
// 使用經過驗證的檔案處理

fun uploadFile(file: MultipartFile) {
    // 安全：驗證 content type 後處理
    val allowedTypes = listOf("image/jpeg", "image/png")
    if (file.contentType in allowedTypes && file.size < 5_000_000) {
        val safeName = java.util.UUID.randomUUID().toString() + ".jpg"
        // 使用經過驗證的安全路徑存儲
    }
}

