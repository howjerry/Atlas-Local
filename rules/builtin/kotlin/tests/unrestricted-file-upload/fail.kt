import org.springframework.web.multipart.MultipartFile
import java.io.File

// Unrestricted File Upload: SHOULD trigger the rule
// Pattern: MultipartFile 直接存取未經驗證

fun uploadFile(file: MultipartFile) {
    // 不安全：直接 transferTo 無驗證
    file.transferTo(File("/uploads/${file.originalFilename}"))

    // 不安全：直接讀取 bytes
    val bytes = file.getBytes()
}

