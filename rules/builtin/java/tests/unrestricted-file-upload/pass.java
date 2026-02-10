// Unrestricted File Upload: should NOT trigger the rule
// 使用驗證後的安全檔案處理

import org.springframework.web.multipart.MultipartFile;
import java.io.*;

public class UnrestrictedFileUploadPass {
    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");

    public void safeUpload(MultipartFile file) throws Exception {
        // 安全：先驗證再處理（此處不觸發規則因為是自訂方法）
        String contentType = file.getContentType();
        if (!ALLOWED_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("Invalid file type");
        }
        String safeName = UUID.randomUUID().toString() + ".png";
        File dest = new File("/uploads/" + safeName);
        // 注意：這裡仍會觸發規則，因為使用了 transferTo
        // 實際上此 pass 測試展示的是不使用這些方法的安全替代方案
    }

    public void safeProcess(String data) {
        // 安全：不涉及 MultipartFile
        byte[] bytes = data.getBytes();
    }
}

