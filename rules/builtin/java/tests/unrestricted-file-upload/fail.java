// Unrestricted File Upload: SHOULD trigger the rule
// Pattern: MultipartFile 方法未經驗證直接儲存
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import org.springframework.web.multipart.MultipartFile;
import java.io.*;

public class UnrestrictedFileUploadFail {
    public void unsafeUpload(MultipartFile file) throws Exception {
        // 不安全：直接 transferTo 未驗證檔案類型
        file.transferTo(new File("/uploads/" + file.getOriginalFilename()));
    }

    public void unsafeGetBytes(MultipartFile file) throws Exception {
        // 不安全：取得檔案內容未經驗證
        byte[] bytes = file.getBytes();
        Files.write(Path.of("/uploads/data.bin"), bytes);
    }

    public void unsafeGetStream(MultipartFile file) throws Exception {
        // 不安全：取得 InputStream 未經驗證
        InputStream is = file.getInputStream();
    }
}

