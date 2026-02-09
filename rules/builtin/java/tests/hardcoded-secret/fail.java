// 硬編碼密碼: 應該觸發規則
// Pattern: 在變數宣告中直接寫入密碼或金鑰
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

public class HardcodedSecretFail {
    // 硬編碼資料庫密碼
    private String password = "sup3rS3cret!";

    // 硬編碼 API 金鑰
    private String apikey = "sk-1234567890abcdef";

    // 硬編碼存取 token
    public void connect() {
        String api_secret = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    }
}
