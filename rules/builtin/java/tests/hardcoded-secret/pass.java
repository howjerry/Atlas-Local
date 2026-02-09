// 硬編碼密碼: 不應觸發規則
// 從環境變數或設定檔讀取密碼

public class HardcodedSecretPass {
    // 從環境變數讀取密碼（安全）
    private String dbHost = System.getenv("DB_HOST");

    // 使用佔位符描述（非實際密碼）
    private String username = "admin";

    // 一般字串變數不應觸發
    private String greeting = "Hello, World!";
    private String status = "active";

    public void connect() {
        String dbUrl = System.getenv("DATABASE_URL");
        int maxRetries = 3;
    }
}
