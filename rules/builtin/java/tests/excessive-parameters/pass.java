// 過多參數: 不應觸發規則
// 方法參數在 5 個以內

public class ExcessiveParametersPass {
    // 3 個參數（可接受）
    public void createUser(String name, String email, String phone) {
        // 參數數量合理
    }

    // 使用 Parameter Object 模式
    public void buildReport(ReportConfig config) {
        // 使用物件包裝參數
    }

    // 無參數
    public void init() {
        // 初始化
    }

    static class ReportConfig {
        String title;
        String author;
    }
}
