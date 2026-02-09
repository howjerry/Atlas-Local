// 布林方法命名: 應該觸發規則
// Pattern: 回傳 boolean 的方法未使用 is/has/can 等前綴

public class BooleanMethodNamingFail {
    // 缺少 is/has/can 前綴
    public boolean valid(String input) {
        return input != null && !input.isEmpty();
    }

    // 缺少前綴
    public boolean ready() {
        return true;
    }

    // 缺少前綴
    public boolean permission(String user, String resource) {
        return true;
    }
}
