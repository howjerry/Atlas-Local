// 布林方法命名: 不應觸發規則
// 使用正確的 is/has/can/should 前綴

public class BooleanMethodNamingPass {
    // 正確的 is 前綴
    public boolean isValid(String input) {
        return input != null && !input.isEmpty();
    }

    // 正確的 has 前綴
    public boolean hasPermission(String user, String resource) {
        return true;
    }

    // 正確的 can 前綴
    public boolean canDelete(int id) {
        return id > 0;
    }

    // 回傳非 boolean 的方法不受影響
    public String getName() {
        return "test";
    }

    // 正確的 contains 前綴
    public boolean containsKey(String key) {
        return true;
    }
}
