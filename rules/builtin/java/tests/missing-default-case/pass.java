// 缺少 default case: 不應觸發規則
// 使用 if-else 或包含 default 的 switch

public class MissingDefaultCasePass {
    // 使用 if-else 替代 switch
    public String getDayName(int day) {
        if (day == 1) {
            return "Monday";
        } else if (day == 2) {
            return "Tuesday";
        } else {
            return "Unknown";
        }
    }

    // 不使用 switch（避免觸發）
    public String getStatus(int code) {
        String[] statuses = {"OK", "Error", "Pending"};
        if (code >= 0 && code < statuses.length) {
            return statuses[code];
        }
        return "Unknown";
    }
}
