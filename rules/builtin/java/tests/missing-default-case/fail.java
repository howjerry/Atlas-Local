// 缺少 default case: 應該觸發規則
// Pattern: switch 陳述式沒有 default 分支

public class MissingDefaultCaseFail {
    // switch 缺少 default case
    public String getDayName(int day) {
        String name;
        switch (day) {
            case 1:
                name = "Monday";
                break;
            case 2:
                name = "Tuesday";
                break;
            case 3:
                name = "Wednesday";
                break;
        }
        return name;
    }
}
