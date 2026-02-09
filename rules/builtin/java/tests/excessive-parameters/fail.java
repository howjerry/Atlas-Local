// 過多參數: 應該觸發規則
// Pattern: 方法有 6 個以上的參數

public class ExcessiveParametersFail {
    // 6 個參數（觸發）
    public void createUser(String name, String email, String phone,
                           String address, String city, String zipCode) {
        // 參數過多
    }

    // 7 個參數（觸發）
    public void buildReport(String title, String author, String dept,
                            int year, int month, String format, boolean draft) {
        // 參數更多
    }
}
