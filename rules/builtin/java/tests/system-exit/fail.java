// System.exit 呼叫: 應該觸發規則
// Pattern: 在程式中呼叫 System.exit()

public class SystemExitFail {
    // 在錯誤處理中呼叫 System.exit
    public void processData(String data) {
        if (data == null) {
            System.exit(1);
        }
    }

    // 在一般方法中呼叫 System.exit
    public void shutdown() {
        System.exit(0);
    }
}
