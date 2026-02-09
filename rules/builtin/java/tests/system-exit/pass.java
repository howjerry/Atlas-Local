// System.exit 呼叫: 不應觸發規則
// 使用例外處理替代 System.exit

public class SystemExitPass {
    // 拋出例外而非直接終止 JVM
    public void processData(String data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
    }

    // 正常回傳而非強制終止
    public boolean shutdown() {
        cleanup();
        return true;
    }

    private void cleanup() {
        // 清理資源
    }
}
