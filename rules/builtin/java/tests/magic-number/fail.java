// 魔法數字: 應該觸發規則
// Pattern: 在方法呼叫的引數中使用未命名的數字常值

public class MagicNumberFail {
    // 在 Thread.sleep 中使用魔法數字
    public void delayOperation() throws InterruptedException {
        Thread.sleep(3600000);
    }

    // 在方法呼叫中使用魔法數字
    public void configure() {
        setMaxRetries(5);
        setTimeout(30000);
    }

    private void setMaxRetries(int n) {}
    private void setTimeout(int ms) {}
}
