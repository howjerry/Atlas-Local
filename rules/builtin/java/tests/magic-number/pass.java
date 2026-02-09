// 魔法數字: 不應觸發規則
// 使用命名常數或只用 0/1

public class MagicNumberPass {
    private static final long ONE_HOUR_MS = 3600000;
    private static final int MAX_RETRIES = 5;

    // 使用命名常數
    public void delayOperation() throws InterruptedException {
        Thread.sleep(ONE_HOUR_MS);
    }

    // 使用命名常數
    public void configure() {
        setMaxRetries(MAX_RETRIES);
    }

    // 0 和 1 是常見值，不算魔法數字
    public int getDefault() {
        return 0;
    }

    private void setMaxRetries(int n) {}
}
