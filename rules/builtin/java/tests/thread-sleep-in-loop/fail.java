// 迴圈中的 Thread.sleep: 應該觸發規則
// Pattern: 在 for/while/do 迴圈中呼叫 Thread.sleep()

public class ThreadSleepInLoopFail {
    // 在 while 迴圈中使用 Thread.sleep（輪詢模式）
    public void waitForCondition() throws InterruptedException {
        while (true) {
            Thread.sleep(1000);
            if (checkReady()) break;
        }
    }

    // 在 for 迴圈中使用 Thread.sleep
    public void retryOperation() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            Thread.sleep(2000);
            doWork();
        }
    }

    private boolean checkReady() { return false; }
    private void doWork() {}
}
