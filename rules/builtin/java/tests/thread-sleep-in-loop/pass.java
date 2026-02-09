// 迴圈中的 Thread.sleep: 不應觸發規則
// 使用 ScheduledExecutorService 或 CountDownLatch

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;

public class ThreadSleepInLoopPass {
    // 使用 ScheduledExecutorService 替代迴圈 + sleep
    public void scheduleTask() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> doWork(), 0, 1, TimeUnit.SECONDS);
    }

    // 使用 CountDownLatch 等待
    public void waitForCompletion() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        latch.await(30, TimeUnit.SECONDS);
    }

    private void doWork() {}
}
