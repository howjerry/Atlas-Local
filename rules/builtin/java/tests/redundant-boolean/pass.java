public class Pass {
    public void check(boolean isReady, boolean isActive) {
        if (isReady) {
            start();
        }

        if (isActive) {
            process();
        }

        boolean result = !isReady;
    }
}
