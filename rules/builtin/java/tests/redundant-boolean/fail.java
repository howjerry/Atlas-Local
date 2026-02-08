public class Fail {
    public void check(boolean isReady, boolean isActive) {
        if (isReady == true) {
            start();
        }

        if (isActive != false) {
            process();
        }

        boolean result = isReady == false;
    }
}
