public class FailExample {
    public void riskyOperation() {
        try {
            Integer.parseInt("invalid");
        } catch (NumberFormatException e) { }
    }

    public void anotherRisky() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
        }
    }
}
