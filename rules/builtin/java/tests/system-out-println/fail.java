public class FailExample {
    public void debugOutput() {
        System.out.println("Debug: processing started");
        System.err.println("Error occurred");
        System.out.print("partial output");
    }
}
