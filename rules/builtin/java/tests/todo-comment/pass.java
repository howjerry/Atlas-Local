public class Pass {
    // This method validates user input
    public void process(String input) {
        if (input != null) {
            System.out.println(input);
        }
    }

    /* Helper class for DB operations */
    public String transform(String data) {
        return data.toUpperCase();
    }

    // Returns the sum of two integers
    public int calculate(int a, int b) {
        return a + b;
    }
}
