public class PassExample {
    public int parseNumber(String input) {
        return Integer.parseInt(input);
    }

    public void properHandling() {
        try {
            Integer.parseInt("invalid");
        } catch (NumberFormatException e) {
            System.err.println("Parse error: " + e.getMessage());
        }
    }
}
