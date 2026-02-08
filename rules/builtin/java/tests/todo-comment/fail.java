public class Fail {
    // TODO: refactor this method
    public void process(String input) {
        System.out.println(input);
    }

    /* FIXME: handle edge case when input is null */
    public String transform(String data) {
        return data.toUpperCase();
    }

    // HACK: this is a temporary workaround for the API bug
    public int calculate(int a, int b) {
        return a + b;
    }
}
