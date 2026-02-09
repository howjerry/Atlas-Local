// 空的條件區塊: 不應觸發規則
// if 區塊含有實際邏輯

public class EmptyConditionalPass {
    // if 區塊有實際邏輯
    public void checkValue(int x) {
        if (x > 0) {
            System.out.println("Positive");
        }
    }

    // if-else 都有內容
    public String validate(String input) {
        if (input != null) {
            return input.trim();
        } else {
            return "";
        }
    }
}
