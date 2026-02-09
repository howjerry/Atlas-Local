// 空的條件區塊: 應該觸發規則
// Pattern: if 陳述式有空的 body

public class EmptyConditionalFail {
    // if 區塊是空的
    public void checkValue(int x) {
        if (x > 0) {
        }
    }

    // 另一個空的 if 區塊
    public void validate(String input) {
        if (input != null) { }
    }
}
