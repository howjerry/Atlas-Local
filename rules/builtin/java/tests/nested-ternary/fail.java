// 巢狀三元運算: 應該觸發規則
// Pattern: 三元運算式中包含另一個三元運算式

public class NestedTernaryFail {
    // consequence 中巢狀三元
    public String getLabel(int score) {
        return score > 90 ? (score > 95 ? "A+" : "A") : "B";
    }

    // alternative 中巢狀三元
    public String classify(int value) {
        return value > 0 ? "positive" : (value < 0 ? "negative" : "zero");
    }
}
