// 巢狀三元運算: 不應觸發規則
// 使用單層三元或 if-else

public class NestedTernaryPass {
    // 單層三元運算（可接受）
    public String getLabel(int score) {
        return score > 90 ? "A" : "B";
    }

    // 使用 if-else 替代巢狀三元
    public String classify(int value) {
        if (value > 0) {
            return "positive";
        } else if (value < 0) {
            return "negative";
        } else {
            return "zero";
        }
    }
}
