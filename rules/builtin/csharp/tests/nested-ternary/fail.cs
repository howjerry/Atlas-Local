// Nested Ternary: SHOULD trigger the rule
// Pattern: conditional_expression containing another conditional_expression

using System;

public class NestedTernaryFail
{
    public string Classify(int value)
    {
        // 巢狀三元運算子降低可讀性
        return value > 0 ? "positive" : value < 0 ? "negative" : "zero";
    }

    public int GetPriority(bool urgent, bool important)
    {
        return urgent ? (important ? 1 : 2) : (important ? 3 : 4);
    }
}
