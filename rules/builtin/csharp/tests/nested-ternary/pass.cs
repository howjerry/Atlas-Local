// Nested Ternary: should NOT trigger the rule
// Uses simple (non-nested) ternary or if-else

using System;

public class NestedTernaryPass
{
    public string Classify(int value)
    {
        if (value > 0) return "positive";
        if (value < 0) return "negative";
        return "zero";
    }

    public string GetLabel(bool active)
    {
        // 單層三元運算子是允許的
        return active ? "Active" : "Inactive";
    }
}
