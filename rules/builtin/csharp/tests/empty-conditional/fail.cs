// Empty Conditional: SHOULD trigger the rule
// Pattern: if/else blocks with empty body

using System;

public class EmptyConditionalFail
{
    public void CheckValue(int x)
    {
        if (x > 0)
        {
        }

        if (x < 0)
        {
            Console.WriteLine("negative");
        }
        else
        {
        }
    }
}
