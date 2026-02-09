// Empty Conditional: should NOT trigger the rule
// All if/else blocks have non-empty bodies

using System;

public class EmptyConditionalPass
{
    public void CheckValue(int x)
    {
        if (x > 0)
        {
            Console.WriteLine("positive");
        }

        if (x < 0)
        {
            Console.WriteLine("negative");
        }
        else
        {
            Console.WriteLine("zero");
        }
    }
}
