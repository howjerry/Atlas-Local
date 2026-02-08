using System;

public class PassExample
{
    public int ParseNumber(string input)
    {
        return int.Parse(input);
    }

    public void ProperHandling()
    {
        try
        {
            int.Parse("invalid");
        }
        catch (FormatException ex)
        {
            Console.Error.WriteLine("Parse error: " + ex.Message);
        }
    }
}
