using System;

public class FailExample
{
    public void RiskyOperation()
    {
        try
        {
            int.Parse("invalid");
        }
        catch (FormatException ex) { }
    }

    public void AnotherRisky()
    {
        try
        {
            System.IO.File.ReadAllText("missing.txt");
        }
        catch (Exception e)
        {
        }
    }
}
