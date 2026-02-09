// Excessive Parameters: SHOULD trigger the rule
// Pattern: methods with 6 or more parameters

using System;

public class ExcessiveParametersFail
{
    public void CreateUser(
        string firstName,
        string lastName,
        string email,
        string phone,
        string address,
        string city)
    {
        Console.WriteLine("Creating user...");
    }

    public decimal CalculatePrice(
        decimal basePrice,
        decimal tax,
        decimal discount,
        decimal shipping,
        decimal insurance,
        decimal handling,
        decimal surcharge)
    {
        return basePrice + tax - discount + shipping + insurance + handling + surcharge;
    }
}
