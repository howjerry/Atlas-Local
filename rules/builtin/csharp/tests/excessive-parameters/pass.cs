// Excessive Parameters: should NOT trigger the rule
// Methods have 5 or fewer parameters

using System;

public class ExcessiveParametersPass
{
    public void CreateUser(string name, string email)
    {
        Console.WriteLine("Creating user...");
    }

    public decimal CalculatePrice(decimal basePrice, decimal tax, decimal discount)
    {
        return basePrice + tax - discount;
    }

    public void ProcessOrder(string orderId, DateTime date, string status, int quantity, decimal total)
    {
        Console.WriteLine("Processing...");
    }
}
