using System;

namespace Atlas.Tests
{
    // Safe C# file -- should NOT trigger any findings.
    public class SafeCode
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
        }

        public int Add(int a, int b)
        {
            return a + b;
        }
    }
}
