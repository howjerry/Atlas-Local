using System;

namespace TodoExample
{
    public class PassExample
    {
        // This method validates user input
        public void ProcessData(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException(nameof(input));
            var result = input.Trim();
        }

        // Calculates the sum of two integers
        public int Calculate(int x, int y)
        {
            return x + y;
        }

        /// <summary>
        /// Formats the given value to uppercase.
        /// </summary>
        public string Format(string value)
        {
            return value.ToUpper();
        }
    }
}
