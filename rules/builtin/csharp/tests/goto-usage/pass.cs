// Goto Usage: should NOT trigger the rule
// Uses structured control flow instead of goto

using System;
using System.Linq;

public class GotoUsagePass
{
    public void SearchMatrix(int[,] matrix, int target)
    {
        bool found = false;
        for (int i = 0; i < matrix.GetLength(0) && !found; i++)
        {
            for (int j = 0; j < matrix.GetLength(1) && !found; j++)
            {
                if (matrix[i, j] == target)
                    found = true;
            }
        }
        Console.WriteLine(found ? "Found!" : "Not found");
    }

    public void ProcessItems(int[] items)
    {
        foreach (var item in items)
        {
            Console.WriteLine(item);
        }
    }
}
