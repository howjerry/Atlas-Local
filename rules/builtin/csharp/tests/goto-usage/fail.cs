// Goto Usage: SHOULD trigger the rule
// Pattern: goto_statement

using System;

public class GotoUsageFail
{
    public void SearchMatrix(int[,] matrix, int target)
    {
        for (int i = 0; i < matrix.GetLength(0); i++)
        {
            for (int j = 0; j < matrix.GetLength(1); j++)
            {
                if (matrix[i, j] == target)
                    goto Found;
            }
        }
        Console.WriteLine("Not found");
        return;
    Found:
        Console.WriteLine("Found!");
    }

    public void ProcessItems(int[] items)
    {
        int index = 0;
    Start:
        if (index >= items.Length) return;
        Console.WriteLine(items[index]);
        index++;
        goto Start;
    }
}
