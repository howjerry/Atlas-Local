// Path Traversal: SHOULD trigger the rule
// Pattern: File.ReadAllText/new FileStream/etc. with user input
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.IO;

public class PathTraversalFail
{
    public void UnsafeFileAccess(string userInput)
    {
        string content = File.ReadAllText(userInput);

        File.WriteAllText(userInput, "data");

        var stream = new FileStream(userInput, FileMode.Open);

        var reader = new StreamReader(userInput);

        string fullPath = Path.Combine(userInput, "file.txt");
    }
}
