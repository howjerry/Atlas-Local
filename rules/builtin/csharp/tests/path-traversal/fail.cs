// Path Traversal: SHOULD trigger the rule
// Pattern: File I/O methods with non-literal arguments (identifier, member access, etc.)
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.IO;

public class PathTraversalFail
{
    public void UnsafeFileAccess(string userInput)
    {
        string content = File.ReadAllText(userInput);

        File.WriteAllText(userInput, "data");

        File.Delete(userInput);

        var stream = new FileStream(userInput, FileMode.Open);

        File.ReadAllText($"/uploads/{userInput}");
    }
}
