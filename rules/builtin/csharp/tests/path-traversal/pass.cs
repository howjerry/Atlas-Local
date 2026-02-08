// Path Traversal: should NOT trigger the rule
// Uses validated and sanitized paths via helper methods

using System.IO;

public class PathTraversalPass
{
    private readonly string _baseDir = "/app/data";

    public byte[] SafeFileAccess(string userInput)
    {
        string safePath = ValidatePath(userInput);
        return SafeReadHelper.ReadFile(safePath);
    }

    private string ValidatePath(string input)
    {
        string fullPath = GetSafePath(_baseDir, input);
        if (!fullPath.StartsWith(_baseDir))
            throw new System.Security.SecurityException("Path traversal detected");
        return fullPath;
    }
}
