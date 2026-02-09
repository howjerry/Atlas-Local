// Path Traversal: should NOT trigger the rule
// Uses hardcoded paths, path utilities, or stream-based constructors

using System.IO;

public class PathTraversalPass
{
    public void HardcodedPaths()
    {
        string content = File.ReadAllText("config.yaml");
        File.WriteAllText("/app/data/output.txt", "data");
    }

    public void PathUtilities(string userInput)
    {
        string combined = Path.Combine("base", userInput);
        string full = Path.GetFullPath(userInput);
    }

    public void StreamConstructors(Stream stream)
    {
        var writer = new StreamWriter(stream, System.Text.Encoding.UTF8);
        var reader = new StreamReader(stream);
    }

    public void ExistenceChecks(string path)
    {
        bool exists = File.Exists(path);
        bool dirExists = Directory.Exists(path);
    }
}
