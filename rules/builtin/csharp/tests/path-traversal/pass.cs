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

    public void GuidBasedFilename()
    {
        // GUID 產生的檔名不存在 path traversal 風險
        string safePath = $"/uploads/{Guid.NewGuid()}.pdf";
        File.ReadAllText(Path.GetFileName(safePath));
    }

    public void SafeExtensionExtraction(string userPath)
    {
        // Path.GetExtension 只回傳副檔名，無 path traversal 風險
        string ext = Path.GetExtension(userPath);
        File.WriteAllText($"/safe/{ext}", "data");
    }

    public void SafeDirectoryName(string userPath)
    {
        // Path.GetDirectoryName 經過正規化，不會直接暴露 path traversal
        string dir = Path.GetDirectoryName(userPath);
    }
}
