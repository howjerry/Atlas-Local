// Unrestricted File Upload: SHOULD trigger the rule
// Pattern: 上傳檔案未經驗證直接儲存
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using Microsoft.AspNetCore.Http;
using System.IO;

public class UnsafeUpload
{
    public async Task Upload(IFormFile file)
    {
        var path = Path.Combine("uploads", file.FileName);
        // 不安全：直接儲存上傳檔案
        using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);
    }
}

