// Unrestricted File Upload: should NOT trigger the rule
// 驗證檔案類型後再儲存

using Microsoft.AspNetCore.Http;
using System.IO;

public class SafeUpload
{
    private static readonly HashSet<string> AllowedExtensions = new() { ".jpg", ".png", ".pdf" };

    public async Task Upload(IFormFile file)
    {
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!AllowedExtensions.Contains(ext))
            throw new InvalidOperationException("Invalid file type");

        // 安全：使用隨機檔名並已驗證副檔名
        var safeName = Path.GetRandomFileName() + ext;
        var path = Path.Combine("uploads", safeName);
    }
}

