// CSRF Disabled: SHOULD trigger the rule
// Pattern: 停用 ASP.NET anti-forgery 保護
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using Microsoft.AspNetCore.Mvc;

[IgnoreAntiforgeryToken]
public class UnsafeController : Controller
{
    [HttpPost]
    public IActionResult Transfer(string to, decimal amount)
    {
        // 不安全：控制器停用了 CSRF 保護
        return Ok();
    }
}

