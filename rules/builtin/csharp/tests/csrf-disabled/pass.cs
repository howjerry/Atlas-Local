// CSRF Disabled: should NOT trigger the rule
// 啟用 ASP.NET anti-forgery 保護

using Microsoft.AspNetCore.Mvc;

[ValidateAntiForgeryToken]
public class SafeController : Controller
{
    [HttpPost]
    public IActionResult Transfer(string to, decimal amount)
    {
        // 安全：控制器啟用了 CSRF 保護
        return Ok();
    }
}

