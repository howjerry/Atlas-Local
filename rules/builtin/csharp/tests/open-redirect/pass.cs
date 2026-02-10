// Open Redirect: should NOT trigger the rule
// Uses LocalRedirect or hardcoded URLs

using Microsoft.AspNetCore.Mvc;

public class OpenRedirectPass : Controller
{
    public IActionResult Login(string returnUrl)
    {
        // 使用 LocalRedirect 確保不會外部跳轉
        if (Url.IsLocalUrl(returnUrl))
        {
            return LocalRedirect(returnUrl);
        }
        return LocalRedirect("/");
    }

    public IActionResult GoHome()
    {
        return Redirect("/dashboard");
    }

    public IActionResult GoToAction(string action)
    {
        // RedirectToAction 的第一個參數是 action name，由框架路由，非 open redirect
        return RedirectToAction(nameof(GoHome));
    }
}
