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
}
