// Open Redirect: SHOULD trigger the rule
// Pattern: Redirect(), RedirectToAction(), RedirectPermanent() with user input
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using Microsoft.AspNetCore.Mvc;

public class OpenRedirectFail : Controller
{
    public IActionResult Login(string returnUrl)
    {
        // 使用者輸入直接傳入 Redirect
        return Redirect(returnUrl);
    }

    public IActionResult GoToAction(string action)
    {
        return RedirectToAction(action);
    }

    public IActionResult PermanentRedirect(string url)
    {
        return RedirectPermanent(url);
    }
}
