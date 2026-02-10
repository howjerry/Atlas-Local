// ViewState Insecure: SHOULD trigger the rule
// Pattern: 停用 ViewState MAC 驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Web.UI;

public class UnsafePage : Page
{
    protected void Page_Init(object sender, EventArgs e)
    {
        // 不安全：停用 ViewState MAC 驗證
        EnableViewStateMac = false;
    }

    public void UnsafeEncryption()
    {
        // 不安全：停用 ViewState 加密
        ViewStateEncryptionMode = ViewStateEncryptionMode.Never;
    }
}

