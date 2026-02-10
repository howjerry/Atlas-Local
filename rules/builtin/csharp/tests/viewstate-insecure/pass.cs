// ViewState Insecure: should NOT trigger the rule
// 啟用 ViewState MAC 驗證和加密

using System.Web.UI;

public class SafePage : Page
{
    protected void Page_Init(object sender, EventArgs e)
    {
        // 安全：啟用 ViewState MAC 驗證（預設值）
        EnableViewStateMac = true;
        ViewStateEncryptionMode = ViewStateEncryptionMode.Always;
    }
}

