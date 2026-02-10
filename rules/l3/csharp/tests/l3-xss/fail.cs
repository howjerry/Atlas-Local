// L3 XSS: 跨方法污染 — Request.QueryString → arg → Response.Write
// 注意：此為 SAST 偵測用測試夾具
public class SearchController
{
    public void Index()
    {
        var query = Request.QueryString["q"];
        RenderResult(query);
    }

    void RenderResult(string content)
    {
        Response.Write("<h1>" + content + "</h1>");
    }
}
