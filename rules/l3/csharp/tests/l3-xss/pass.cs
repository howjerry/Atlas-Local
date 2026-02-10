// L3 XSS (safe): 經過 HtmlEncoder.Encode 淨化
public class SearchController
{
    public void Index()
    {
        var query = HtmlEncoder.Encode(Request.QueryString["q"]);
        RenderResult(query);
    }

    void RenderResult(string content)
    {
        Response.Write("<h1>" + content + "</h1>");
    }
}
