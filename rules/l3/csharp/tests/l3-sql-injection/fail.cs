// L3 SQL Injection: 跨方法污染 — Request.QueryString → arg → SqlCommand
// 注意：此為 SAST 偵測用測試夾具
public class UserController
{
    public void Search()
    {
        var name = Request.QueryString["name"];
        QueryUser(name);
    }

    void QueryUser(string username)
    {
        var sql = "SELECT * FROM users WHERE name = '" + username + "'";
        SqlCommand(sql);
    }
}
