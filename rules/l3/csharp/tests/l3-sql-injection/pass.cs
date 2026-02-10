// L3 SQL Injection (safe): 經過 int.Parse 淨化
public class UserController
{
    public void Search()
    {
        var id = int.Parse(Request.QueryString["id"]);
        QueryUser(id);
    }

    void QueryUser(int userId)
    {
        var sql = "SELECT * FROM users WHERE id = " + userId;
        SqlCommand(sql);
    }
}
