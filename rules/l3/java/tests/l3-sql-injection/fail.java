// L3 SQL Injection: 跨方法污染 — request.getParameter → arg → statement.executeQuery
// 注意：此為 SAST 偵測用測試夾具
public class UserServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        queryUser(name);
    }

    void queryUser(String username) {
        String sql = "SELECT * FROM users WHERE name = '" + username + "'";
        statement.executeQuery(sql);
    }
}
