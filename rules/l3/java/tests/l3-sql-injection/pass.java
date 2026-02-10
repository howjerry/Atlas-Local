// L3 SQL Injection (safe): 經過 Integer.parseInt 淨化
public class UserServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        int id = Integer.parseInt(request.getParameter("id"));
        queryUser(id);
    }

    void queryUser(int userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
        statement.executeQuery(sql);
    }
}
