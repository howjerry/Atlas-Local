// 開放重導向: 不應觸發規則
// 使用固定字串進行重導向

import javax.servlet.http.*;

public class OpenRedirectPass extends HttpServlet {
    // 使用硬編碼路徑重導向（安全）
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect("/dashboard");
    }

    // 使用硬編碼 URL 重導向（安全）
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect("/login?expired=true");
    }
}
