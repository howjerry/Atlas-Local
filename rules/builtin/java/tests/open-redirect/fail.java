// 開放重導向: 應該觸發規則
// Pattern: 使用使用者輸入作為 sendRedirect 參數
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.servlet.http.*;

public class OpenRedirectFail extends HttpServlet {
    // 直接使用 request 參數進行重導向（不安全）
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("url"));
    }

    // 使用 request 方法回傳值重導向（不安全）
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getHeader("Referer"));
    }
}
