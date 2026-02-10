// L3 XSS: 跨方法污染 — request.getParameter → arg → response.getWriter().println
// 注意：此為 SAST 偵測用測試夾具
public class SearchServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        String query = request.getParameter("q");
        renderResult(response, query);
    }

    void renderResult(HttpServletResponse response, String content) {
        response.getWriter().println("<h1>" + content + "</h1>");
    }
}
