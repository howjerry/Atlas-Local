// L3 XSS (safe): 經過 HtmlUtils.htmlEscape 淨化
public class SearchServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        String query = HtmlUtils.htmlEscape(request.getParameter("q"));
        renderResult(response, query);
    }

    void renderResult(HttpServletResponse response, String content) {
        response.getWriter().println("<h1>" + content + "</h1>");
    }
}
