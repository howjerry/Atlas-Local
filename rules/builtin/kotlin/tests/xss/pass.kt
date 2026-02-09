import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun handleRequest(request: HttpServletRequest, response: HttpServletResponse) {
    val out = response.writer
    // 安全：使用靜態字串
    out.println("Hello, World!")

    // 安全：使用 HTML 編碼
    val safeName = HtmlUtils.htmlEscape(request.getParameter("name"))
    out.println(safeName)
}
