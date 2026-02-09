import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun handleRequest(request: HttpServletRequest, response: HttpServletResponse) {
    val out = response.writer
    // 不安全：直接將使用者輸入寫入回應
    out.println(request.getParameter("name"))
    out.write(request.getParameter("data"))
}
