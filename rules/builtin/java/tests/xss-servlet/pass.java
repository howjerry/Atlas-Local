// XSS via Servlet Response Writer: should NOT trigger the rule
// Uses encoded output or static strings

import javax.servlet.http.*;
import java.io.*;

public class XssServletPass extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        PrintWriter out = response.getWriter();
        out.println("Welcome to our site");

        out.print("<html><body>Hello</body></html>");

        String name = Encode.forHtml(request.getParameter("name"));
        out.println(name);
    }
}
