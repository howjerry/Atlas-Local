// XSS via Servlet Response Writer: SHOULD trigger the rule
// Pattern: print/println/write on writer with method invocation argument
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.servlet.http.*;
import java.io.*;

public class XssServletFail extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        PrintWriter out = response.getWriter();
        out.println(request.getParameter("name"));

        out.print(request.getParameter("query"));

        out.write(request.getHeader("Referer"));
    }
}
