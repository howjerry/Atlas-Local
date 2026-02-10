// L3 Command Injection: 跨方法污染 — request.getParameter → arg → Paths.get
// 注意：此為 SAST 偵測用測試夾具
public class FileServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filePath = request.getParameter("file");
        loadFile(filePath);
    }

    void loadFile(String path) {
        Paths.get(path);
    }
}
