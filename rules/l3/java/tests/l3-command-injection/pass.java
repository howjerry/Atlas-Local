// L3 Command Injection (safe): 使用靜態路徑
public class FileServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filePath = "/static/readme.txt";
        loadFile(filePath);
    }

    void loadFile(String path) {
        Paths.get(path);
    }
}
