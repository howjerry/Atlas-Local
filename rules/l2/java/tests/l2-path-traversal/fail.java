public void handle(HttpServletRequest request) {
    String filePath = request.getParameter("file");
    new FileInputStream(filePath);
}
