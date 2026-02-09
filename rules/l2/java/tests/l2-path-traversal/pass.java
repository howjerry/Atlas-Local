public void handle(HttpServletRequest request) {
    String filePath = request.getParameter("file");
    String safe = Paths.get(filePath).normalize().toString();
    System.out.println(safe);
}
