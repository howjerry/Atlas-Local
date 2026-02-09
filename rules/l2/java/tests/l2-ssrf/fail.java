public void handle(HttpServletRequest request) {
    String url = request.getParameter("url");
    new URL(url).openConnection();
}
