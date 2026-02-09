public void handle(HttpServletRequest request) {
    String url = request.getParameter("url");
    int safe = Integer.parseInt(url);
    System.out.println(safe);
}
