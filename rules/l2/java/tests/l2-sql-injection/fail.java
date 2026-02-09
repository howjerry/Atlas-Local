public void handle(HttpServletRequest request) {
    String name = request.getParameter("name");
    statement.executeQuery(name);
}
