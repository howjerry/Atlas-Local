public void handle(HttpServletRequest request) {
    String id = request.getParameter("id");
    int safeId = Integer.parseInt(id);
    statement.executeQuery(String.valueOf(safeId));
}
