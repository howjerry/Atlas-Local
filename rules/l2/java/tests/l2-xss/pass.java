public void handle(HttpServletRequest request, HttpServletResponse response) {
    String name = request.getParameter("name");
    String safe = StringEscapeUtils.escapeHtml4(name);
    response.getWriter().write(safe);
}
