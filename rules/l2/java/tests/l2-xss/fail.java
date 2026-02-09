public void handle(HttpServletRequest request, HttpServletResponse response) {
    String name = request.getParameter("name");
    response.getWriter().write(name);
}
