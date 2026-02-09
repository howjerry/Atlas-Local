public void handle(HttpServletRequest request) {
    String cmd = request.getParameter("cmd");
    int safe = Integer.parseInt(cmd);
    System.out.println(safe);
}
