public class Pass {
    public void onEvent(Event e) {
        handleEvent(e);
    }

    public void initialize() {
        loadConfig();
        setupDefaults();
    }

    public void onClose(Connection conn) {
        conn.close();
        logger.info("Connection closed");
    }
}
