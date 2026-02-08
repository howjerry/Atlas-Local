import java.util.logging.Logger;

public class PassExample {
    private static final Logger logger = Logger.getLogger(PassExample.class.getName());

    public void properLogging() {
        logger.info("Processing started");
        logger.severe("Error occurred");
    }
}
