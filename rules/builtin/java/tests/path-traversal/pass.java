// Path Traversal: should NOT trigger the rule
// Uses validated and normalized paths

import java.io.*;
import java.nio.file.*;

public class PathTraversalPass {
    private static final Path BASE_DIR = Path.of("/app/data");

    public void safeFileAccess(String userInput) throws Exception {
        Path resolved = BASE_DIR.resolve(userInput).normalize();
        if (!resolved.startsWith(BASE_DIR)) {
            throw new SecurityException("Path traversal detected");
        }
        byte[] data = Files.readAllBytes(resolved);
    }
}
