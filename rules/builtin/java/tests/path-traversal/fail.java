// Path Traversal: SHOULD trigger the rule
// Pattern: File/FileInputStream/FileOutputStream/FileReader/FileWriter constructors,
//          or Paths.get/Path.of/Path.resolve with user input
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.io.*;
import java.nio.file.*;

public class PathTraversalFail {
    public void unsafeFileAccess(String userInput) throws Exception {
        File f = new File(userInput);

        FileInputStream fis = new FileInputStream(userInput);

        FileWriter fw = new FileWriter(userInput);

        Path p = Paths.get(userInput);

        Path p2 = Path.of(userInput);
    }
}
