import java.sql.*;
import java.io.*;

// NOTE: This file INTENTIONALLY contains insecure patterns for SAST test fixtures.
public class Vulnerable {

    // SQL injection via string concatenation -- should trigger atlas/security/java/sql-injection
    public ResultSet getUser(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    // Insecure deserialization -- should trigger atlas/security/java/insecure-deserialization
    public Object loadData(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // Path traversal -- should trigger atlas/security/java/path-traversal
    public String readFile(String filename) throws Exception {
        File f = new File(filename);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }
}
