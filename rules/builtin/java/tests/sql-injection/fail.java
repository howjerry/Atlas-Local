// SQL Injection: SHOULD trigger the rule
// Pattern: execute/executeQuery/executeUpdate/addBatch with string concatenation
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.sql.*;

public class SqlInjectionFail {
    public void unsafeQuery(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        stmt.executeUpdate("DELETE FROM sessions WHERE token = " + token);

        stmt.addBatch("INSERT INTO logs VALUES ('" + message + "')");
    }
}
