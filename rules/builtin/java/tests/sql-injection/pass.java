// SQL Injection: should NOT trigger the rule
// Uses parameterized queries with PreparedStatement

import java.sql.*;

public class SqlInjectionPass {
    public void safeQuery(Connection conn, String userId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ResultSet rs = ps.executeQuery();

        PreparedStatement ps2 = conn.prepareStatement("DELETE FROM sessions WHERE token = ?");
        ps2.setString(1, token);
        ps2.executeUpdate();
    }
}
