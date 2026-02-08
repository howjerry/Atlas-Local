// SQL Injection (Interpolation): should NOT trigger the rule
// Uses parameterized queries with Dapper anonymous objects

using System.Data.SqlClient;
using Dapper;

public class SqlInjectionInterpPass
{
    public void SafeQuery(SqlConnection conn, string userId)
    {
        var result = conn.QueryAsync("SELECT * FROM users WHERE id = @Id", new { Id = userId });

        conn.Execute("DELETE FROM sessions WHERE token = @Token", new { Token = token });

        var name = conn.QueryFirstOrDefault("SELECT name FROM accounts WHERE email = @Email",
            new { Email = email });
    }
}
