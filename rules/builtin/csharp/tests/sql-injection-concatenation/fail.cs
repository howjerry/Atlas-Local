// SQL Injection (Concatenation): SHOULD trigger the rule
// Pattern: ExecuteReader/QueryAsync/etc. with string concatenation
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Data.SqlClient;
using Dapper;

public class SqlInjectionConcatFail
{
    public void UnsafeQuery(SqlConnection conn, string userId)
    {
        var reader = conn.ExecuteReader("SELECT * FROM users WHERE id = " + userId);

        conn.Execute("DELETE FROM sessions WHERE token = " + token);

        var result = conn.QueryAsync("SELECT name FROM accounts WHERE email = " + email);
    }
}
