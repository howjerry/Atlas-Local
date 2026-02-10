// LDAP Injection: SHOULD trigger the rule
// Pattern: LDAP 搜尋使用字串內插組合 filter
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.DirectoryServices;

public class UnsafeLdap
{
    public SearchResult UnsafeFindOne(string username)
    {
        var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        // 不安全：使用字串內插組合 LDAP filter
        var searcher = new DirectorySearcher($"(uid={username})");
        return searcher.FindOne();
    }

    public SearchResultCollection UnsafeFindAll(DirectorySearcher searcher, string input)
    {
        // 不安全：FindAll 使用字串內插
        return searcher.FindAll($"(cn={input})");
    }
}

