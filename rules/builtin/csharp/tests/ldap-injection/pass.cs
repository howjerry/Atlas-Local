// LDAP Injection: should NOT trigger the rule
// 使用硬編碼的 LDAP filter

using System.DirectoryServices;

public class SafeLdap
{
    public SearchResult SafeFindOne()
    {
        var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        // 安全：使用硬編碼的 filter
        var searcher = new DirectorySearcher("(objectClass=user)");
        return searcher.FindOne();
    }
}

