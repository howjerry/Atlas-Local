// LDAP Injection: SHOULD trigger the rule
// Pattern: LDAP search 使用字串串接組合 filter
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.naming.directory.*;

public class LdapInjectionFail {
    public void unsafeSearch(DirContext ctx, String username) throws Exception {
        // 不安全：使用字串串接組合 LDAP filter
        ctx.search("ou=users", "(uid=" + username + ")", new SearchControls());

        // 不安全：list 使用串接
        ctx.list("cn=" + username + ",ou=users");
    }
}

