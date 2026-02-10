// LDAP Injection: should NOT trigger the rule
// 使用參數化查詢或靜態 filter

import javax.naming.directory.*;

public class LdapInjectionPass {
    public void safeSearch(DirContext ctx) throws Exception {
        // 安全：使用硬編碼的 filter
        ctx.search("ou=users", "(uid=admin)", new SearchControls());

        // 安全：使用硬編碼的名稱
        ctx.list("ou=users,dc=example,dc=com");
    }
}

