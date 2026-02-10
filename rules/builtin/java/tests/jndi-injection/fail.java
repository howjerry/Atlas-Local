// JNDI Injection: SHOULD trigger the rule
// Pattern: JNDI lookup 使用變數作為名稱參數
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.naming.*;

public class JndiInjectionFail {
    public void unsafeLookup(String userInput) throws Exception {
        // 不安全：使用變數作為 JNDI lookup 名稱
        InitialContext ctx = new InitialContext();
        Object obj = ctx.lookup(userInput);
    }

    public void unsafeLookupFromRequest(Context ctx, String resourceName) throws Exception {
        // 不安全：動態 lookup 名稱
        Object dataSource = ctx.lookup(resourceName);
    }
}

