// JNDI Injection: should NOT trigger the rule
// 使用硬編碼的 JNDI 名稱

import javax.naming.*;

public class JndiInjectionPass {
    public void safeLookup() throws Exception {
        // 安全：硬編碼的 JNDI 名稱
        InitialContext ctx = new InitialContext();
        Object ds = ctx.lookup("java:comp/env/jdbc/MyDB");
    }

    public void safeLookupWithConstant(Context ctx) throws Exception {
        // 安全：使用硬編碼的資源名稱
        Object obj = ctx.lookup("java:comp/env/mail/Session");
    }
}

