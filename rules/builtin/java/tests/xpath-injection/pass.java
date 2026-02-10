// XPath Injection: should NOT trigger the rule
// 使用參數化 XPath 查詢或靜態表達式

import javax.xml.xpath.*;
import org.w3c.dom.*;

public class XPathInjectionPass {
    public void safeXPathCompile(XPath xpath) throws Exception {
        // 安全：使用硬編碼的 XPath 表達式
        XPathExpression expr = xpath.compile("//users/user[@role='admin']");
    }

    public void safeXPathEvaluate(XPath xpath, Document doc) throws Exception {
        // 安全：使用靜態 XPath 表達式
        String result = (String) xpath.evaluate("//config/database/host", doc);
    }
}

