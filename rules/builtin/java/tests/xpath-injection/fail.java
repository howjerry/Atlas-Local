// XPath Injection: SHOULD trigger the rule
// Pattern: XPath 查詢使用字串串接組合表達式
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.xml.xpath.*;
import org.w3c.dom.*;

public class XPathInjectionFail {
    public void unsafeXPathCompile(XPath xpath, String userInput) throws Exception {
        // 不安全：compile 使用字串串接
        XPathExpression expr = xpath.compile("//users/user[@name='" + userInput + "']");
    }

    public void unsafeXPathEvaluate(XPath xpath, Document doc, String userId) throws Exception {
        // 不安全：evaluate 使用字串串接
        String result = (String) xpath.evaluate("//user[@id='" + userId + "']/password", doc);
    }
}

