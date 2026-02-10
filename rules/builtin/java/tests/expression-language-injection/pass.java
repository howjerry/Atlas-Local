// Expression Language Injection: should NOT trigger the rule
// 使用硬編碼的表達式字串

import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class ExpressionLanguageInjectionPass {
    private ExpressionParser parser = new SpelExpressionParser();

    public void safeSpelParse() {
        // 安全：使用硬編碼的表達式
        Expression expr = parser.parseExpression("'Hello World'.concat('!')");
        Object result = expr.getValue();
    }

    public void safeGetValue() {
        // 安全：使用硬編碼的表達式
        Expression expr = parser.parseExpression("#root.name");
        String name = expr.getValue(String.class);
    }
}

