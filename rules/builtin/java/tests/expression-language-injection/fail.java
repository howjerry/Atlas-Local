// Expression Language Injection: SHOULD trigger the rule
// Pattern: 表達式評估方法使用變數作為表達式參數
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class ExpressionLanguageInjectionFail {
    private ExpressionParser parser = new SpelExpressionParser();

    public void unsafeSpelParse(String userInput) {
        // 不安全：parseExpression 使用變數
        Expression expr = parser.parseExpression(userInput);
        Object result = expr.getValue();
    }

    public void unsafeGetValue(EvaluationContext ctx, String expression) {
        // 不安全：getValue 使用變數
        Expression expr = parser.parseExpression(expression);
        Object result = expr.getValue(ctx);
    }

    public void unsafeEvaluate(ExpressionParser parser, String input) {
        // 不安全：evaluate 使用變數
        parser.parseExpression(input);
    }
}

