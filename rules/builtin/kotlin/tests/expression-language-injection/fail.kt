import org.springframework.expression.ExpressionParser
import org.springframework.expression.spel.standard.SpelExpressionParser

// Expression Language Injection: SHOULD trigger the rule
// Pattern: 表達式評估方法使用變數作為表達式參數

class ExpressionInjectionExample {
    private val parser: ExpressionParser = SpelExpressionParser()

    fun unsafeSpelParse(userInput: String) {
        // 不安全：parseExpression 使用變數
        val expr = parser.parseExpression(userInput)
        val result = expr.value
    }

    fun unsafeGetValue(expression: String) {
        // 不安全：getValue 使用變數
        val expr = parser.parseExpression(expression)
        val result = expr.getValue(context)
    }
}

