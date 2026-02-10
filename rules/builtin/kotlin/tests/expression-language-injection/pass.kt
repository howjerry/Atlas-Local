import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.SimpleEvaluationContext

// Expression Language Injection: should NOT trigger the rule
// 使用硬編碼表達式或安全的評估上下文

class SafeExpressionExample {
    private val parser = SpelExpressionParser()

    fun safeHardcodedExpression() {
        // 安全：使用硬編碼的表達式字串
        val expr = parser.parseExpression("name == 'admin'")
        val result = expr.value
    }

    fun safeSandboxedContext(input: String) {
        // 安全：使用 SimpleEvaluationContext 限制可存取的方法
        val context = SimpleEvaluationContext.forReadOnlyDataBinding().build()
        val expr = parser.parseExpression("name")
        val result = expr.getValue(context)
    }
}

