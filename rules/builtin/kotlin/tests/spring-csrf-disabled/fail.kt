import org.springframework.security.config.annotation.web.builders.HttpSecurity

// Spring CSRF Disabled: SHOULD trigger the rule
// Pattern: Spring Security 停用 CSRF 保護

class SecurityConfig {
    fun configure(http: HttpSecurity) {
        // 不安全：停用 CSRF 保護
        http.csrf().disable()
    }
}

