import org.springframework.security.config.annotation.web.builders.HttpSecurity

// Spring CSRF Disabled: should NOT trigger the rule
// 使用正確的 CSRF 設定

class SecurityConfig {
    fun configure(http: HttpSecurity) {
        // 安全：保持 CSRF 啟用（預設行為）
        http.authorizeRequests()
            .antMatchers("/api/**").authenticated()
    }
}

