// Spring CSRF Disabled: should NOT trigger the rule
// 保持 CSRF 啟用或正確配置

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SpringCsrfDisabledPass {
    public void configureWithCsrf(HttpSecurity http) throws Exception {
        // 安全：保持 CSRF 保護啟用（預設）
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();
    }

    public void configureWithCustomCsrf(HttpSecurity http) throws Exception {
        // 安全：自訂 CSRF token 儲存方式
        http.csrf(csrf -> csrf.csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    }
}

