// Spring CSRF Disabled: SHOULD trigger the rule
// Pattern: Spring Security 配置中禁用 CSRF
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SpringCsrfDisabledFail {
    public void configureOldStyle(HttpSecurity http) throws Exception {
        // 不安全：禁用 CSRF 保護（傳統寫法）
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }

    public void configureLambdaStyle(HttpSecurity http) throws Exception {
        // 不安全：禁用 CSRF 保護（Lambda 寫法）
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    }
}

