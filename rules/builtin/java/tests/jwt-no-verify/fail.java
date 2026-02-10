// JWT No Verify: SHOULD trigger the rule
// Pattern: JWT 解析未驗證簽名
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import io.jsonwebtoken.Jwts;
import com.auth0.jwt.JWT;

public class JwtNoVerifyFail {
    public void unsafeJjwt(String token) {
        // 不安全：parseClaimsJwt 不驗證簽名（注意是 Jwt 而非 Jws）
        var claims = Jwts.parser().parseClaimsJwt(token).getBody();
    }

    public void unsafePlaintext(String token) {
        // 不安全：parsePlaintextJwt 不驗證簽名
        var body = Jwts.parser().parsePlaintextJwt(token).getBody();
    }

    public void unsafeAuth0(String token) {
        // 不安全：Auth0 decode 不驗證簽名
        var decoded = JWT.decode(token);
    }
}

