// JWT No Verify: should NOT trigger the rule
// 使用正確的簽名驗證方法解析 JWT

import io.jsonwebtoken.Jwts;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtNoVerifyPass {
    public void safeJjwt(String token, byte[] keyBytes) {
        // 安全：parseClaimsJws 會驗證簽名
        var claims = Jwts.parserBuilder()
            .setSigningKey(keyBytes)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public void safeAuth0(String token, String secret) {
        // 安全：使用 require + verify 驗證簽名
        var verifier = JWT.require(Algorithm.HMAC256(secret)).build();
        var decoded = verifier.verify(token);
    }
}

