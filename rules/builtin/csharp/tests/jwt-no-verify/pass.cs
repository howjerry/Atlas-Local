// JWT No Verify: should NOT trigger the rule
// 使用正確的 JWT 驗證設定

using Microsoft.IdentityModel.Tokens;

public class SafeJwt
{
    public TokenValidationParameters GetSafeParams(byte[] key)
    {
        // 安全：啟用所有驗證
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = true
        };
    }
}

