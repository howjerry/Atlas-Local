// JWT No Verify: SHOULD trigger the rule
// Pattern: TokenValidationParameters 停用簽名驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using Microsoft.IdentityModel.Tokens;

public class UnsafeJwt
{
    public TokenValidationParameters GetUnsafeParams()
    {
        var parameters = new TokenValidationParameters();
        // 不安全：停用簽名驗證
        parameters.ValidateIssuerSigningKey = false;
        return parameters;
    }

    public TokenValidationParameters GetUnsafeNoSigned()
    {
        var parameters = new TokenValidationParameters();
        // 不安全：不要求已簽名的 token
        parameters.RequireSignedTokens = false;
        return parameters;
    }
}

