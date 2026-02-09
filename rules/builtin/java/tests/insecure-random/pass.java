// 不安全隨機數: 不應觸發規則
// 使用 SecureRandom 替代 Random

import java.security.SecureRandom;

public class InsecureRandomPass {
    // 使用 SecureRandom 產生 token（安全）
    public String generateToken() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(secureRandom.nextInt(16));
        }
        return sb.toString();
    }

    // 使用 SecureRandom 產生 session ID（安全）
    public long generateSessionId() {
        SecureRandom secureRng = new SecureRandom();
        return secureRng.nextLong();
    }
}
