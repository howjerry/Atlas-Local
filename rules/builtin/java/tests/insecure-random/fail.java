// 不安全隨機數: 應該觸發規則
// Pattern: 使用 java.util.Random 而非 SecureRandom
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.util.Random;

public class InsecureRandomFail {
    // 使用 Random 產生 token（不安全）
    public String generateToken() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(random.nextInt(16));
        }
        return sb.toString();
    }

    // 使用 Random 產生 session ID（不安全）
    public long generateSessionId() {
        Random rng = new Random();
        return rng.nextLong();
    }
}
