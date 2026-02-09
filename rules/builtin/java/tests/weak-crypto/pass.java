// 弱加密演算法: 不應觸發規則
// 使用 SHA-256 和 AES 等強加密演算法

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class WeakCryptoPass {
    // 使用 SHA-256 雜湊（安全）
    public byte[] hashWithSHA256(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes());
    }

    // 使用 AES/GCM 加密（安全）
    public byte[] encryptWithAES(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(data);
    }
}
