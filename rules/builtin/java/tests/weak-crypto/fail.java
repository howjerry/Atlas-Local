// 弱加密演算法: 應該觸發規則
// Pattern: 使用 MD5, SHA-1, DES 等已知脆弱的演算法
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class WeakCryptoFail {
    // 使用 MD5 雜湊（已知碰撞攻擊）
    public byte[] hashWithMD5(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }

    // 使用 SHA-1 雜湊（已知碰撞攻擊）
    public byte[] hashWithSHA1(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data.getBytes());
    }

    // 使用 DES 加密（金鑰過短）
    public byte[] encryptWithDES(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        return cipher.doFinal(data);
    }
}
