// Insecure Object Reference: should NOT trigger the rule
// 使用硬編碼 ID 或間接參考

import org.springframework.web.bind.annotation.*;

public class InsecureObjectReferencePass {
    private UserRepository userRepository;

    public void getAdminUser() {
        // 安全：使用硬編碼的 ID
        var admin = userRepository.findById(1L);
    }

    public void findUserByEmail(String email) {
        // 安全：使用不同的查詢方法（非 findById 模式）
        var user = userRepository.findByEmail(email);
    }

    public void getAllUsers() {
        // 安全：使用 findAll，不涉及直接物件參考
        var users = userRepository.findAll();
    }
}

