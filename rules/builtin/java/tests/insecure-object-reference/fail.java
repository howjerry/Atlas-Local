// Insecure Object Reference: SHOULD trigger the rule
// Pattern: Repository 直接使用請求參數查詢資料庫
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import org.springframework.web.bind.annotation.*;

public class InsecureObjectReferenceFail {
    private UserRepository userRepository;
    private OrderRepository orderRepository;

    public void getUser(Long userId) {
        // 不安全：直接使用參數查詢，未驗證授權
        var user = userRepository.findById(userId);
    }

    public void getOrder(Long orderId) {
        // 不安全：getOne 直接使用參數
        var order = orderRepository.getOne(orderId);
    }

    public void getReference(Long id) {
        // 不安全：getReferenceById 直接使用參數
        var entity = userRepository.getReferenceById(id);
    }
}

