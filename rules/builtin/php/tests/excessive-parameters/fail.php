<?php
// 不良：函式有太多參數（6 個以上）
function createUser($name, $email, $phone, $address, $city, $country) {
    // 建立使用者
}

// 不良：方法有太多參數
class OrderService {
    public function placeOrder($product, $quantity, $price, $discount, $tax, $shipping) {
        // 建立訂單
    }
}
