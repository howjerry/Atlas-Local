<?php
// 良好：使用 Parameter Object 模式
class UserData {
    public string $name;
    public string $email;
    public string $phone;
    public string $address;
    public string $city;
    public string $country;
}

function createUser(UserData $data) {
    // 建立使用者
}

// 良好：參數數量合理（5 個以下）
function calculateTotal($price, $quantity, $taxRate) {
    return $price * $quantity * (1 + $taxRate);
}
