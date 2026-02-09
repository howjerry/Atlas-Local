<?php
// 良好：有實作的函式
function processOrder($order) {
    $order->validate();
    $order->save();
}

// 良好：有實作的方法
class UserService {
    public function validateUser($user) {
        if (empty($user->email)) {
            throw new InvalidArgumentException('Email is required');
        }
    }

    public function sendNotification($message) {
        $this->mailer->send($message);
    }
}
