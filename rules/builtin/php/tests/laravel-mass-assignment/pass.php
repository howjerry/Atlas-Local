<?php
// Laravel Mass Assignment: should NOT trigger the rule
// 使用 only() 或 validated() 限制欄位

use App\Models\User;

class SafeUserController
{
    public function store(Request $request)
    {
        // 安全：使用 only() 限制欄位
        User::create($request->only(['name', 'email']));
    }

    public function update(Request $request, User $user)
    {
        // 安全：使用 validated() 搭配 Form Request
        $user->update($request->validated());
    }
}

