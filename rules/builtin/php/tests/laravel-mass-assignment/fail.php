<?php
// Laravel Mass Assignment: SHOULD trigger the rule
// Pattern: 使用 $request->all() 進行大量賦值
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

use App\Models\User;

class UserController
{
    public function store(Request $request)
    {
        // 不安全：使用 request()->all() 大量賦值
        User::create($request->all());
    }

    public function update(Request $request, User $user)
    {
        // 不安全：使用 $request->all() 更新
        $user->update($request->all());
    }
}

