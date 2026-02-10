// Insecure Cookie: should NOT trigger the rule
// 使用安全的 cookie 設定

package main

import "net/http"

func safeCookie(w http.ResponseWriter) {
	// 安全：Secure 和 HttpOnly 都設為 true
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

