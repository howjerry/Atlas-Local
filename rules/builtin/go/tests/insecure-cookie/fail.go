// Insecure Cookie: SHOULD trigger the rule
// Pattern: http.Cookie 設定 Secure 或 HttpOnly 為 false
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "net/http"

func unsafeCookie(w http.ResponseWriter) {
	// 不安全：Secure 設為 false
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   false,
		HttpOnly: false,
	}
	http.SetCookie(w, cookie)
}

