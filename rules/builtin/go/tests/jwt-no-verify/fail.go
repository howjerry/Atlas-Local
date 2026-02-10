// JWT No Verify: SHOULD trigger the rule
// Pattern: JWT 解析跳過簽名驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "github.com/golang-jwt/jwt/v5"

func unsafeParseUnverified(tokenString string) {
	parser := jwt.NewParser()
	// 不安全：使用 ParseUnverified 跳過簽名驗證
	token, _, _ := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	_ = token
}

func unsafeDecodeSegment(segment string) {
	// 不安全：直接解碼 JWT segment
	data, _ := jwt.DecodeSegment(segment)
	_ = data
}

