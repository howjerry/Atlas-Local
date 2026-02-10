// JWT No Verify: should NOT trigger the rule
// 使用正確的簽名驗證

package main

import "github.com/golang-jwt/jwt/v5"

func safeParse(tokenString string, secretKey []byte) {
	// 安全：使用 Parse 搭配 key function 驗證簽名
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		return
	}
}

