// Log Injection: should NOT trigger the rule
// 使用結構化日誌或硬編碼字串

package main

import (
	"log"
)

func safeLogHardcoded() {
	// 安全：使用硬編碼字串
	log.Println("Application started")
	log.Println("Connection established")
}

func safeStructuredLog() {
	// 安全：使用 log.Println 不帶格式化
	log.Println("User logged in successfully")
}

