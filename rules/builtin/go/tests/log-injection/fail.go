// Log Injection: SHOULD trigger the rule
// Pattern: log/fmt 格式化函數使用未清理的使用者輸入
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"fmt"
	"log"
	"net/http"
)

func unsafeLogPrintf(r *http.Request) {
	username := r.FormValue("username")
	// 不安全：log.Printf 使用未清理的使用者輸入
	log.Printf("User login: %s", username)
}

func unsafeFmtPrintf(r *http.Request) {
	action := r.FormValue("action")
	// 不安全：fmt.Printf 使用未清理的使用者輸入
	fmt.Printf("Action performed: %s", action)
}

func unsafeLogFatalf(r *http.Request) {
	errorMsg := r.FormValue("error")
	// 不安全：log.Fatalf 使用未清理的使用者輸入
	log.Fatalf("Critical error: %s", errorMsg)
}

