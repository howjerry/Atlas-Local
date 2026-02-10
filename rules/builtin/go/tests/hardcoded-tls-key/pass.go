// Hardcoded TLS Key: should NOT trigger the rule
// 從環境變數讀取憑證路徑

package main

import (
	"crypto/tls"
	"os"
)

func safeFromEnv() {
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")
	// 安全：從環境變數讀取路徑
	cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
	_ = cert
}

