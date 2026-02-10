// Hardcoded TLS Key: SHOULD trigger the rule
// Pattern: tls.LoadX509KeyPair 使用硬編碼路徑
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "crypto/tls"

func unsafeHardcodedPaths() {
	// 不安全：硬編碼的憑證路徑
	cert, _ := tls.LoadX509KeyPair("/etc/ssl/server.crt", "/etc/ssl/server.key")
	_ = cert
}

func unsafeKeyPair() {
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB...")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nMIIE...")
	// 不安全：硬編碼的 PEM 資料
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	_ = cert
}

