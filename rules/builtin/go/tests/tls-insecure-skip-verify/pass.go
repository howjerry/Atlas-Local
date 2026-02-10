// TLS Insecure Skip Verify: should NOT trigger the rule
// 使用正確的 TLS 設定

package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

func safeClient(certPool *x509.CertPool) *http.Client {
	// 安全：使用自訂 CA pool 驗證憑證
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: transport}
}

