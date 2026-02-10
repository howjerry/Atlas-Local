// TLS Insecure Skip Verify: SHOULD trigger the rule
// Pattern: tls.Config 設定 InsecureSkipVerify 為 true
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"crypto/tls"
	"net/http"
)

func unsafeClient() *http.Client {
	// 不安全：停用憑證驗證
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: transport}
}

