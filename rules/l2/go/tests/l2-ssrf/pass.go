package main

import (
	"net"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlStr := r.FormValue("url")
	parsedURL, _ := url.Parse(urlStr)
	
	// 驗證 URL 是否為 HTTPS
	if parsedURL.Scheme == "https" {
		// 驗證 Host 不是本機地址
		ip := net.ParseIP(parsedURL.Hostname())
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			http.Get(urlStr)
		}
	}
}
