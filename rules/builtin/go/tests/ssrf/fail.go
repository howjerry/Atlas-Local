// SSRF: SHOULD trigger the rule
// Pattern: http.Get/Post/NewRequest with variable URL arguments
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "net/http"

func fetchURL(url string) (*http.Response, error) {
	return http.Get(url)
}

func postData(target string) (*http.Response, error) {
	return http.Post(target, "application/json", nil)
}

func makeRequest(endpoint string) (*http.Request, error) {
	return http.NewRequest("GET", endpoint, nil)
}
