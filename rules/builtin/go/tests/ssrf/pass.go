// SSRF: should NOT trigger the rule
// Uses a custom HTTP client without top-level http.Get/Post/NewRequest

package main

import "net/http"

func safeRequest() {
	client := &http.Client{}
	resp, _ := client.Get("https://api.example.com/data")
	_ = resp
}

func safePost() {
	client := &http.Client{}
	resp, _ := client.Post("https://api.example.com/data", "application/json", nil)
	_ = resp
}
