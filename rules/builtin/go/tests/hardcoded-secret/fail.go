// Hardcoded Secret: SHOULD trigger the rule
// Pattern: String literals assigned to variables named password/secret/token etc.
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

func connectDB() {
	password := "super_secret_123"
	_ = password
}

func callAPI() {
	apiKey := "sk-1234567890abcdef"
	_ = apiKey
}

func authenticate() {
	token := "eyJhbGciOiJIUzI1NiJ9.test"
	_ = token
}
