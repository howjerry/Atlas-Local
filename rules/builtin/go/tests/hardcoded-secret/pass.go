// Hardcoded Secret: should NOT trigger the rule
// Uses environment variables for secrets

package main

import "os"

func connectDB() {
	dbPassword := os.Getenv("DB_PASSWORD")
	_ = dbPassword
}

func callAPI() {
	key := os.Getenv("API_KEY")
	_ = key
}

func getConfig() {
	name := "production"
	_ = name
}
