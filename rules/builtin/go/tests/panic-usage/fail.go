// Panic Usage: SHOULD trigger the rule
// Pattern: Calling panic() in application code

package main

func processData(data []byte) {
	if len(data) == 0 {
		panic("data cannot be empty")
	}
}

func initConfig(path string) {
	if path == "" {
		panic("config path is required")
	}
}

func divide(a, b int) int {
	if b == 0 {
		panic("division by zero")
	}
	return a / b
}
