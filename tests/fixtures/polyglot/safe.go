package main

import "fmt"

// Safe Go file -- should NOT trigger any findings.
func main() {
	name := "World"
	fmt.Printf("Hello, %s!\n", name)
}

func add(a, b int) int {
	return a + b
}
