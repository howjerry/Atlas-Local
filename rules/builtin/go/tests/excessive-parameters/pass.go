// Excessive Parameters: should NOT trigger the rule
// Functions with 5 or fewer parameters

package main

func createUser(name string, email string, age int) {
	_ = name
	_ = email
	_ = age
}

func add(a int, b int) int {
	return a + b
}

func greet(name string) string {
	return "Hello, " + name
}
