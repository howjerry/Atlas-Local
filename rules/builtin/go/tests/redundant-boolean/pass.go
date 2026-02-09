// Redundant Boolean: should NOT trigger the rule
// Returns boolean expressions directly

package main

func isPositive(x int) bool {
	return x > 0
}

func isEmpty(s string) bool {
	return len(s) == 0
}

func isValid(x int) bool {
	if x > 0 {
		return true
	}
	return x == -1
}
