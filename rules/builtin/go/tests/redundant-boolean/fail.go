// Redundant Boolean: SHOULD trigger the rule
// Pattern: if returning true else returning false

package main

func isPositive(x int) bool {
	if x > 0 {
		return true
	} else {
		return false
	}
}

func isEmpty(s string) bool {
	if len(s) == 0 {
		return true
	} else {
		return false
	}
}
